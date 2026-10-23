// Test-only harness for the log object: a settable clock, a storage-sync trace
// and crash/race points. Never bundle as a deployed entry point.
import { LogObject } from '../../services/sync-worker/src/log.mjs';

const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g) ?? [], h => parseInt(h, 16));

// Socket attachment reads in this isolate, so a test can show what a dropped
// presence frame costs.
let attachmentReads = 0;
const deserializeAttachment = WebSocket.prototype.deserializeAttachment;
WebSocket.prototype.deserializeAttachment = function () {
  attachmentReads++;
  return deserializeAttachment.call(this);
};

export class FixtureLog extends LogObject {
  clock = 0;
  trace = [];
  failSync = false;
  crashAfterMark = false;
  crashAfterDelete = false;
  reclaimAfterHead = false;
  advanceAfterHead = 0;
  restageAfterHead = null;
  supersedeOnDirectoryRead = null;
  appendOnControlRead = null;
  #stalled = null;
  #restage = null;
  constructor(ctx, env) {
    super(ctx, env, {
      now: () => this.clock,
      sync: async () => {
        this.trace.push('sync');
        if (this.failSync) throw new Error('test sync failure');
        await ctx.storage.sync();
        this.trace.push('synced');
      },
      afterHead: async () => {
        this.clock += this.advanceAfterHead;
        this.advanceAfterHead = 0;
        // A reclaim sweep runs while the append awaits its R2 check.
        if (this.reclaimAfterHead) { this.reclaimAfterHead = false; await this.alarm(); }
        // A whole reclaim and a restage of the same body fit inside the R2
        // check; the restage's R2 put is still pending when the append resumes.
        if (this.restageAfterHead) {
          const { permit, body } = this.restageAfterHead;
          this.restageAfterHead = null;
          await this.alarm();
          await new Promise(reached => {
            this.#stalled = { reached };
            this.#restage = this.stage(unhex(permit), unhex(body));
          });
        }
      },
      afterControlRows: async () => {
        if (!this.appendOnControlRead) return;
        const { permit, event } = this.appendOnControlRead;
        this.appendOnControlRead = null;
        const result = await this.append(unhex(permit), unhex(event));
        if (result.refused) throw new Error('test append failed');
      },
      afterDirectoryRows: async () => {
        if (!this.supersedeOnDirectoryRead) return;
        const { permit, body } = this.supersedeOnDirectoryRead;
        this.supersedeOnDirectoryRead = null;
        const result = await this.storeDirectoryEntry(unhex(permit), unhex(body));
        if (result.refused) throw new Error('test supersede failed');
      },
      beforePut: () => {
        const stalled = this.#stalled;
        if (!stalled) return;
        return new Promise((_, fail) => { stalled.fail = fail; stalled.reached(); });
      },
      afterMark: async () => {
        if (this.crashAfterMark) ctx.abort('test crash between mark and delete');
      },
      afterDelete: async () => {
        if (this.crashAfterDelete) ctx.abort('test crash between object and row deletes');
      },
    });
  }
  async control(settings) {
    Object.assign(this, settings);
    if (settings.trace) this.trace = [];
    return { ok: true };
  }
  async traced(action, ...args) {
    this.trace = [];
    const result = await this[action](...args);
    this.trace.push('resolved');
    return { result, trace: this.trace };
  }
  // Fails the stalled restage put and returns that stage's result.
  async failStalledPut() {
    this.#stalled.fail(new Error('test put failure'));
    this.#stalled = null;
    return this.#restage;
  }
  // Handler names such as `alarm` are not reachable over RPC; run the sweep here.
  async sweep() {
    await this.alarm();
    return { ok: true };
  }
  async privateObjects() {
    return this.ctx.storage.sql.exec('SELECT prefix_digest,bundle_digest,bundle FROM private_home_objects ORDER BY prefix_digest')
      .toArray().map(r => ({ ...r, bundle: hex(r.bundle) }));
  }
  async corruptPrivateBundle(prefix, bundle) {
    this.ctx.storage.sql.exec('UPDATE private_home_objects SET bundle=? WHERE prefix_digest=?', bundle, prefix);
    await this.ctx.storage.sync();
    return { ok: true };
  }
  // Test-only simulation of an old populated account-home order store. Never
  // run a production migration or relabel the legacy state to canonical.
  async removeOrderMarker() {
    this.ctx.storage.sql.exec("DELETE FROM meta WHERE key='order_format'");
    await this.ctx.storage.sync();
    return { ok: true };
  }
  // Explain the production bounded read against the object's actual SQLite schema.
  async controlPlan(after, through) {
    return this.ctx.storage.sql.exec(`EXPLAIN QUERY PLAN ${LogObject.boundedControlQuery}`, after, through, 64).toArray();
  }
  // Every row of every table this object stores, and its key-value entries.
  // The runtime's own tables are not readable; `list()` covers its key-value one.
  async dump() {
    const sql = this.ctx.storage.sql;
    const tables = sql.exec("SELECT name FROM sqlite_master WHERE type='table'").toArray().map(row => row.name)
      .filter(name => !name.startsWith('_cf_') && !name.startsWith('sqlite_'));
    const rows = Object.fromEntries(tables.map(name => [name, sql.exec(`SELECT * FROM "${name}"`).toArray()]));
    return { rows, kv: Object.fromEntries(await this.ctx.storage.list()) };
  }
  // What each live presence socket carries through hibernation.
  async attachments() {
    return this.ctx.getWebSockets('presence').map(socket => socket.deserializeAttachment());
  }
  async attachmentReads() { return attachmentReads; }
  // Whether each presence socket is still open, as this object sees it.
  async presenceOpen() {
    return this.ctx.getWebSockets('presence').map(socket => socket.readyState === WebSocket.OPEN);
  }
  async inspect() {
    const sql = this.ctx.storage.sql;
    return {
      events: sql.exec('SELECT position,event_id,digest,control,commitment FROM events ORDER BY position').toArray()
        .map(r => ({ ...r, commitment: hex(r.commitment) })),
      bodies: sql.exec('SELECT commitment,state,len,since_ms FROM bodies ORDER BY commitment').toArray(),
      meta: Object.fromEntries(sql.exec('SELECT key,value FROM meta').toArray().map(r => [r.key, r.value])),
    };
  }
}

function wire(value) {
  if (Array.isArray(value)) return value.map(wire);
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return hex(value);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, wire(v)]));
  return value;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const stub = env.LOG.get(env.LOG.idFromName(url.searchParams.get('log')));
    if (url.pathname === '/subscribe' || url.pathname === '/presence') return stub.fetch(request);
    try {
      const { action, args = [], bytes = [] } = await request.json();
      // Arguments listed in `bytes` are hex on the wire and bytes to the object.
      const values = args.map((v, i) => bytes.includes(i) ? unhex(v) : v);
      if (action === 'r2') {
        const [op, key, value] = args;
        if (op === 'head') return Response.json((await env.BODIES.head(key))?.size ?? null);
        if (op === 'put') { await env.BODIES.put(key, unhex(value)); return Response.json(true); }
        if (op === 'list') return Response.json((await env.BODIES.list()).objects.map(o => o.key));
      }
      if (!['storeDirectoryEntry', 'readDirectory', 'retireHomeObjects', 'storeHomeObjects', 'privateObjects', 'corruptPrivateBundle', 'removeOrderMarker', 'stage', 'append', 'read', 'controls', 'controlPlan', 'head', 'sweep', 'control', 'inspect', 'traced', 'failStalledPut', 'dump', 'attachments', 'attachmentReads', 'presenceOpen', 'orderedBodies'].includes(action))
        return Response.json({ error: 'unknown action' }, { status: 400 });
      return Response.json(wire(await stub[action](...values)));
    } catch (error) {
      return Response.json({ error: String(error?.message ?? error) }, { status: 500 });
    }
  },
};
