// Internal SQLite Durable Object for one ordered log, a base's or an account
// home's. Only the edge Worker holds its stub: the default `fetch` below is a
// 404. Bodies live in R2 under `b/<log>/<commitment>`; this object keeps their
// staging state, the ordered event index and the head. It returns durable facts
// only; receipts are signed elsewhere. It also relays a base's presence frames
// between its live devices, in memory only.
import { DurableObject } from 'cloudflare:workers';
import { Refused, be, bytes, call, hex, instantiate, refuse, safe, unhex } from './wasm.mjs';

const DAY_MS = 86_400_000;
const RETRY_MS = 60_000;
const SWEEP = 1000; // R2 deletes at most 1000 keys per call
const MAX_PERMIT = 4096;
const MAX_BODIES = 64;
const MAX_CONTROLS = 64;
// Shared with the SQLite query-plan fixture so it explains the exact read.
const BOUNDED_CONTROL_QUERY = 'SELECT commitment,envelope FROM events WHERE control=1 AND position>? AND position<=? ORDER BY position LIMIT ?';
const EMPTY = { position: 0, hash: '00'.repeat(32) };
const EMPTY_OPENING = '0002' + '00'.repeat(80);
// The epoch a removal leaves the log in: no content is admitted under it.
const CLOSED = '00'.repeat(32);
// Presence: opaque sealed frames of at most this many bytes, and per-base
// limits on frames in and socket sends out, each per second. A frame over
// either is dropped whole.
const MAX_PRESENCE = 512;
const PRESENCE_IN = 200;
const PRESENCE_OUT = 5_000;
// Messages to the edge's presence socket: `PEERS || others:u16 || event:u8 ||
// slot:u32` for a roster change, `FRAME || from:u32 || sealed` for a frame.
const PEERS = 0;
const FRAME = 1;
const SNAPSHOT = 0;
const JOINED = 1;
const LEFT = 2;
// Closes presence sockets whose epoch is no longer the log's.
const EPOCH_CLOSE = 4409;

function maybe(sql, statement, ...params) {
  const rows = sql.exec(statement, ...params).toArray();
  if (rows.length > 1) throw new Error('duplicate row');
  return rows[0] ?? null;
}

function peers(others, event, slot) {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  out[0] = PEERS;
  view.setUint16(1, others);
  out[3] = event;
  view.setUint32(4, slot);
  return out;
}
function tryClose(socket, code, reason) {
  try { socket.close(code, reason); } catch { /* already closed */ }
}
function trySend(socket, message) {
  try { socket.send(message); } catch { /* a closing socket misses it */ }
}

export class LogObject extends DurableObject {
  // The fixture explains precisely the query used by this object.
  static boundedControlQuery = BOUNDED_CONTROL_QUERY;
  #instance;
  #hooks;
  #directoryWrites = new Map();
  // The log's current epoch, in memory for the presence path, which touches
  // no storage. Loaded once here and moved only when a control is ordered.
  #epoch;
  // Presence rate buckets; they reset harmlessly when the object hibernates.
  #in = { tokens: PRESENCE_IN, at: null };
  #out = { tokens: PRESENCE_OUT, at: null };
  // Presence sockets this object closed for an epoch change: every one closes
  // together, so none announces leaving to a device that joined since.
  #ended = new WeakSet();
  constructor(ctx, env, hooks = {}) {
    super(ctx, env);
    this.#instance = instantiate().then(instance => {
      // Establish the per-log format before any RPC may serve reads, change
      // epoch or order rows. Empty private home objects are not log history.
      this.ctx.storage.transactionSync(() => this.#assertOrder(instance));
      return instance;
    });
    this.#hooks = {
      now: () => Date.now(),
      sync: () => ctx.storage.sync(),
      afterHead: async () => {},
      afterMark: async () => {},
      afterDelete: async () => {},
      beforePut: async () => {},
      afterDirectoryRows: async () => {},
      afterControlRows: async () => {},
      ...hooks,
    };
    const sql = ctx.storage.sql;
    // `control` is the route the commitment carries: 1 for a control, 0 for content.
    sql.exec(`CREATE TABLE IF NOT EXISTS events(position INTEGER PRIMARY KEY,
      event_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, control INTEGER NOT NULL CHECK(control IN (0,1)),
      commitment BLOB NOT NULL, envelope BLOB NOT NULL)`);
    sql.exec('CREATE INDEX IF NOT EXISTS events_controls ON events(position) WHERE control=1');
    sql.exec(`CREATE TABLE IF NOT EXISTS bodies(commitment TEXT PRIMARY KEY,
      state TEXT NOT NULL CHECK(state IN ('staging','ordered','reclaiming')),
      len INTEGER NOT NULL, since_ms INTEGER NOT NULL, gen INTEGER NOT NULL)`);
    sql.exec('CREATE INDEX IF NOT EXISTS bodies_by_state ON bodies(state, since_ms)');
    sql.exec('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    // Private account control storage, deliberately outside events and bodies.
    // No read RPC, expiry or reclaim path exists for these acknowledged bytes.
    sql.exec(`CREATE TABLE IF NOT EXISTS private_home_objects(
      prefix_digest TEXT PRIMARY KEY, bundle_digest TEXT NOT NULL, bundle BLOB NOT NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS private_directory(
      entry TEXT PRIMARY KEY, version INTEGER NOT NULL, digest TEXT NOT NULL, len INTEGER NOT NULL)`);
    this.#epoch = maybe(sql, "SELECT value FROM meta WHERE key='epoch'")?.value ?? null;
  }

  #assertOrder(instance) {
    const sql = this.ctx.storage.sql;
    const marker = maybe(sql, "SELECT value FROM meta WHERE key='order_format'")?.value;
    const opening = maybe(sql, "SELECT value FROM meta WHERE key='opening'")?.value;
    const head = maybe(sql, "SELECT value FROM meta WHERE key='head'")?.value;
    const tail = maybe(sql, 'SELECT position,commitment FROM events ORDER BY position DESC LIMIT 1');
    if (marker === undefined && opening === undefined && head === undefined && !tail &&
        !maybe(sql, "SELECT value FROM meta WHERE key='control'") &&
        !maybe(sql, "SELECT value FROM meta WHERE key='epoch'")) {
      sql.exec("INSERT INTO meta(key,value) VALUES('order_format','2')");
      sql.exec("INSERT INTO meta(key,value) VALUES('opening',?)", EMPTY_OPENING);
      return;
    }
    if (marker !== '2' || typeof opening !== 'string' || !/^[0-9a-f]{164}$/.test(opening))
      throw new Error('unsupported order format');
    if (!tail) {
      if (head !== undefined || opening !== EMPTY_OPENING) throw new Error('empty order mismatch');
      return;
    }
    const log = maybe(sql, "SELECT value FROM meta WHERE key='log'")?.value;
    if (!log || !/^[0-9a-f]{66}$/.test(log) || !head) throw new Error('missing order gate');
    const state = call(instance, 'commitment_state', [unhex(log.slice(2)), new Uint8Array(tail.commitment)]);
    const storedHead = JSON.parse(head);
    if (state.order !== opening || state.position !== tail.position ||
        state.position !== storedHead.position || state.hash !== storedHead.hash) throw new Error('order tail mismatch');
    const lastControl = maybe(sql, 'SELECT commitment FROM events WHERE control=1 ORDER BY position DESC LIMIT 1');
    const control = maybe(sql, "SELECT value FROM meta WHERE key='control'")?.value;
    if (!lastControl || !control) throw new Error('missing control gate');
    const controlState = call(instance, 'commitment_state', [unhex(log.slice(2)), new Uint8Array(lastControl.commitment)]);
    if (JSON.parse(control).position !== controlState.position || JSON.parse(control).hash !== controlState.hash)
      throw new Error('control tail mismatch');
  }

  // Immutable private signup objects: not staged content, not an append.
  async storeHomeObjects(permit, bundle) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      bundle = bytes(bundle);
      const scope = this.#verify(instance, permit, bundle, 'store_home_objects');
      this.ctx.storage.transactionSync(() => {
        const now = this.#now();
        if (now < scope.issued_ms || now >= scope.deadline_ms) refuse('Expired');
        this.#bind(scope.log);
        const sql = this.ctx.storage.sql;
        const row = maybe(sql,
          'SELECT bundle_digest,bundle FROM private_home_objects WHERE prefix_digest=?', scope.prefix_digest);
        if (row) {
          const stored = new Uint8Array(row.bundle);
          if (row.bundle_digest !== scope.bundle_digest || stored.length !== bundle.length ||
              !stored.every((byte, i) => byte === bundle[i])) refuse('Conflict');
        } else {
          sql.exec('INSERT INTO private_home_objects(prefix_digest,bundle_digest,bundle) VALUES(?,?,?)',
            scope.prefix_digest, scope.bundle_digest, bundle.slice().buffer);
        }
      });
      // A retry awaits durability too; a prior write may have lost its response.
      await this.#hooks.sync();
      return { prefixDigest: scope.prefix_digest, bundleDigest: scope.bundle_digest };
    });
  }

  // The digest suffix makes each revision immutable: an interrupted R2 put
  // cannot replace the bytes still named by the previous durable SQL row.
  #directoryKey(log, entry, digest) { return `d/${log}/${entry}/${digest}`; }

  // Serialize writes for the same opaque entry across awaits without blocking
  // unrelated entries or reads; SQLite mutations still take short transactions.
  async #directoryWrite(entry, run) {
    const prior = this.#directoryWrites.get(entry) ?? Promise.resolve();
    const next = prior.catch(() => {}).then(run);
    this.#directoryWrites.set(entry, next);
    try { return await next; } finally {
      if (this.#directoryWrites.get(entry) === next) this.#directoryWrites.delete(entry);
    }
  }

  async storeDirectoryEntry(permit, body) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      body = bytes(body);
      const scope = this.#verify(instance, permit, body, 'store_directory_entry');
      return this.#directoryWrite(scope.entry, async () => {
        const sql = this.ctx.storage.sql;
        const current = maybe(sql, 'SELECT version,digest FROM private_directory WHERE entry=?', scope.entry);
        if (current && (current.version > scope.version ||
            (current.version === scope.version && current.digest !== scope.body))) refuse('Conflict');
        if (!current || current.version < scope.version) {
          // R2 first, row second. On failure the old row still names its old
          // immutable object. A crash before the row update may leave an
          // unreferenced R2 object; there is no orphan sweep.
          await this.env.BODIES.put(this.#directoryKey(scope.log, scope.entry, scope.body), body);
          this.ctx.storage.transactionSync(() => {
            const now = this.#now();
            if (now < scope.issued_ms || now >= scope.deadline_ms) refuse('Expired');
            this.#bind(scope.log);
            const row = maybe(sql, 'SELECT version,digest FROM private_directory WHERE entry=?', scope.entry);
            if (row && row.version >= scope.version) refuse('Conflict');
            sql.exec('INSERT OR REPLACE INTO private_directory(entry,version,digest,len) VALUES(?,?,?,?)',
              scope.entry, scope.version, scope.body, scope.len);
          });
        } else {
          const now = this.#now();
          if (now < scope.issued_ms || now >= scope.deadline_ms) refuse('Expired');
          this.ctx.storage.transactionSync(() => this.#bind(scope.log));
        }
        await this.#hooks.sync();
        // Delete only after the replacement row is durable. A concurrent
        // reader holding the old row may see Missing and re-read the page.
        if (current && current.version < scope.version && current.digest !== scope.body) {
          try {
            await this.env.BODIES.delete(this.#directoryKey(scope.log, scope.entry, current.digest));
          } catch (error) {
            console.error(`directory cleanup: ${error instanceof Error ? error.constructor.name : 'Error'}`);
          }
        }
        return { ok: true };
      });
    });
  }

  async readDirectory(permit, after) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      const scope = this.#verify(instance, permit, new Uint8Array(0), 'read_directory');
      if (after !== null && (typeof after !== 'string' || !/^[0-9a-f]{64}$/.test(after))) refuse('Malformed');
      const sql = this.ctx.storage.sql;
      const rows = sql.exec('SELECT entry,digest,len FROM private_directory WHERE entry>? ORDER BY entry LIMIT 65', after ?? '').toArray();
      await this.#hooks.sync();
      await this.#hooks.afterDirectoryRows();
      const entries = [];
      for (const row of rows.slice(0, 64)) {
        const object = await this.env.BODIES.get(this.#directoryKey(scope.log, row.entry, row.digest));
        if (!object || object.size !== row.len) refuse('Missing');
        const body = new Uint8Array(await object.arrayBuffer());
        entries.push({ entry: row.entry, body });
      }
      return { entries, more: rows.length > 64 };
    });
  }

  async retireHomeObjects(permit) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      const scope = this.#verify(instance, permit, new Uint8Array(0), 'retire_home_objects');
      this.ctx.storage.transactionSync(() => {
        const now = this.#now();
        if (now < scope.issued_ms || now >= scope.deadline_ms) refuse('Expired');
        this.#bind(scope.log);
        this.ctx.storage.sql.exec('DELETE FROM private_home_objects WHERE prefix_digest=?', scope.prefix_digest);
      });
      await this.#hooks.sync();
      return { ok: true };
    });
  }

  // Internal RPC: stage one exact body under a stage permit.
  async stage(permit, body) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      body = bytes(body);
      const scope = this.#verify(instance, permit, body, 'stage');
      const now = this.#now();
      // The row is written before the object, so a crash leaves a reclaimable
      // row, never an object no row names.
      const state = this.ctx.storage.transactionSync(() => {
        this.#bind(scope.log);
        const sql = this.ctx.storage.sql;
        const row = maybe(sql, 'SELECT state,len FROM bodies WHERE commitment=?', scope.body);
        // The commitment hashes the exact bytes, and an ordered row is never
        // reclaimed, so those bytes are already in R2. No other event can order
        // against it: #admit takes only a `staging` row. So a resend after a
        // lost stage or append response is simply ok.
        if (row?.state === 'reclaiming' || row?.state === 'ordered') return row.state;
        if (row && row.len !== scope.len) throw new Error('stored length');
        // Each insert or refresh takes a new generation, which fences an
        // append that checked R2 before this stage.
        const gen = this.#nextGen();
        if (row) sql.exec('UPDATE bodies SET since_ms=?, gen=? WHERE commitment=?', now, gen, scope.body);
        else sql.exec("INSERT INTO bodies(commitment,state,len,since_ms,gen) VALUES(?,'staging',?,?,?)",
          scope.body, scope.len, now, gen);
        return 'staging';
      });
      if (state === 'reclaiming') {
        // Make sure an interrupted sweep resumes.
        await this.#ensureAlarm(now + RETRY_MS);
        refuse('Reclaiming');
      }
      await this.#hooks.sync();
      // An ordered body is already in R2 and is never reclaimed.
      if (state === 'staging') {
        await this.#hooks.beforePut();
        await this.env.BODIES.put(this.#key(scope.log, scope.body), body);
        await this.#ensureAlarm(now + DAY_MS);
      }
      return { ok: true };
    });
  }

  // Internal RPC: order one exact event under an append permit. Resolves with
  // the durable result only after storage sync.
  async append(permit, event) {
    return this.#guard(async () => {
      const instance = await this.#instance;
      event = bytes(event);
      const scope = this.#verify(instance, permit, event, 'append');
      const first = this.ctx.storage.transactionSync(() => this.#admit(instance, scope));
      let control = null;
      if (!first.ack && scope.body !== null) {
        for (const [body, len] of this.#bodies(scope, first)) {
          const object = await this.env.BODIES.head(this.#key(scope.log, body));
          if (!object || object.size !== len) refuse('NotStaged');
        }
        await this.#hooks.afterHead();
      }
      // Recheck everything after the await. A reclaim marks its row before it
      // deletes, and any restage takes a new generation before its put, so a
      // body still `staging` in the same generation was in R2 at the HEAD above.
      const result = first.ack ?? this.ctx.storage.transactionSync(() => {
        const again = this.#admit(instance, scope);
        if (again.ack) return again.ack;
        if (again.len !== first.len || again.gen !== first.gen ||
            again.attached?.len !== first.attached?.len || again.attached?.gen !== first.attached?.gen)
          refuse('NotStaged');
        const ordered = this.#order(instance, scope, event);
        if (scope.after) control = scope.epoch;
        return ordered;
      });
      // A newly ordered control ends every presence socket: their epoch's
      // members may have changed.
      if (control !== null) this.#reopen(control);
      await this.#hooks.sync();
      this.#notify();
      return result;
    });
  }

  // Internal RPC: 1-64 ordered events. Takes no append position or lock.
  async read(first, last) {
    return this.#guard(async () => {
      if (!safe(first) || !safe(last) || first < 1 || last < first || last - first >= 64) refuse('Malformed');
      const items = this.ctx.storage.sql.exec(
        'SELECT commitment,envelope FROM events WHERE position BETWEEN ? AND ? ORDER BY position', first, last)
        .toArray().map(row => ({ commitment: new Uint8Array(row.commitment), event: new Uint8Array(row.envelope) }));
      // A concurrent append can have written SQL but still await its sync.
      // Capture immutable rows first, then cross the same durability boundary
      // as append before the edge may sign this read's exact tail. No writes
      // or transaction/write lock span this await.
      await this.#hooks.sync();
      return items;
    });
  }

  // Internal RPC: up to 64 control-route events after position `after`, in
  // order; 0 reads from the start. Read-only, like `read`.
  async controls(after, through = null) {
    return this.#guard(async () => {
      if (!safe(after) || (through !== null && (!safe(through) || through < after))) refuse('Malformed');
      // Capture the indexed page AND its endpoint in one synchronous SQL read
      // section, before the durability barrier. The endpoint is the exact
      // requested position, not the final returned control.
      const page = this.ctx.storage.transactionSync(() => {
        const sql = this.ctx.storage.sql;
        const items = (through === null
          ? sql.exec('SELECT commitment,envelope FROM events WHERE control=1 AND position>? ORDER BY position LIMIT ?', after, MAX_CONTROLS)
          : sql.exec(BOUNDED_CONTROL_QUERY, after, through, MAX_CONTROLS))
          .toArray().map(row => ({ commitment: new Uint8Array(row.commitment), event: new Uint8Array(row.envelope) }));
        const target = through ?? this.#head().position;
        const endpoint = target === 0 ? null : maybe(sql, 'SELECT commitment FROM events WHERE position=?', target);
        if (target !== 0 && !endpoint) refuse('Missing');
        return { items, endpoint: endpoint ? new Uint8Array(endpoint.commitment) : null };
      });
      await this.#hooks.afterControlRows();
      await this.#hooks.sync();
      return page;
    });
  }

  async head() {
    return this.#guard(async () => this.#head());
  }

  // Internal RPC: for each of 1-64 body commitments, its stored length if the
  // edge may serve it, else null. A base log serves only ordered bodies. An
  // account-home log also serves a `staging` one: the service reads a
  // rotation's body back before it permits the append, and only the service
  // is granted a read of an account body that is not ordered. A `reclaiming`
  // body is never served. Read-only.
  async orderedBodies(commitments) {
    return this.#guard(async () => {
      if (!Array.isArray(commitments) || commitments.length < 1 || commitments.length > MAX_BODIES ||
          !commitments.every(c => typeof c === 'string' && /^[0-9a-f]{64}$/.test(c))) refuse('Malformed');
      const sql = this.ctx.storage.sql;
      const account = maybe(sql, "SELECT value FROM meta WHERE key='log'")?.value.startsWith('02') ?? false;
      return commitments.map(c => {
        const row = maybe(sql, 'SELECT state,len FROM bodies WHERE commitment=?', c);
        return row?.state === 'ordered' || (account && row?.state === 'staging') ? row.len : null;
      });
    });
  }

  // Internal subscription: a hibernating send-only socket of 40-byte head
  // notices (`position:u64 || hash:32`), starting with the current head.
  // Internal presence: a hibernating socket tagged `presence` at the epoch the
  // edge verified, carrying only that epoch and a random slot.
  async fetch(request) {
    try { await this.#instance; } catch { return new Response(null, { status: 503 }); }
    const path = new URL(request.url).pathname;
    if ((path !== '/subscribe' && path !== '/presence') || request.headers.get('Upgrade') !== 'websocket')
      return new Response(null, { status: 404 });
    if (path === '/presence') return this.#join(request.headers.get('X-Bh-Epoch'));
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.send(this.#notice());
    return new Response(null, { status: 101, webSocket: client });
  }
  async webSocketMessage(socket, message) {
    try { await this.#instance; } catch {
      tryClose(socket, 1003, 'unsupported order');
      return;
    }
    if (this.#isPresence(socket)) this.#relay(socket, message);
    else socket.close(1003, 'send-only');
  }
  webSocketClose(socket, code) {
    tryClose(socket, code);
    if (this.#isPresence(socket)) this.#left(socket);
  }

  // Reclaim sweep: staging rows older than a day are marked `reclaiming`,
  // durably, before their R2 objects are deleted; then the rows are dropped.
  // So no reclaimed object outlives its row. Rows already `reclaiming` (an
  // interrupted sweep) are resumed first.
  async alarm() {
    // A hibernated alarm cannot mutate a markerless legacy order store.
    try { await this.#instance; } catch { return; }
    const now = this.#now();
    const sql = this.ctx.storage.sql;
    const log = maybe(sql, "SELECT value FROM meta WHERE key='log'")?.value;
    if (!log) return;
    const doomed = this.ctx.storage.transactionSync(() => {
      const resumed = sql.exec("SELECT commitment FROM bodies WHERE state='reclaiming' LIMIT ?", SWEEP).toArray();
      sql.exec(`UPDATE bodies SET state='reclaiming' WHERE commitment IN (SELECT commitment FROM bodies
        WHERE state='staging' AND since_ms<=? ORDER BY since_ms LIMIT ?)`, now - DAY_MS, SWEEP - resumed.length);
      return sql.exec("SELECT commitment FROM bodies WHERE state='reclaiming' LIMIT ?", SWEEP)
        .toArray().map(row => row.commitment);
    });
    await this.#hooks.sync();
    await this.#hooks.afterMark();
    if (doomed.length) {
      await this.env.BODIES.delete(doomed.map(commitment => this.#key(log, commitment)));
      await this.#hooks.afterDelete();
      this.ctx.storage.transactionSync(() => {
        for (const commitment of doomed)
          sql.exec("DELETE FROM bodies WHERE commitment=? AND state='reclaiming'", commitment);
      });
      await this.#hooks.sync();
    }
    const more = maybe(sql, "SELECT 1 AS more FROM bodies WHERE state='reclaiming' LIMIT 1");
    const oldest = maybe(sql, "SELECT MIN(since_ms) AS since FROM bodies WHERE state='staging'")?.since;
    if (more) await this.ctx.storage.setAlarm(now + RETRY_MS);
    else if (safe(oldest)) await this.ctx.storage.setAlarm(Math.max(oldest + DAY_MS, now + RETRY_MS));
  }

  #now() {
    const now = this.#hooks.now();
    if (!safe(now)) refuse('Unavailable');
    return now;
  }
  async #guard(run) {
    try {
      // All RPCs, including body-free reads and head notices, must wait for
      // the canonical opening/tail check completed at activation.
      await this.#instance;
      return await run();
    } catch (error) {
      if (error instanceof Refused) return { refused: error.reason };
      // Class and message only, with any hex run (a key or identifier) elided:
      // never permit, body or identifier bytes.
      const message = String(error?.message ?? '').replace(/[0-9a-f]{16,}/gi, '…');
      console.error(`log object: ${error?.name ?? 'Error'}: ${message}`);
      return { refused: 'Unavailable' };
    }
  }
  // Rust verifies the permit's certificate, signature and window against the
  // pinned root at this object's clock, and binds it to the exact bytes.
  #verify(instance, permit, payload, kind) {
    const root = this.env.HOSTING_ROOT;
    if (typeof root !== 'string' || !/^[0-9a-f]{64}$/.test(root)) refuse('Unavailable');
    permit = bytes(permit);
    if (permit.length > MAX_PERMIT) refuse('Malformed');
    const scope = call(instance, 'verify_permit',
      [unhex(root), be(this.#now(), 8), be(permit.length, 4), permit, payload]);
    if (scope.scope !== kind || !this.env.LOG.idFromName(scope.log).equals(this.ctx.id)) refuse('Scope');
    return scope;
  }
  #bind(log) {
    const sql = this.ctx.storage.sql;
    const bound = maybe(sql, "SELECT value FROM meta WHERE key='log'")?.value;
    if (bound === undefined) sql.exec("INSERT INTO meta(key,value) VALUES('log',?)", log);
    else if (bound !== log) refuse('Scope');
  }
  // The last ordered event (`head`) or the last ordered control (`control`).
  #head(key = 'head') {
    const value = maybe(this.ctx.storage.sql, 'SELECT value FROM meta WHERE key=?', key)?.value;
    if (value === undefined) return { ...EMPTY };
    const head = JSON.parse(value);
    if (!safe(head.position)) throw new Error(`stored ${key}`);
    return head;
  }
  // Inside a transaction. The permit is checked at use: deadline, then the
  // exact-retry index, then the predecessor (controls) or epoch (content),
  // then the body row. Returns the original result for an exact retry on the
  // same route. A control's predecessor is the control head, so content
  // ordered since the last control never holds a control back.
  #admit(instance, scope) {
    const now = this.#now();
    if (now < scope.issued_ms || now >= scope.deadline_ms) refuse('Expired');
    this.#bind(scope.log);
    const sql = this.ctx.storage.sql;
    const prior = maybe(sql, 'SELECT position,digest,control,commitment FROM events WHERE event_id=?', scope.event_id);
    if (prior) {
      if (prior.digest !== scope.digest || prior.control !== (scope.after ? 1 : 0)) refuse('Conflict');
      const commitment = new Uint8Array(prior.commitment);
      const state = call(instance, 'commitment_state', [unhex(scope.log.slice(2)), commitment]);
      if (state.position !== prior.position || state.event_id !== scope.event_id || state.digest !== prior.digest)
        throw new Error('retry row mismatch');
      return { ack: { position: state.position, hash: state.hash, eventId: state.event_id,
        commitment: state.commitment } };
    }
    if (scope.after) {
      const control = this.#head('control');
      if (scope.after.position !== control.position || scope.after.hash !== control.hash) refuse('Predecessor');
    } else if (scope.epoch === CLOSED || maybe(sql, "SELECT value FROM meta WHERE key='epoch'")?.value !== scope.epoch) {
      refuse('Epoch');
    }
    if (scope.body === null) return { len: null, gen: null };
    const row = maybe(sql, 'SELECT state,len,gen FROM bodies WHERE commitment=?', scope.body);
    // Only a `staging` body can be ordered, so a body that is already `ordered`
    // never belongs to a second event.
    if (row?.state !== 'staging') refuse('NotStaged');
    // A control's attached body (a rekey's seal set) is staged and fenced
    // exactly like its own.
    let attached = null;
    if (scope.attached !== null) {
      const extra = maybe(sql, 'SELECT state,len,gen FROM bodies WHERE commitment=?', scope.attached);
      if (extra?.state !== 'staging') refuse('NotStaged');
      attached = { len: extra.len, gen: extra.gen };
    }
    return { len: row.len, gen: row.gen, attached };
  }
  // The bodies an append orders and their staged lengths: its own, then any
  // attached one.
  #bodies(scope, admitted) {
    const bodies = [[scope.body, admitted.len]];
    if (scope.attached !== null) bodies.push([scope.attached, admitted.attached.len]);
    return bodies;
  }
  // Inside a transaction: the next body generation from a durable counter.
  #nextGen() {
    const sql = this.ctx.storage.sql;
    const gen = Number(maybe(sql, "SELECT value FROM meta WHERE key='gen'")?.value ?? 0) + 1;
    if (!safe(gen)) throw new Error('stored gen');
    sql.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('gen',?)", String(gen));
    return gen;
  }
  // Inside the same transaction as the final #admit.
  #order(instance, scope, event) {
    const sql = this.ctx.storage.sql;
    const head = this.#head();
    // A permit with a predecessor orders a control; the route is committed in the chain.
    const control = scope.after ? 1 : 0;
    const before = maybe(sql, "SELECT value FROM meta WHERE key='opening'")?.value;
    if (typeof before !== 'string') throw new Error('missing opening');
    const next = call(instance, 'order_commitment',
      [unhex(scope.log.slice(2)), unhex(before), Uint8Array.of(control), event]);
    if (next.position !== head.position + 1 || next.event_id !== scope.event_id || next.digest !== scope.digest ||
        (head.position && before === EMPTY_OPENING))
      throw new Error('order plan');
    sql.exec('INSERT INTO events(position,event_id,digest,control,commitment,envelope) VALUES(?,?,?,?,?,?)',
      next.position, next.event_id, next.digest, control, unhex(next.commitment).buffer, event.slice().buffer);
    // rowsWritten also counts index rows; zero means the row was not staging.
    // An attached body is ordered with the event, so it is never reclaimed.
    for (const body of [scope.body, scope.attached]) {
      if (body !== null &&
          sql.exec("UPDATE bodies SET state='ordered' WHERE commitment=? AND state='staging'", body).rowsWritten === 0)
        throw new Error('body state');
    }
    const ordered = JSON.stringify({ position: next.position, hash: next.hash });
    // A control carries the epoch the log is in once it is ordered, all zeros
    // once closed; content must match an open one. It is the next control's
    // predecessor.
    if (scope.after) {
      sql.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('epoch',?)", scope.epoch);
      sql.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('control',?)", ordered);
    }
    sql.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('head',?)", ordered);
    sql.exec("INSERT OR REPLACE INTO meta(key,value) VALUES('opening',?)", next.order);
    return { position: next.position, hash: next.hash, eventId: next.event_id, commitment: next.commitment };
  }
  #key(log, commitment) { return `b/${log}/${commitment}`; }
  async #ensureAlarm(at) {
    if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(at);
  }
  // ---- presence: synchronous, no await, no storage, R2 or console --------

  #isPresence(socket) { return this.ctx.getTags(socket).includes('presence'); }
  // The other open presence sockets at the current epoch.
  #present(except) {
    return this.ctx.getWebSockets('presence').filter(socket => socket !== except &&
      socket.readyState === WebSocket.OPEN && socket.deserializeAttachment()?.epoch === this.#epoch);
  }
  // Only the current, open epoch joins; otherwise 409 and the edge answers
  // `Refused{Epoch}`.
  #join(epoch) {
    if (epoch === null || epoch !== this.#epoch || epoch === CLOSED) return new Response(null, { status: 409 });
    const others = this.#present();
    const taken = new Set(this.ctx.getWebSockets('presence').map(socket => socket.deserializeAttachment()?.slot));
    let slot;
    do slot = crypto.getRandomValues(new Uint32Array(1))[0]; while (taken.has(slot));
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server, ['presence']);
    server.serializeAttachment({ epoch, slot });
    server.send(peers(others.length, SNAPSHOT, slot));
    for (const socket of others) trySend(socket, peers(others.length, JOINED, slot));
    return new Response(null, { status: 101, webSocket: client });
  }
  // Forwards `from || sealed` to every other current presence socket.
  #relay(socket, message) {
    // A socket this object is closing forwards nothing more.
    if (socket.readyState !== WebSocket.OPEN) return;
    if (typeof message === 'string') { tryClose(socket, 1003, 'binary frames only'); return; }
    const sealed = new Uint8Array(message);
    if (sealed.length === 0 || sealed.length > MAX_PRESENCE) { tryClose(socket, 1009, 'presence too large'); return; }
    // Both buckets are checked before any attachment is read, so a dropped
    // frame costs no work per socket. The out bucket takes the most sends
    // the frame could need and returns what it did not.
    const most = this.ctx.getWebSockets('presence').length - 1;
    if (!this.#take(this.#in, PRESENCE_IN, 1) || !this.#take(this.#out, PRESENCE_OUT, most)) return;
    const from = socket.deserializeAttachment();
    const to = from?.epoch === this.#epoch ? this.#present(socket) : null;
    this.#out.tokens += most - (to?.length ?? 0);
    if (!to) { this.#end(socket); return; }
    const out = new Uint8Array(5 + sealed.length);
    out[0] = FRAME;
    new DataView(out.buffer).setUint32(1, from.slot);
    out.set(sealed, 5);
    for (const other of to) trySend(other, out);
  }
  #left(socket) {
    const slot = socket.deserializeAttachment()?.slot;
    if (slot === undefined || this.#ended.has(socket)) return;
    const others = this.#present(socket);
    for (const other of others) trySend(other, peers(others.length - 1, LEFT, slot));
  }
  // Takes `count` tokens from a bucket refilled at `rate` a second, up to one
  // second's worth, or none if it holds fewer.
  #take(bucket, rate, count) {
    const now = this.#hooks.now();
    if (!safe(now)) return false;
    if (bucket.at !== null) bucket.tokens = Math.min(rate, bucket.tokens + Math.max(0, now - bucket.at) * rate / 1000);
    bucket.at = now;
    if (bucket.tokens < count) return false;
    bucket.tokens -= count;
    return true;
  }
  // A control was ordered: every presence socket closes, and joins from now
  // on must name the epoch it carries.
  #reopen(epoch) {
    this.#epoch = epoch;
    for (const socket of this.ctx.getWebSockets('presence')) this.#end(socket);
  }
  #end(socket) {
    this.#ended.add(socket);
    tryClose(socket, EPOCH_CLOSE, 'epoch');
  }

  #notice() {
    const head = this.#head();
    const out = new Uint8Array(40);
    out.set(be(head.position, 8));
    out.set(unhex(head.hash), 8);
    return out;
  }
  // Head notices go to subscription sockets only, never presence.
  #notify() {
    const notice = this.#notice();
    for (const socket of this.ctx.getWebSockets()) {
      if (this.#isPresence(socket)) continue;
      try { socket.send(notice); } catch { /* a closing socket misses a notice; the next one carries the head */ }
    }
  }
}

export default { fetch() { return new Response(null, { status: 404 }); } };
