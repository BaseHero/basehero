// Test-only harness for the edge: the real routes, with a log object that
// holds its answers back after doing the work, R2 reads that can be held and
// are counted, a clock that can be moved ahead of real time, and the edge's
// memory budget read back or partly taken by a stand-in. Never bundle
// as a deployed entry point.
import edge from '../../services/sync-worker/src/edge.mjs';
import { LogObject } from '../../services/sync-worker/src/log.mjs';
import { admit, budget, charge, release, uncharge } from '../../services/sync-worker/src/budget.mjs';

export { PairingRelay } from '../../services/sync-worker/src/relay.mjs';

const sleep = ms => new Promise(done => setTimeout(done, ms));

// The object commits, stages or reads first, then waits `holds[method]` ms
// before it answers, so its own clock check happened inside the window.
export class SlowLog extends LogObject {
  holds = {};
  calls = { stage: 0, append: 0, read: 0 };
  #put = null;
  #stage = null;
  #head = null;
  #sync = null;
  #syncHeld = null;
  #appendWaiters = [];
  constructor(ctx, env) {
    super(ctx, env, { sync: async () => {
      if (this.holds.failSync) throw new Error('test sync failure');
      // The next storage sync stops here, after its transaction committed.
      const gate = this.#sync;
      if (gate) {
        this.#sync = null;
        gate.entered();
        await gate.release;
      }
      await ctx.storage.sync();
    }, beforePut: async () => {
      if (!this.#put) return;
      this.#put.entered();
      await this.#put.release;
    }, afterHead: async () => {
      if (!this.#head) return;
      this.#head.entered();
      await this.#head.release;
    } });
  }
  async control(holds) {
    if (holds.action === 'waitForPut') {
      await this.#put.reached;
      return { ...this.calls };
    }
    if (holds.action === 'waitForHead') {
      await this.#head.reached;
      return { ...this.calls };
    }
    if (holds.action === 'releaseHead') {
      this.#head?.resume(); this.#head = null;
      return { ...this.calls };
    }
    if (holds.action === 'waitForSync') {
      await this.#syncHeld.reached;
      return { ...this.calls };
    }
    if (holds.action === 'releaseSync') {
      this.#syncHeld?.resume(); this.#syncHeld = null;
      return { ...this.calls };
    }
    if (holds.action === 'waitForStage') {
      await this.#stage.reached;
      return { ...this.calls };
    }
    if (holds.action === 'releaseStage') {
      this.#stage?.resume(); this.#stage = null;
      return { ...this.calls };
    }
    if (holds.action === 'releasePut') {
      this.#put?.resume(); this.#put = null;
      return { ...this.calls };
    }
    if (holds.action === 'calls') return { ...this.calls };
    // A log object restart, as a deploy or eviction does: every socket it
    // accepted closes and its memory is gone.
    if (holds.action === 'abort') {
      try { this.ctx.abort('test restart'); } catch { /* the abort ends this call */ }
      return { ok: true };
    }
    if (holds.action === 'dump') return dump(this.ctx);
    if (holds.action === 'waitForAppend') {
      if (this.calls.append < holds.count)
        await new Promise(resolve => this.#appendWaiters.push({ count: holds.count, resolve }));
      return { ...this.calls };
    }
    if (holds.holdPut || holds.holdStage || holds.holdHead || holds.holdSync) {
      let entered, resume;
      const reached = new Promise(resolve => { entered = resolve; });
      const release = new Promise(resolve => { resume = resolve; });
      const gate = { entered, reached, release, resume };
      if (holds.holdPut) this.#put = gate;
      else if (holds.holdHead) this.#head = gate;
      else if (holds.holdSync) this.#sync = this.#syncHeld = gate;
      else this.#stage = gate;
    }
    this.holds = holds;
    return { ok: true };
  }
  async storeHomeObjects(...args) { return this.#held('storeHomeObjects', await super.storeHomeObjects(...args)); }
  async stage(...args) {
    this.calls.stage++;
    const result = await super.stage(...args);
    if (this.#stage) { this.#stage.entered(); await this.#stage.release; }
    return this.#held('stage', result);
  }
  async append(...args) {
    const result = await super.append(...args);
    this.calls.append++;
    for (const waiter of this.#appendWaiters.filter(w => w.count <= this.calls.append)) waiter.resolve();
    this.#appendWaiters = this.#appendWaiters.filter(w => w.count > this.calls.append);
    return this.#held('append', result);
  }
  async read(...args) { this.calls.read++; return this.#held('read', await super.read(...args)); }
  async controls(...args) { return this.#held('controls', await super.controls(...args)); }
  async #held(method, result) {
    await sleep(this.holds[method] ?? 0);
    return result;
  }
}

// Every row of every table this object stores, and its key-value entries, in hex.
async function dump(ctx) {
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  const value = v => v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? hex(v) : v;
  const sql = ctx.storage.sql;
  // The runtime's own tables are not readable; `list()` below covers its key-value one.
  const tables = sql.exec("SELECT name FROM sqlite_master WHERE type='table'").toArray().map(row => row.name)
    .filter(name => !name.startsWith('_cf_') && !name.startsWith('sqlite_'));
  const rows = Object.fromEntries(tables.map(name => [name, sql.exec(`SELECT * FROM "${name}"`).toArray()
    .map(row => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, value(v)])))]));
  const kv = Object.fromEntries([...(await ctx.storage.list())].map(([k, v]) => [k, JSON.stringify(v)]));
  return { rows, kv };
}

// R2 keys whose get waits this many ms first.
const bodyHolds = new Map();
// R2 body reads the edge has started; the most in flight at once since the
// last edge control, those in flight now; a delay for every read; and the
// read, counted from the last edge control, that finds no object.
let gets = 0;
let peak = 0;
let active = 0;
let bodyDelay = 0;
let started = 0;
let missAt = null;
// Milliseconds this isolate's `Date.now()` runs ahead of real time, or a
// fixed time it stands at. Timers still run on real time.
const realNow = Date.now;
let ahead = 0;
let frozen = null;
Date.now = () => (frozen ?? realNow()) + ahead;
// Lasting costs and frames taken by the fixture, standing in for other
// devices' sockets and the frames in flight to them.
let ballast = 0;
let inFlight = 0;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/control/log') {
      const stub = env.LOG.get(env.LOG.idFromName(url.searchParams.get('log')));
      const holds = await request.json();
      try { return Response.json(await stub.control(holds)); } catch (error) {
        // An aborted object fails the call that aborted it.
        if (holds.action === 'abort') return Response.json({ ok: true });
        throw error;
      }
    }
    if (url.pathname === '/control/edge') {
      const settings = await request.json();
      bodyHolds.clear();
      for (const [key, ms] of Object.entries(settings.bodyHolds ?? {})) bodyHolds.set(key, ms);
      ahead = settings.ahead ?? 0;
      frozen = settings.frozen ?? null;
      bodyDelay = settings.bodyDelay ?? 0;
      missAt = settings.missAt ?? null;
      const answer = { ok: true, gets, peak, active };
      peak = active;
      started = 0;
      return Response.json(answer);
    }
    // The budget now; `{ballast}` first replaces the stand-in lasting cost,
    // and `{frames}` the stand-in frames, taking none if it does not fit.
    if (url.pathname === '/control/budget') {
      const settings = await request.json();
      if (settings.ballast !== undefined) {
        if (ballast) release(ballast);
        ballast = settings.ballast && admit(settings.ballast) ? settings.ballast : 0;
      }
      if (settings.frames !== undefined) {
        if (inFlight) uncharge(inFlight);
        inFlight = settings.frames && charge(settings.frames, true) ? settings.frames : 0;
      }
      return Response.json({ ...budget(), ballast, inFlight });
    }
    if (url.pathname === '/control/r2') {
      return Response.json((await env.BODIES.list()).objects.map(o => o.key));
    }
    const bodies = {
      async get(key) {
        gets++;
        const nth = started++;
        peak = Math.max(peak, ++active);
        try {
          await sleep(bodyDelay);
          if (bodyHolds.has(key)) await sleep(bodyHolds.get(key));
          return nth === missAt ? null : await env.BODIES.get(key);
        } finally { active--; }
      },
    };
    return edge.fetch(request, { ...env, BODIES: bodies }, ctx);
  },
};
