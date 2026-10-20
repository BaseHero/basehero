// The public edge Worker. It serves exactly these routes; anything else is 404.
//
//   GET /v1/authz   WebSocket proxied, bytes unchanged, to one ready
//                   authorization backend chosen per connection.
//   GET /v1/data    WebSocket of data-wire frames. Every request carries a
//                   hosting permit, verified here before any log object is
//                   called; every data frame is gated on that permit's deadline
//                   and on the send window the device has granted. Presence
//                   frames ride a verified presence join and never wait for
//                   window: they are sent at once or dropped.
//   POST|GET /v1/pair/<64 hex>?side=show|join&index=0-3
//                   Opaque pairing relay messages.
import { LogObject } from './log.mjs';
import { MAX_MESSAGE, PairingRelay } from './relay.mjs';
import { SMALL, SOCKET_COST, STREAM_COST, admit, block, charge, release, take, unblock, uncharge, waiting } from './budget.mjs';
import { REASONS, Refused, be, call, instantiate, refuse, safe, unhex } from './wasm.mjs';

export { LogObject, PairingRelay };

let wasm;
const instance = () => (wasm ??= instantiate());

function failed(where, error) {
  // Class and message only, with any hex run (a key or identifier) elided:
  // never permit, body or identifier bytes.
  const message = String(error?.message ?? '').replace(/[0-9a-f]{16,}/gi, '…');
  console.error(`edge ${where}: ${error?.name ?? 'Error'}: ${message}`);
}
const status = code => new Response(null, { status: code });

// ---- memory budget ---------------------------------------------------------

// Charged in `budget.mjs`, which states what each socket costs and why.

// ---- /v1/authz -------------------------------------------------------------

// Admission is charged before any await, so concurrent arrivals cannot
// overshoot the budget while their upgrades are pending.
// The attested channel's largest frame: an 11-byte header and the largest proof.
const AUTHZ_MAX_FRAME = 11 + 3_212_592;
// Bytes a session may carry, both directions together, in any rolling minute.
const AUTHZ_RATE_BYTES = 8 * 1024 * 1024;
const AUTHZ_RATE_SECONDS = 60;
const AUTHZ_UPGRADE_MS = 2000;
let authzNext = 0;

function readyBackends(env) {
  let list;
  try { list = JSON.parse(env.AUTHZ_BACKENDS ?? '[]'); } catch { return []; }
  if (!Array.isArray(list)) return [];
  return list.filter(b => b?.ready === true && typeof b.url === 'string' && /^https?:\/\//.test(b.url)).map(b => b.url);
}

async function authz(env) {
  if (!admit(SOCKET_COST)) return status(503);
  let released = false;
  const end = () => { if (!released) { released = true; release(SOCKET_COST); } };
  let upstream, proxy, handedOff = false;
  try {
    // Rotate the first choice per connection. A backend that does not accept
    // the upgrade is skipped before any frame flows; once frames flow the
    // connection stays pinned, and nothing is ever resent to another backend.
    const ready = readyBackends(env);
    const start = authzNext++;
    for (let i = 0; i < ready.length && !upstream; i++) {
      // The timeout covers only the upgrade: a signal passed to fetch stays
      // bound to the upgraded socket, so it is cleared once the answer arrives.
      const upgrade = new AbortController();
      const timer = setTimeout(() => upgrade.abort(), AUTHZ_UPGRADE_MS);
      try {
        const response = await fetch(ready[(start + i) % ready.length], {
          headers: { Upgrade: 'websocket' }, signal: upgrade.signal,
        });
        if (response.status === 101 && response.webSocket) upstream = response.webSocket;
      } catch { /* try the next ready backend */ } finally { clearTimeout(timer); }
    }
    if (!upstream) return status(503);
    const [client, peer] = Object.values(new WebSocketPair());
    proxy = peer;
    let disposed = false;
    // Bytes per whole second of the last minute, oldest first.
    const recent = [];
    const withinRate = length => {
      const second = Math.floor(Date.now() / 1000);
      while (recent.length && recent[0].second <= second - AUTHZ_RATE_SECONDS) recent.shift();
      const total = recent.reduce((sum, bucket) => sum + bucket.bytes, 0);
      if (total + length > AUTHZ_RATE_BYTES) return false;
      if (recent.at(-1)?.second === second) recent.at(-1).bytes += length;
      else recent.push({ second, bytes: length });
      return true;
    };
    const stop = (code, reason) => {
      if (disposed) return;
      disposed = true;
      end();
      try { proxy.close(code, reason); } catch { /* already closed */ }
      try { upstream.close(code, reason); } catch { /* already closed */ }
    };
    proxy.accept();
    upstream.accept();
    for (const [source, target] of [[proxy, upstream], [upstream, proxy]]) {
      let processing = false;
      source.addEventListener('message', event => {
        if (disposed) return;
        if (typeof event.data === 'string') { stop(1003, 'binary frames only'); return; }
        const length = event.data?.size ?? event.data?.byteLength;
        if (processing) { stop(1011, 'queue full'); return; }
        if (!Number.isSafeInteger(length) || length > AUTHZ_MAX_FRAME) { stop(1009, 'frame limit'); return; }
        if (!withinRate(length)) { stop(1008, 'rate limit'); return; }
        processing = true;
        // A binary message may arrive as a Blob; it is bounded above before
        // conversion. The bytes are forwarded as they are, never read.
        Promise.resolve(event.data instanceof Blob ? event.data.arrayBuffer() : event.data).then(bytes => {
          if (!disposed) target.send(bytes);
        }).catch(() => stop(1011, 'transport')).finally(() => { processing = false; });
      });
      source.addEventListener('close', () => stop(1011, 'interrupted'));
      source.addEventListener('error', () => stop(1011, 'transport'));
    }
    const response = new Response(null, { status: 101, webSocket: client });
    handedOff = true;
    return response;
  } finally {
    if (!handedOff) {
      end();
      try { proxy?.close(1011, 'interrupted'); } catch { /* not accepted or already closed */ }
      try { upstream?.close(1011, 'interrupted'); } catch { /* not accepted or already closed */ }
    }
  }
}

// ---- /v1/data --------------------------------------------------------------

const MAX_FRAME = 4 * 1024 * 1024 + 64 * 1024;
// Each data socket's send window before any Credit: one largest frame plus margin.
const INITIAL_WINDOW = MAX_FRAME + 4 * 1024 * 1024;
// Unused window a device may hold; a grant past it closes the socket with 1008.
const MAX_WINDOW = 64 * 1024 * 1024;
// Bytes of data frames a socket may have taken and not had back by Credit or
// refund, however much window it has granted: what an honest device, which
// credits exactly what it received, can have in flight.
const MAX_HELD = INITIAL_WINDOW;
// While any frame waits for the budget, a socket that has not credited back,
// within this long, everything it held when its stall time began is closed
// with 1013, which clients retry, and returns all it holds. A stall time
// begins when a socket begins to hold frames, and again each time it has paid
// what it owed; credit for only part, or frames returned unsent, does not pay
// it. So a frame is held uncredited for at most twice this while others wait.
// An honest device credits each frame as it arrives, so this closes it only
// if its link brings less than a full initial window in two minutes (about
// 560 kbit/s) while the isolate is short of budget; the longest single frame,
// a 4.2 MB Events frame, takes about 35 s at 1 Mbit/s.
const STALL_MS = 120_000;
// One Events item at the largest envelope: commitment and event blobs.
const MAX_EVENTS_ITEM = 4 + 179 + 4 + 2 + 32 + 4 + 65536;
const RECEIPT_LEN = 300;
// Header, count, option flag, fixed-width receipt: 64 max items total
// 4,209,014 bytes, below MAX_FRAME (4,259,840).
const MAX_EVENTS_FIXED = 7 + 2 + 1 + RECEIPT_LEN;
const MAX_PERMIT = 4096;
const MAX_IN_FLIGHT = 8;
// R2 reads one body stream keeps in flight: each takes about 120 ms from the
// edge, so 64 bodies take four rounds, not 64. Window and budget bound their
// memory whatever this is. If the runtime's limit on an invocation's
// simultaneous connections counts these reads, those past it wait their turn
// (unverified for R2 bindings), so this is a ceiling, not a promise.
const BODY_READS = 16;
const MAX_SUBSCRIPTIONS = 64;
// A socket must present a verified permit this soon after opening; Credit is
// not a permit and does not extend it. A request refused before then closes
// the socket, so it costs at most one permit verification.
const DATA_FIRST_PERMIT_MS = 5_000;
// An admitted socket with no request in flight and no subscription closes
// after this. Credit is not activity.
const DATA_IDLE_MS = 10_000;
const MAX_CONTROLS = 64;
const SCOPES = { read: ['read_events', 'read_bodies', 'read_controls'], stage: ['stage'], append: ['append'], subscribe: ['subscribe'], store_home_objects: ['store_home_objects'], presence_join: ['presence'] };
// Presence: opaque sealed frames of at most this many bytes. Each join may
// send 10 a second after a burst of 20; excess frames are dropped, and a socket
// that drops more than 100 in a minute is closed.
const MAX_PRESENCE = 512;
const PRESENCE_RATE = 10;
const PRESENCE_BURST = 20;
const PRESENCE_MAX_DROPS = 100;
// Peers waiting for window per join. A join that would queue more, or whose
// Peers miss their window, ends `Unavailable`, so the device rejoins for a
// fresh roster rather than keep a slot that has left.
const MAX_PEERS_WAITING = 16;
// The log object's presence messages: `PEERS || others:u16 || event:u8 ||
// slot:u32` for a roster change, `FRAME || from:u32 || sealed` for a frame.
const PEERS = 0;
const FRAME = 1;
// The log object closes a presence socket with this when the epoch changes.
const EPOCH_CLOSE = 4409;

// Response frames: `version:u16 = 1` for legacy, version 2 for tags from 32
// (Published, Presence, Peers); `tag:u8 || id:u32 || fields`, with
// variable byte strings as `length:u32 || bytes`.
function response(tag, id, blobs, fixed = []) {
  const size = 7 + fixed.reduce((n, f) => n + f.length, 0) + blobs.reduce((n, b) => n + 4 + b.length, 0);
  if (size > MAX_FRAME) throw new Error('response frame too large');
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  view.setUint16(0, tag >= 32 ? 2 : 1);
  out[2] = tag;
  view.setUint32(3, id);
  let at = 7;
  for (const part of fixed) { out.set(part, at); at += part.length; }
  for (const blob of blobs) { view.setUint32(at, blob.length); out.set(blob, at + 4); at += 4 + blob.length; }
  return out;
}
const encode = {
  events: (id, items, receipt) => {
    if (items.length > 64 || (receipt && receipt.length !== RECEIPT_LEN)) throw new Error('events framing');
    return response(1, id, items.flatMap(i => [i.commitment, i.event]),
      [be(items.length, 4).subarray(2), Uint8Array.of(receipt ? 1 : 0), ...(receipt ? [receipt] : [])]);
  },
  body: (id, index, last, bytes) => response(2, id, [bytes], [Uint8Array.of(index, last ? 1 : 0)]),
  staged: id => response(3, id, []),
  homeObjectsStored: (id, prefix, digest) => response(7, id, [], [unhex(prefix), unhex(digest)]),
  acked: (id, ack) => response(4, id, [ack]),
  published: (id, ack, commitment) => {
    if (commitment.length !== 179) throw new Error('commitment length');
    const prefix = response(32, id, [ack]);
    const out = new Uint8Array(prefix.length + commitment.length);
    if (out.length > MAX_FRAME) throw new Error('response frame too large');
    out.set(prefix); out.set(commitment, prefix.length);
    return out;
  },
  head: (id, notice, receipt) => receipt
    ? response(5, id, [receipt], [notice, Uint8Array.of(1)])
    : response(5, id, [], [notice, Uint8Array.of(0)]),
  refused: (id, reason) => response(6, id, [], [Uint8Array.of(REASONS.indexOf(reason) > 0 ? REASONS.indexOf(reason) : 10)]),
  presence: (id, from, sealed) => response(35, id, [sealed], [be(from, 4)]),
  peers: (id, others, event, slot) => response(36, id, [], [be(others, 4).subarray(2), Uint8Array.of(event), be(slot, 4)]),
};

function hostingKeys(env) {
  const is = (value, length) => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
  if (!is(env.HOSTING_ROOT, 64) || !is(env.RECEIPT_KEY, 64) || !is(env.RECEIPT_CERT, 260)) return null;
  return { root: unhex(env.HOSTING_ROOT), seed: unhex(env.RECEIPT_KEY), cert: unhex(env.RECEIPT_CERT) };
}

class DataSession {
  #socket;
  #env;
  #keys;
  // Whether this socket's lasting cost is charged to the budget, which it is
  // from its first verified permit, never before.
  #admitted = false;
  // The first-permit deadline until admitted, then the idle timer, if running.
  #timer = null;
  #inFlight = 0;
  #subscriptions = new Map();
  // Presence joins by base log, and when this socket dropped presence frames
  // over a join's rate in the last minute.
  #presence = new Map();
  #drops = [];
  #closed = false;
  // Bytes of data frames the edge may still send, and the frames waiting for
  // more or for the budget, first come first served. `#held` is what this
  // socket has taken and not had back, all of it charged to the budget.
  #window = INITIAL_WINDOW;
  #held = 0;
  #waiting = [];
  // What this socket still owes, by Credit, of what it held when its stall
  // time began, and when that was.
  #owed = 0;
  #since = 0;
  // Closes this socket for a stalled credit, from any request: a socket can
  // be closed only by the request that holds it, where this reaction runs.
  #stalled;
  // The sockets holding frames, the earliest time one of them may have
  // stalled, and the timer that checks then while any frame waits, counted.
  static #holding = new Set();
  static #due = Infinity;
  static #check = null;
  static #checks = 0;
  // The request frames being handled, as the functions that return their
  // charges: a close returns them at once, as their handling may never end.
  #requests = new Set();
  #resume = () => this.#pump();
  constructor(socket, env, keys) {
    this.#socket = socket;
    this.#env = env;
    this.#keys = keys;
    this.#timer = setTimeout(() => this.#close(1008, 'no permit'), DATA_FIRST_PERMIT_MS);
    new Promise(resolve => { this.#stalled = resolve; }).then(() => this.#close(1013, 'credit stalled'));
    socket.addEventListener('message', event => this.#message(event.data));
    socket.addEventListener('close', () => this.#close());
    socket.addEventListener('error', () => this.#close());
  }

  #message(data) {
    if (this.#closed) return;
    if (typeof data === 'string') { this.#close(1003, 'binary frames only'); return; }
    const length = data?.size ?? data?.byteLength;
    if (!safe(length) || length > MAX_FRAME) { this.#close(1009, 'frame too large'); return; }
    this.#inFlight++;
    const cost = 2 * length;
    const paid = charge(cost, cost <= SMALL);
    const done = () => {
      if (!this.#requests.delete(done)) return;
      this.#inFlight--;
      if (paid) uncharge(cost);
    };
    this.#requests.add(done);
    this.#handle(data, done, paid).catch(error => {
      failed('data', error);
      this.#close(1011, 'internal error');
    }).finally(() => { done(); this.#idle(); });
  }

  // Charges the socket's lasting cost at its first verified permit. If the
  // budget's lasting half is full, the request is refused and the socket closed.
  #admit(id) {
    if (this.#admitted) return true;
    if (!admit(SOCKET_COST)) {
      this.#refuse(id, 'Unavailable');
      this.#close(1013, 'try again later');
      return false;
    }
    this.#admitted = true;
    clearTimeout(this.#timer);
    this.#timer = null;
    return true;
  }

  // A request's permit has verified: the admitted socket is not idle.
  #busy() {
    clearTimeout(this.#timer);
    this.#timer = null;
  }

  // Starts the idle timer of an admitted socket with nothing in flight and no
  // subscription, unless it is already running, so nothing but a request or
  // subscription moves it.
  #idle() {
    if (this.#closed || !this.#admitted || this.#timer !== null) return;
    if (this.#inFlight > 0 || this.#subscriptions.size > 0 || this.#presence.size > 0 || this.#waiting.length > 0) return;
    this.#timer = setTimeout(() => this.#close(1000, 'idle'), DATA_IDLE_MS);
  }

  async #handle(data, done, paid) {
    const frame = new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : data);
    // A presence frame (version 2, tag 34) over its bound closes the socket
    // before it is decoded.
    if (frame[0] === 0 && frame[1] === 2 && frame[2] === 34 && frame.length > 7 + 4 + MAX_PRESENCE) {
      this.#close(1009, 'presence too large');
      return;
    }
    const wasm = await instance();
    let request;
    try { request = call(wasm, 'decode_request', [frame]); } catch (error) {
      if (!(error instanceof Refused)) throw error;
      this.#close(1002, 'malformed frame');
      return;
    }
    // A grant is not a request: it never counts as in flight.
    if (request.kind === 'credit') { done(); this.#credit(request.credit); return; }
    // Nor is a presence frame, which is forwarded or dropped at once.
    if (request.kind === 'presence') {
      done();
      const [start, size] = request.payload;
      this.#presenceIn(request.id, frame.slice(start, start + size));
      return;
    }
    // A refusal before admission may have closed the socket while this frame
    // waited; its permit is then never verified.
    if (this.#closed) return;
    const { id } = request;
    // A request the budget cannot hold now is refused before its permit is
    // verified; a socket not yet admitted is then closed as at admission.
    if (!paid) {
      this.#refuse(id, 'Unavailable');
      if (!this.#admitted) this.#close(1013, 'try again later');
      return;
    }
    try {
      if (this.#inFlight > MAX_IN_FLIGHT) refuse('Unavailable');
      if (request.kind === 'publish') {
        await this.#publish(wasm, frame, request, id);
        return;
      }
      const [start, size] = request.permit;
      if (size > MAX_PERMIT) refuse('Malformed');
      // Copies, so a log object receives exactly these bytes and no more of the frame.
      const permit = frame.slice(start, start + size);
      const payload = request.payload ? frame.slice(request.payload[0], request.payload[0] + request.payload[1]) : new Uint8Array(0);
      // Rust verifies certificate, signature, window and scope bounds against
      // the pinned root, and binds stage/append permits to the exact bytes. The
      // log, range and body list served come only from this verified permit.
      const scope = call(wasm, 'verify_permit', [this.#keys.root, be(Date.now(), 8), be(permit.length, 4), permit, payload]);
      if (!SCOPES[request.kind].includes(scope.scope)) refuse('Scope');
      if (!this.#admit(id)) return;
      this.#busy();
      const log = this.#env.LOG.get(this.#env.LOG.idFromName(scope.log));
      if (scope.scope === 'read_events') await this.#readEvents(wasm, id, scope, log);
      else if (scope.scope === 'read_controls') await this.#readControls(wasm, id, scope, log);
      else if (scope.scope === 'read_bodies') await this.#readBodies(id, scope, log);
      else if (scope.scope === 'stage') {
        outcome(await log.stage(permit, payload));
        await this.#deliver(scope, 7, () => encode.staged(id));
      } else if (scope.scope === 'store_home_objects') {
        const stored = outcome(await log.storeHomeObjects(permit, payload));
        if (stored.prefixDigest !== scope.prefix_digest || stored.bundleDigest !== scope.bundle_digest)
          refuse('Unavailable');
        await this.#deliver(scope, 71, () => encode.homeObjectsStored(id, stored.prefixDigest, stored.bundleDigest));
      } else if (scope.scope === 'append') await this.#append(wasm, id, scope, log, permit, payload);
      else if (scope.scope === 'presence') await this.#join(id, scope, log);
      else await this.#subscribe(wasm, id, scope, log, request.after);
    } catch (error) {
      if (!(error instanceof Refused)) failed('request', error);
      this.#refuse(id, error instanceof Refused ? error.reason : 'Unavailable');
      if (!this.#admitted) this.#close(1008, 'refused');
    }
  }

  // The window is taken for the largest frame the permit's range allows before
  // the object is read, so waiting requests hold no event bytes.
  async #readEvents(wasm, id, scope, log) {
    // The permit bounds the range to 1-64 positions; the object also checks it.
    const bound = MAX_EVENTS_FIXED + (scope.last - scope.first + 1) * MAX_EVENTS_ITEM;
    await this.#take(scope, bound);
    await this.#events(wasm, id, scope, bound, () => log.read(scope.first, scope.last));
  }

  // Up to 64 control-route events after the permit's position, as one Events
  // frame under the same window and deadline gates as a read of 64 events.
  async #readControls(wasm, id, scope, log) {
    const bound = MAX_EVENTS_FIXED + MAX_CONTROLS * MAX_EVENTS_ITEM;
    await this.#take(scope, bound);
    await this.#events(wasm, id, scope, bound, () => log.controls(scope.after));
  }

  // Sends one Events frame from a read that took `bound` bytes of window.
  async #events(wasm, id, scope, bound, read) {
    let items, receipt = null;
    try {
      // The DO captures rows and completes storage.sync before returning.
      // Neither the requester's cursor nor the live head supplies this head.
      items = outcome(await read());
      if (items.length && scope.log.startsWith('01')) {
        const tail = items.at(-1);
        const head = call(wasm, 'read_tail', [unhex(scope.log.slice(2)), tail.commitment, tail.event]);
        const signed = call(wasm, 'sign_head', [this.#keys.root, this.#keys.seed, this.#keys.cert, unhex(scope.log),
          be(head.position, 8), unhex(head.hash)]);
        receipt = unhex(signed.receipt);
      }
    } catch (error) {
      this.#refund(bound);
      throw error;
    }
    this.#send(scope, bound, () => encode.events(id, items, receipt));
  }

  // One Body frame per commitment in permit order, each waiting for window and
  // gated on the deadline before its body is read from R2. Up to BODY_READS
  // reads run at once, taking their window in permit order, and each frame is
  // sent after the frames before it. A body that is not ordered, or not
  // found, ends the stream after the frames before it; a read not sent
  // returns its window once it has finished.
  async #readBodies(id, scope, log) {
    const lengths = outcome(await log.orderedBodies(scope.bodies));
    const count = scope.bodies.length;
    // The stream is bulk or small as a whole, so a catch-up of many small
    // bodies does not use the reserve.
    const small = lengths.reduce((n, length) => n + 13 + (safe(length) ? length : 0), 0) <= SMALL;
    // Each body's send, settled only after every send before it.
    const sends = [];
    let sent = Promise.resolve();
    try {
      for (let index = 0; index < count; index++) {
        if (index >= BODY_READS) await sends[index - BODY_READS];
        const length = lengths[index];
        if (!safe(length)) refuse('Missing');
        const size = 7 + 2 + 4 + length;
        await this.#take(scope, size, small);
        // Credit may release a waiter after its deadline, before its timer.
        if (Date.now() >= scope.deadline_ms) { this.#refund(size); refuse('Expired'); }
        const read = this.#env.BODIES.get(`b/${scope.log}/${scope.bodies[index]}`).then(async object => {
          if (!object) refuse('Missing');
          return { bytes: new Uint8Array(await object.arrayBuffer()) };
        }).catch(error => ({ error }));
        // A frame not handed to `#send`, which refunds its own, is refunded here.
        sent = sent.then(async () => {
          const { bytes, error } = await read;
          if (error) { this.#refund(size); throw error; }
          this.#send(scope, size, () => encode.body(id, index, index === count - 1, bytes));
        }, async error => {
          await read;
          this.#refund(size);
          throw error;
        });
        sends.push(sent);
      }
    } finally {
      // Frames before a failure still go first, and the earliest failure ends
      // the stream. Waiting for the last send waits for every read.
      await sent;
    }
  }

  // Check BOTH existing grants against immutable bytes before any mutation.
  // Neither the control route nor an account log may compound publication.
  async #publish(wasm, frame, request, id) {
    const part = name => {
      const [start, size] = request[name];
      return frame.slice(start, start + size);
    };
    const stagePermit = part('stage_permit');
    const appendPermit = part('append_permit');
    if (stagePermit.length > MAX_PERMIT || appendPermit.length > MAX_PERMIT) refuse('Malformed');
    const event = part('event');
    const body = part('body');
    const verify = (permit, payload) => call(wasm, 'verify_permit',
      [this.#keys.root, be(Date.now(), 8), be(permit.length, 4), permit, payload]);
    const stage = verify(stagePermit, body);
    const append = verify(appendPermit, event);
    if (stage.scope !== 'stage' || append.scope !== 'append' || !stage.log.startsWith('01') ||
        stage.log !== append.log || append.after !== null || append.body !== stage.body ||
        append.body === null || stage.len !== body.length) refuse('Scope');
    if (!this.#admit(id)) return;
    this.#busy();
    const scope = { ...append, deadline_ms: Math.min(stage.deadline_ms, append.deadline_ms) };
    const log = this.#env.LOG.get(this.#env.LOG.idFromName(scope.log));
    // Existing DO stage performs its durable R2 put before append can order.
    outcome(await log.stage(stagePermit, body));
    if (Date.now() >= scope.deadline_ms) refuse('Expired');
    const result = outcome(await log.append(appendPermit, event));
    if (result.eventId !== scope.event_id || !safe(result.position) ||
        typeof result.commitment !== 'string' || !/^[0-9a-f]{358}$/.test(result.commitment))
      refuse('Unavailable');
    const commitment = unhex(result.commitment);
    // Rust recomputes the chain hash, binds the exact descriptor and content
    // route, and refuses a forged or noncanonical stored commitment.
    const proof = call(wasm, 'publish_tail', [unhex(scope.log.slice(2)), commitment, event]);
    if (proof.position !== result.position || proof.hash !== result.hash) refuse('Unavailable');
    const signed = call(wasm, 'sign_head', [this.#keys.root, this.#keys.seed, this.#keys.cert, unhex(scope.log),
      be(proof.position, 8), unhex(proof.hash), unhex(result.eventId)]);
    const ack = unhex(signed.ack);
    await this.#deliver(scope, 7 + 4 + ack.length + commitment.length,
      () => encode.published(id, ack, commitment));
  }

  // The Ack and its receipt are made from the object's durable result only.
  async #append(wasm, id, scope, log, permit, payload) {
    const result = outcome(await log.append(permit, payload));
    if (result.eventId !== scope.event_id || !safe(result.position)) throw new Error('append result');
    const signed = call(wasm, 'sign_head', [this.#keys.root, this.#keys.seed, this.#keys.cert, unhex(scope.log),
      be(result.position, 8), unhex(result.hash), unhex(result.eventId)]);
    const ack = unhex(signed.ack);
    await this.#deliver(scope, 7 + 4 + ack.length, () => encode.acked(id, ack));
  }

  // Head notices strictly after the `after` cursor, until the permit's
  // deadline ends this subscription with `Refused{Expired}`. A newer Subscribe
  // for the same log replaces this one, which is how a device renews before
  // the deadline.
  async #subscribe(wasm, id, scope, log, after) {
    if (!safe(after)) refuse('Malformed');
    const full = () => this.#subscriptions.size >= MAX_SUBSCRIPTIONS && !this.#subscriptions.has(scope.log);
    if (full()) refuse('Unavailable');
    const upgraded = await log.fetch('https://log.invalid/subscribe', { headers: { Upgrade: 'websocket' } });
    const upstream = upgraded.webSocket;
    if (!upstream) refuse('Unavailable');
    // Other subscribes may have filled the socket during the upgrade.
    // A replacement keeps the lasting cost of the subscription it replaces.
    if (this.#closed || full() || (!this.#subscriptions.has(scope.log) && !admit(STREAM_COST))) {
      upstream.accept();
      upstream.close(1000);
      if (this.#closed) return;
      refuse('Unavailable');
    }
    this.#subscriptions.get(scope.log)?.stop();
    let chain = Promise.resolve();
    const subscription = {
      timer: setTimeout(() => end('Expired'), Math.max(0, scope.deadline_ms - Date.now())),
      stop() {
        clearTimeout(this.timer);
        try { upstream.close(1000); } catch { /* already closed */ }
      },
    };
    const current = () => this.#subscriptions.get(scope.log) === subscription;
    // Ends only this subscription with one refusal for its id, whether its
    // deadline timer or a withheld Head frame comes first.
    const end = reason => {
      if (!current()) return;
      subscription.stop();
      this.#unstream(this.#subscriptions, scope.log);
      this.#refuse(id, reason);
      this.#idle();
    };
    upstream.addEventListener('message', event => {
      chain = chain.then(async () => {
        if (!current()) return;
        const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
        if (!(data instanceof ArrayBuffer) || data.byteLength !== 40) throw new Error('head notice');
        const notice = new Uint8Array(data);
        const position = new DataView(data).getBigUint64(0);
        if (position <= BigInt(after)) return;
        const signed = call(wasm, 'sign_head', [this.#keys.root, this.#keys.seed, this.#keys.cert, unhex(scope.log),
          notice.subarray(0, 8), notice.subarray(8)]);
        const receipt = signed.receipt ? unhex(signed.receipt) : null;
        await this.#deliver(scope, 7 + 41 + (receipt ? 4 + receipt.length : 0), () => encode.head(id, notice, receipt),
          current);
      }).catch(error => {
        if (!(error instanceof Refused)) failed('subscription', error);
        end(error instanceof Refused ? error.reason : 'Unavailable');
      });
    });
    upstream.addEventListener('close', () => end('Unavailable'));
    upstream.addEventListener('error', () => end('Unavailable'));
    this.#subscriptions.set(scope.log, subscription);
    upstream.accept();
  }

  // Joins the base's presence until the permit's deadline, which then ends it
  // with `Refused{Expired}`. A newer join for the same base replaces this one:
  // at the same epoch it only takes the new id and deadline, keeping the
  // upstream socket; at another epoch it reopens. The log object ends a join
  // at an epoch change (`Refused{Epoch}`) or a restart (`Refused{Unavailable}`).
  async #join(id, scope, log) {
    const held = this.#presence.get(scope.log);
    if (held?.epoch === scope.epoch) { held.renew(id, scope.deadline_ms); return; }
    // The same per-socket bound and lasting cost as subscriptions.
    if (!held && (this.#presence.size >= MAX_SUBSCRIPTIONS || !admit(STREAM_COST))) refuse('Unavailable');
    held?.stop();
    this.#presence.delete(scope.log);
    const join = {
      id, epoch: scope.epoch, deadline_ms: scope.deadline_ms, upstream: null, timer: null,
      tokens: PRESENCE_BURST, filled: Date.now(), chain: Promise.resolve(), peers: 0,
      renew(next, deadline) {
        this.id = next;
        this.deadline_ms = deadline;
        clearTimeout(this.timer);
        this.timer = setTimeout(() => end('Expired'), Math.max(0, deadline - Date.now()));
      },
      stop() {
        clearTimeout(this.timer);
        try { this.upstream?.close(1000); } catch { /* already closed */ }
      },
    };
    const current = () => this.#presence.get(scope.log) === join;
    // Ends only this join, with one refusal for its current id.
    const end = reason => {
      if (!current()) return;
      join.stop();
      this.#unstream(this.#presence, scope.log);
      this.#refuse(join.id, reason);
      this.#idle();
    };
    join.end = end;
    join.current = current;
    join.renew(id, scope.deadline_ms);
    this.#presence.set(scope.log, join);
    let upgraded;
    try {
      upgraded = await log.fetch('https://log.invalid/presence', { headers: { Upgrade: 'websocket', 'X-Bh-Epoch': scope.epoch } });
    } catch (error) {
      if (current()) { join.stop(); this.#unstream(this.#presence, scope.log); }
      throw error;
    }
    const upstream = upgraded.webSocket;
    if (!upstream) { end(upgraded.status === 409 ? 'Epoch' : 'Unavailable'); return; }
    // Renewed at another epoch, or closed, during the upgrade.
    if (!current() || this.#closed) {
      upstream.accept();
      upstream.close(1000);
      return;
    }
    join.upstream = upstream;
    // Frames are handled as they arrive, with no await, so none waits on another.
    upstream.binaryType = 'arraybuffer';
    upstream.addEventListener('message', event => this.#presenceOut(join, event.data));
    upstream.addEventListener('close', event => end(event.code === EPOCH_CLOSE ? 'Epoch' : 'Unavailable'));
    upstream.addEventListener('error', () => end('Unavailable'));
    upstream.accept();
  }

  // A device's sealed frame, forwarded as-is to the log object if its join is
  // current and within its rate; otherwise dropped. Nothing about it is logged.
  #presenceIn(id, sealed) {
    if (this.#closed || sealed.length === 0) return;
    let join = null;
    for (const held of this.#presence.values()) if (held.id === id) join = held;
    const now = Date.now();
    if (!join?.upstream || now >= join.deadline_ms) return;
    join.tokens = Math.min(PRESENCE_BURST, join.tokens + Math.max(0, now - join.filled) * PRESENCE_RATE / 1000);
    join.filled = now;
    if (join.tokens < 1) {
      while (this.#drops.length && this.#drops[0] <= now - 60_000) this.#drops.shift();
      this.#drops.push(now);
      if (this.#drops.length > PRESENCE_MAX_DROPS) this.#close(1008, 'presence rate');
      return;
    }
    join.tokens -= 1;
    try { join.upstream.send(sealed); } catch { /* closing: its close event ends the join */ }
  }

  // A message from the log object for this join. A frame never waits for
  // window or budget: it is sent only if nothing on this socket waits, no
  // small frame in the isolate waits for the budget, and both cover it now;
  // otherwise it is dropped, so content never queues behind presence. Peers
  // changes use the normal delivery, in order. Anything else ends the join.
  #presenceOut(join, data) {
    if (!join.current() || this.#closed) return;
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : null;
    const view = bytes && new DataView(data);
    if (bytes?.[0] === PEERS && bytes.length === 8) {
      if (join.peers >= MAX_PEERS_WAITING) { join.end('Unavailable'); return; }
      join.peers++;
      const [others, event, slot] = [view.getUint16(1), bytes[3], view.getUint32(4)];
      join.chain = join.chain.then(() => this.#deliver(join, 14, () => encode.peers(join.id, others, event, slot), join.current))
        // A Peers that was not sent ends the join, as `Expired` once its
        // deadline has passed.
        .catch(() => join.end(Date.now() >= join.deadline_ms ? 'Expired' : 'Unavailable'))
        .finally(() => { join.peers--; });
      return;
    }
    if (bytes?.[0] !== FRAME || bytes.length < 6 || bytes.length > 5 + MAX_PRESENCE) { join.end('Unavailable'); return; }
    const size = 7 + 4 + 4 + bytes.length - 5;
    if (this.#waiting.length || !this.#room(size) || Date.now() >= join.deadline_ms || !take(size, true)) return;
    this.#hold(size);
    try { this.#socket.send(encode.presence(join.id, view.getUint32(1), bytes.subarray(5))); } catch { this.#close(); }
  }

  // Every data frame first takes its encoded length from the send window,
  // waiting for the device's credit, and is sent only before its permit's
  // deadline. Past the deadline, waiting or not, the frame is withheld and
  // `Refused{Expired}` ends only its request: a commit or staged body stands,
  // and the device learns an append's outcome by its exact retry. Refusals use
  // no window.
  async #deliver(scope, size, build, wanted) {
    await this.#take(scope, size);
    if (wanted && !wanted()) { this.#refund(size); return; }
    this.#send(scope, size, build);
  }

  // Resolves once the window and the budget cover `size` and takes it.
  // Throws `Expired` at the permit's deadline, or `Unavailable` when the
  // socket closes.
  #take(scope, size, small = size <= SMALL) {
    if (this.#closed) refuse('Unavailable');
    if (Date.now() >= scope.deadline_ms) refuse('Expired');
    if (!this.#waiting.length && this.#room(size) && take(size, small)) {
      this.#hold(size);
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const waiter = { size, small, resolve, reject };
      // A timer cleared from another request still fires: it ends only a
      // waiter that still waits.
      waiter.timer = setTimeout(() => {
        const index = this.#waiting.indexOf(waiter);
        if (index < 0) return;
        this.#waiting.splice(index, 1);
        reject(new Refused('Expired'));
        this.#pump();
      }, scope.deadline_ms - Date.now());
      this.#waiting.push(waiter);
      this.#pump();
    });
  }

  // Whether the window covers `size` and this socket may hold it in flight.
  #room(size) {
    return this.#window >= size && this.#held + size <= MAX_HELD;
  }

  // Takes `size`, already charged to the budget, from the window. A socket
  // that held nothing begins its stall time.
  #hold(size) {
    this.#window -= size;
    this.#held += size;
    if (!this.#owed) this.#owe();
  }

  // Begins a stall time: the socket owes everything it holds now.
  #owe() {
    this.#owed = this.#held;
    this.#since = Date.now();
    if (!this.#held) { DataSession.#holding.delete(this); return; }
    DataSession.#holding.add(this);
    if (DataSession.#due === Infinity) {
      DataSession.#due = this.#since + STALL_MS;
      DataSession.#watch();
    }
  }

  // Sets the check for when the first holding socket may have stalled, if
  // any frame waits for the budget. A check cleared from another request
  // still fires, so only the latest one sweeps.
  static #watch() {
    clearTimeout(DataSession.#check);
    const check = ++DataSession.#checks;
    DataSession.#check = waiting() && DataSession.#due < Infinity
      ? setTimeout(() => { if (check === DataSession.#checks) DataSession.#sweep(); },
        Math.max(0, DataSession.#due - Date.now()))
      : null;
  }

  // While any frame waits, closes each socket whose stall time has passed.
  static #sweep() {
    if (!waiting()) return;
    const now = Date.now();
    DataSession.#due = Infinity;
    for (const session of DataSession.#holding) {
      const due = session.#since + STALL_MS;
      if (now >= due) session.#stalled();
      else DataSession.#due = Math.min(DataSession.#due, due);
    }
    DataSession.#watch();
  }

  // Builds and sends a frame that took `taken` bytes of window, returning what
  // it did not use.
  #send(scope, taken, build) {
    let frame;
    try {
      frame = build();
      if (frame.length > taken) throw new Error('frame exceeds its window');
    } catch (error) {
      this.#refund(taken);
      throw error;
    }
    this.#refund(taken - frame.length);
    if (this.#closed) refuse('Unavailable');
    if (Date.now() >= scope.deadline_ms) { this.#refund(frame.length); refuse('Expired'); }
    this.#socket.send(frame);
  }

  // Returns `size` to the window, unsent or by Credit, and as much of it as
  // this socket holds to the budget. Credit pays what the socket owes, and a
  // socket that has paid it all begins a new stall time; a frame returned
  // unsent pays only what the socket no longer holds.
  #refund(size, credited = false) {
    this.#window += size;
    const back = Math.min(size, this.#held);
    this.#held -= back;
    this.#owed = Math.min(credited ? this.#owed - back : this.#owed, this.#held);
    if (this.#owed <= 0) this.#owe();
    uncharge(back);
    this.#pump();
  }

  #credit(bytes) {
    if (this.#closed) return;
    if (this.#window + bytes > MAX_WINDOW) { this.#close(1008, 'credit limit'); return; }
    this.#refund(bytes, true);
  }

  // Releases waiting frames in order while they fit. A first waiter that has
  // its window but not the budget, or not yet its turn, waits for an uncharge.
  #pump() {
    while (this.#waiting.length && this.#room(this.#waiting[0].size)) {
      const waiter = this.#waiting[0];
      if (!take(waiter.size, waiter.small, this.#resume)) {
        if (block(this.#resume, waiter.small)) DataSession.#watch();
        return;
      }
      this.#waiting.shift();
      clearTimeout(waiter.timer);
      this.#hold(waiter.size);
      waiter.resolve();
    }
    unblock(this.#resume);
  }

  // Ends a subscription or join's lasting cost with its entry.
  #unstream(entries, log) {
    if (entries.delete(log)) release(STREAM_COST);
  }

  #refuse(id, reason) {
    if (this.#closed) return;
    try { this.#socket.send(encode.refused(id, reason)); } catch { this.#close(); }
  }

  #close(code = 1000, reason = '') {
    if (this.#closed) return;
    this.#closed = true;
    clearTimeout(this.#timer);
    this.#timer = null;
    // Everything the socket holds goes back to the budget once, here.
    unblock(this.#resume);
    const held = this.#held;
    let lasting = STREAM_COST * (this.#subscriptions.size + this.#presence.size);
    this.#held = 0;
    this.#owed = 0;
    DataSession.#holding.delete(this);
    if (this.#admitted) { this.#admitted = false; lasting += SOCKET_COST; }
    for (const subscription of this.#subscriptions.values()) subscription.stop();
    this.#subscriptions.clear();
    for (const join of this.#presence.values()) join.stop();
    this.#presence.clear();
    for (const waiter of this.#waiting.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(new Refused('Unavailable'));
    }
    try { this.#socket.close(code, reason); } catch { /* already closed */ }
    uncharge(held);
    for (const done of [...this.#requests]) done();
    if (lasting > 0) release(lasting);
  }
}

// A log object answers with its result or `{refused}`.
function outcome(result) {
  if (result?.refused) refuse(result.refused);
  return result;
}

// A socket costs the budget nothing until its first verified permit.
function data(env) {
  const keys = hostingKeys(env);
  if (!keys) return status(503);
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  new DataSession(server, env, keys);
  return new Response(null, { status: 101, webSocket: client });
}

// ---- /v1/pair --------------------------------------------------------------

const PAIR = /^\/v1\/pair\/([0-9a-f]{64})$/;
const RELAY_STATUS = { malformed: 400, conflict: 409, expired: 410, size: 413, limit: 429 };

// Reads at most `max` bytes of the request body; null if it is longer.
async function bounded(request, max) {
  if (Number(request.headers.get('Content-Length')) > max) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { out.set(chunk, at); at += chunk.length; }
  return out;
}

async function pair(request, env, name) {
  if (request.method !== 'GET' && request.method !== 'POST') return status(405);
  const query = new URL(request.url).searchParams;
  const side = query.get('side');
  const index = query.get('index') ?? '';
  if ((side !== 'show' && side !== 'join') || !/^[0-9]{1,2}$/.test(index)) return status(400);
  const relay = env.RELAY.get(env.RELAY.idFromName(name));
  let result;
  if (request.method === 'GET') {
    result = await relay.get(side, Number(index));
    if (result.message) return new Response(result.message, { headers: { 'Content-Type': 'application/octet-stream' } });
  } else {
    const message = await bounded(request, MAX_MESSAGE);
    if (message === null) return status(413);
    result = await relay.put(side, Number(index), message);
  }
  return status(RELAY_STATUS[result.error] ?? 204);
}

export default {
  async fetch(request, env) {
    try {
      const path = new URL(request.url).pathname;
      if (path === '/v1/authz' || path === '/v1/data') {
        if (request.method !== 'GET') return status(405);
        if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return status(426);
        return path === '/v1/authz' ? await authz(env) : data(env);
      }
      const pairing = PAIR.exec(path);
      if (pairing) return await pair(request, env, pairing[1]);
      return status(404);
    } catch (error) {
      failed('fetch', error);
      return status(500);
    }
  },
};
