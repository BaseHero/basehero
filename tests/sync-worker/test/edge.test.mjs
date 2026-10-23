import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../../crypto-worker/node_modules/miniflare/dist/src/index.js';
import { WebSocketServer } from '../../crypto-worker/node_modules/ws/wrapper.mjs';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
// Release packaging points production-entry tests at the emitted JS/Wasm
// closure, not the ignored development Wasm in this source tree.
const workerRoot = process.env.BH_RELEASE_WORKER ? resolve(process.env.BH_RELEASE_WORKER) : root;
// Native-only example: permits are issued against the real clock at test time.
// check.sh builds it in the native shell and names it, since the crypto-worker
// shell running these tests uses a different Cargo target directory.
const example = process.env.BH_EDGE_EXAMPLE
  ? resolve(process.env.BH_EDGE_EXAMPLE)
  : resolve(process.env.CARGO_TARGET_DIR ?? resolve(root, 'target'), 'debug/examples/edge');
const fixtures = (now = Date.now()) =>
  JSON.parse(execFileSync(example, ['fixtures', String(now)], { maxBuffer: 16 << 20 }));
// Every permit in this set expires `ms` after the call.
const WINDOW = 30_000;
const expiring = ms => fixtures(Date.now() - WINDOW + ms);
const keys = fixtures();
const decode = (...frames) =>
  JSON.parse(execFileSync(example, ['frames', keys.root, keys.base.slice(2), ...frames], { maxBuffer: 64 << 20 }));

const hex = bytes => Buffer.from(bytes).toString('hex');
const unhex = value => new Uint8Array(Buffer.from(value, 'hex'));
const sleep = ms => new Promise(done => setTimeout(done, ms));

function config(bindings = {}) {
  return {
    // Keep Request.cf fixture data local; never fetch Cloudflare metadata.
    cf: false,
    rootPath: workerRoot, modulesRoot: workerRoot, modules: true,
    scriptPath: resolve(workerRoot, 'services/sync-worker/src/edge.mjs'),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2026-07-01',
    durableObjects: {
      LOG: { className: 'LogObject', useSQLite: true },
      RELAY: { className: 'PairingRelay', useSQLite: true },
    },
    r2Buckets: ['BODIES'],
    bindings: {
      HOSTING_ROOT: keys.root, RECEIPT_KEY: keys.receipt_key, RECEIPT_CERT: keys.receipt_cert,
      AUTHZ_BACKENDS: '[]', ...bindings,
    },
  };
}
async function withEdge(run, bindings) {
  const mf = new Miniflare(config(bindings));
  try { await run(mf); } finally { await mf.dispose(); }
}

// Client-side data-wire request: version 3, tag, id, permit, then the body or
// event blob (Stage/Append) or `after` (Subscribe).
const TAGS = { read: 1, stage: 2, append: 3, subscribe: 4, storeHome: 6,
  readDirectory: 37, storeDirectory: 38, retireHome: 39 };
function request(kind, id, permit, extra) {
  const blob = value => { const b = unhex(value); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return [n, b]; };
  const head = Buffer.alloc(7);
  head.writeUInt16BE(3); head[2] = TAGS[kind]; head.writeUInt32BE(id, 3);
  const parts = [head, ...blob(permit)];
  if (kind === 'stage' || kind === 'append' || kind === 'storeHome' || kind === 'storeDirectory') parts.push(...blob(extra));
  if (kind === 'readDirectory') parts.push(Uint8Array.of(extra ? 1 : 0), ...(extra ? [unhex(extra)] : []));
  if (kind === 'subscribe') { const after = Buffer.alloc(8); after.writeBigUInt64BE(BigInt(extra ?? 0)); parts.push(after); }
  return new Uint8Array(Buffer.concat(parts));
}
function publish(id, stagePermit, appendPermit, event, body) {
  const head = Buffer.alloc(7); head.writeUInt16BE(3); head[2] = 32; head.writeUInt32BE(id, 3);
  const blob = value => { const b = Buffer.from(value, 'hex'); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return [n, b]; };
  return new Uint8Array(Buffer.concat([head, ...blob(stagePermit), ...blob(appendPermit), ...blob(event), ...blob(body)]));
}
// A Credit grant: tag 5, request id 0, `bytes:u32`.
function credit(bytes, id = 0) {
  const out = Buffer.alloc(11);
  out.writeUInt16BE(3); out[2] = 5; out.writeUInt32BE(id, 3); out.writeUInt32BE(bytes, 7);
  return new Uint8Array(out);
}
const MAX_FRAME = 4 * 1024 * 1024 + 64 * 1024;
const INITIAL_WINDOW = MAX_FRAME + 4 * 1024 * 1024;
const MAX_WINDOW = 64 * 1024 * 1024;

async function socket(mf, path) {
  const response = await mf.dispatchFetch(`http://edge.invalid${path}`, { headers: { Upgrade: 'websocket' } });
  if (response.status !== 101) return { status: response.status };
  const ws = response.webSocket;
  const inbox = [];
  let closed = null;
  let wake = () => {};
  ws.addEventListener('message', event => { inbox.push(typeof event.data === 'string' ? event.data : hex(event.data)); wake(); });
  ws.addEventListener('close', event => { closed = { code: event.code, reason: event.reason }; wake(); });
  ws.accept();
  const until = async (ready, ms) => {
    const end = Date.now() + ms;
    while (!ready()) {
      if (Date.now() > end) throw new Error('timed out waiting for the socket');
      await new Promise(done => { wake = done; setTimeout(done, 50); });
    }
  };
  return {
    status: 101,
    ws,
    inbox,
    send: bytes => ws.send(bytes),
    async next(count = 1, ms = 5000) { await until(() => inbox.length >= count || closed, ms); return inbox.splice(0, count); },
    async closed(ms = 5000) { await until(() => closed, ms); return closed; },
    get isClosed() { return closed; },
  };
}
// Send one request and decode the next `count` response frames natively.
async function ask(data, frame, count = 1) {
  data.send(frame);
  const frames = await data.next(count);
  assert.equal(frames.length, count, 'expected response frames');
  return decode(...frames);
}
const acked = (id, log, eventId, head, receipt) => ({ type: 'acked', id, log, event_id: eventId, head, receipt });
async function genesis(data, fx) {
  assert.deepEqual(await ask(data, request('append', 1, fx.append_genesis, fx.genesis)),
    [acked(1, fx.base, fx.genesis_id, fx.genesis_head, 'verified')]);
}
async function content(data, fx) {
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b1, fx.b1)), [{ type: 'staged', id: 2 }]);
  assert.deepEqual(await ask(data, request('append', 3, fx.append_c1, fx.c1)),
    [acked(3, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
}

test('unknown_route_404', () => withEdge(async mf => {
  for (const [method, path] of [['GET', '/'], ['GET', '/v1'], ['GET', '/v1/data/x'], ['POST', '/v1/unknown'],
    ['GET', '/subscribe'], ['GET', `/v1/pair/${'a'.repeat(63)}`], ['GET', `/v1/pair/${'A'.repeat(64)}`],
    ['GET', `/v1/pair/${'a'.repeat(64)}/x`], ['GET', '/v1/authz/x']]) {
    const response = await mf.dispatchFetch(`http://edge.invalid${path}`, { method });
    assert.equal(response.status, 404, `${method} ${path}`);
  }
  for (const path of ['/v1/data', '/v1/authz'])
    assert.equal((await mf.dispatchFetch(`http://edge.invalid${path}`)).status, 426, path);
}));

test('private_home_objects_ack_retry_and_no_public_reads', () => withEdge(async mf => {
  const fx = fixtures();
  let data = await socket(mf, '/v1/data');
  const expected = id => [{ type: 'home_objects_stored', id, prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest }];
  assert.deepEqual(await ask(data, request('storeHome', 10, fx.home_store, fx.home_bundle)), expected(10));
  data.ws.close();
  data = await socket(mf, '/v1/data');
  assert.deepEqual(await ask(data, request('storeHome', 11, fixtures().home_store, fx.home_bundle)), expected(11));
  assert.deepEqual(await ask(data, request('storeHome', 12, fx.home_store_conflict, fx.home_conflict)),
    [{ type: 'refused', id: 12, reason: 'Conflict' }]);
  assert.deepEqual(await ask(data, request('read', 13, fx.home_read_events)),
    [{ type: 'events', id: 13, items: [], head: null, receipt: null }]);
  assert.deepEqual(await ask(data, request('read', 14, fx.home_read_controls)),
    [{ type: 'refused', id: 14, reason: 'Unavailable' }]);
  assert.deepEqual(await ask(data, request('read', 15, fx.home_read_body)), [{ type: 'refused', id: 15, reason: 'Missing' }]);
  for (const path of [`/v1/home/${fx.home_prefix}`, `/b/${fx.account}/${fx.home_digest}`])
    assert.equal((await mf.dispatchFetch(`http://edge.invalid${path}`)).status, 404);
}));

test('directory_frames_routed_with_deadline_checked_per_frame', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  assert.deepEqual(await ask(data, request('storeHome', 1, fx.home_store, fx.home_bundle)),
    [{ type: 'home_objects_stored', id: 1, prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest }]);
  assert.deepEqual(await ask(data, request('storeDirectory', 2, fx.directory_store, fx.directory_body)),
    [{ type: 'directory_entry_stored', id: 2 }]);
  assert.deepEqual(await ask(data, request('readDirectory', 3, fx.directory_read)),
    [{ type: 'directory', id: 3, entries: [fx.directory_body], more: false }]);
  assert.deepEqual(await ask(data, request('retireHome', 4, fx.directory_retire)),
    [{ type: 'home_objects_retired', id: 4 }]);
  await control.log(fx.account, { readDirectory: 2_500 });
  assert.deepEqual(await ask(data, request('readDirectory', 5, expiring(2_000).directory_read)),
    [{ type: 'refused', id: 5, reason: 'Expired' }]);
  await control.log(fx.account, {});
  assert.deepEqual(await ask(data, request('readDirectory', 6, fixtures().directory_read)),
    [{ type: 'directory', id: 6, entries: [fx.directory_body], more: false }]);
}));

test('ack_receipt_verifies', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await content(data, fx);
  // An exact retry under a fresh permit returns the original Ack.
  assert.deepEqual(await ask(data, request('append', 9, fixtures().append_c1, fx.c1)),
    [acked(9, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
  // An account-home log is served by the same object class, with no receipt.
  assert.deepEqual(await ask(data, request('append', 4, fx.append_account_genesis, fx.account_genesis)),
    [acked(4, fx.account, fx.account_genesis_id, fx.account_head, null)]);
}));

test('compound publication returns one proof-carrying frame; exact retry preserves stored commitment', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const requestBytes = publish(90, fx.stage_b1, fx.append_c1, fx.c1, fx.b1);
  const answer = await ask(data, requestBytes);
  assert.deepEqual(answer, [{ type: 'published', id: 90, log: fx.base,
    event_id: fx.c1_id, head: fx.c1_head, receipt: 'verified',
    commitment: fx.c1_commitment, proof_head: fx.c1_head }]);
  assert.deepEqual(await ask(data, publish(91, fx.stage_b1, fixtures().append_c1, fx.c1, fx.b1)),
    [{ ...answer[0], id: 91 }]);
  assert.deepEqual((await ask(data, request('read', 92, fx.read_1_2)))[0].items.map(i => i.commitment),
    [fx.genesis_commitment, fx.c1_commitment]);
}));

test('historical read carries its returned tail receipt, not the current head', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await content(data, fx);
  // The sparse page has only genesis, but authenticates the content endpoint.
  data.send(request('read', 70, fx.read_controls_0));
  const [frame] = await data.next();
  const raw = unhex(frame);
  assert.equal(raw[9], 0, 'sparse Events do not carry a last-item receipt');
  assert.equal(raw[10], 2, 'nonempty sparse endpoint carries opening and receipt');
  const [events] = decode(frame);
  assert.equal(events.receipt, null);
  assert.deepEqual(events.head, fx.genesis_head);
  assert.deepEqual(events.coverage, { order: fx.c1_order, head: fx.c1_head, receipt: 'verified' });
}));

test('data_rejects_bad_permit', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const refused = (id, reason) => [{ type: 'refused', id, reason }];
  assert.deepEqual(await ask(data, request('read', 5, fx.read_other_root)), refused(5, 'Scope'));
  assert.deepEqual(await ask(data, request('read', 6, fx.read_expired)), refused(6, 'Expired'));
  const forged = fx.read_1_2.slice(0, -2) + (fx.read_1_2.endsWith('00') ? '01' : '00');
  assert.deepEqual(await ask(data, request('read', 7, forged)), refused(7, 'Scope'));
  // A valid permit for another kind of request.
  assert.deepEqual(await ask(data, request('read', 8, fx.subscribe)), refused(8, 'Scope'));
  assert.deepEqual(await ask(data, request('subscribe', 9, fx.read_1_2, 0)), refused(9, 'Scope'));
  assert.deepEqual(await ask(data, request('read', 10, fx.stage_b1)), refused(10, 'Scope'));
  // Each permit is valid for its own bytes, but sent as the other request kind.
  assert.deepEqual(await ask(data, request('stage', 11, fx.append_c1, fx.c1)), refused(11, 'Scope'));
  assert.deepEqual(await ask(data, request('append', 12, fx.stage_b1, fx.b1)), refused(12, 'Scope'));
  // A stage permit binds the exact body bytes; nothing was staged or ordered.
  assert.deepEqual(await ask(data, request('stage', 13, fx.stage_b1, fx.b2)), refused(13, 'Scope'));
  assert.deepEqual(await ask(data, request('append', 14, fx.append_c1, fx.c1)), refused(14, 'NotStaged'));
  const [events] = await ask(data, request('read', 15, fx.read_1_64));
  assert.deepEqual(events.items.map(item => item.commitment), [fx.genesis_commitment]);
}));

test('read_range_bounds', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await content(data, fx);
  assert.deepEqual(await ask(data, request('read', 20, fx.read_1_65)), [{ type: 'refused', id: 20, reason: 'Malformed' }]);
  assert.deepEqual(await ask(data, request('read', 21, fx.read_1_2)), [{ type: 'events', id: 21, head: fx.c1_head, receipt: 'verified', items: [
    { commitment: fx.genesis_commitment, event: fx.genesis },
    { commitment: fx.c1_commitment, event: fx.c1 },
  ] }]);
  assert.equal((await ask(data, request('read', 22, fx.read_1_64)))[0].items.length, 2);
}));

test('read_controls_permit_routed', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  const events = (id, items, order = fx.control_order, head = fx.control_head) => [{ type: 'events', id, items,
    head: items.length ? (items.at(-1).commitment === fx.genesis_commitment ? fx.genesis_head : fx.control_head) : null,
    receipt: null, coverage: { order, head, receipt: head.position ? 'verified' : null } }];
  assert.deepEqual(await ask(data, request('read', 20, fx.read_controls_0)),
    events(20, [], '0002' + '00'.repeat(80), { position: 0, hash: '00'.repeat(32) }));
  await genesis(data, fx);
  await content(data, fx);
  assert.deepEqual(await ask(data, request('append', 4, fx.append_control, fx.control)),
    [acked(4, fx.base, fx.control_id, fx.control_head, 'verified')]);
  const genesisItem = { commitment: fx.genesis_commitment, event: fx.genesis };
  const controlItem = { commitment: fx.control_commitment, event: fx.control };
  // Only control-route events, after the permit's position; never c1.
  assert.deepEqual(await ask(data, request('read', 21, fx.read_controls_0)), events(21, [genesisItem, controlItem]));
  assert.deepEqual(await ask(data, request('read', 22, fx.read_controls_1)), events(22, [controlItem]));
  // A control ordered after issuance is withheld by the signed upper bound.
  assert.deepEqual(await ask(data, request('read', 24, fx.read_control_range_1)),
    events(24, [genesisItem], fx.genesis_order, fx.genesis_head));
  assert.deepEqual(await ask(data, request('read', 25, fx.read_control_range_3)), events(25, [genesisItem, controlItem]));
  // Account-home reads are contiguous, not base sparse authority scans.
  assert.deepEqual(await ask(data, request('read', 26, fx.read_account_control_range)),
    [{ type: 'refused', id: 26, reason: 'Missing' }]);
  await ask(data, request('append', 27, fx.append_account_genesis, fx.account_genesis));
  assert.deepEqual(await ask(data, request('read', 28, fx.read_account_control_range)),
    [{ type: 'refused', id: 28, reason: 'Missing' }]);
  // A controls permit is a read permit only.
  assert.deepEqual(await ask(data, request('subscribe', 23, fx.read_controls_0, 0)),
    [{ type: 'refused', id: 23, reason: 'Scope' }]);
}));

test('read bodies serves only ordered bodies, one frame each, in permit order', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  // Nothing ordered yet: a staged body is never served.
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b1, fx.b1)), [{ type: 'staged', id: 2 }]);
  assert.deepEqual(await ask(data, request('read', 30, fx.read_bodies_b1)), [{ type: 'refused', id: 30, reason: 'Missing' }]);
  assert.deepEqual(await ask(data, request('append', 3, fx.append_c1, fx.c1)),
    [acked(3, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
  assert.deepEqual(await ask(data, request('read', 31, fx.read_bodies_b1)),
    [{ type: 'body', id: 31, index: 0, last: true, bytes: fx.b1 }]);
  // b2 is staged but not ordered: b1 is served, then the stream ends Missing.
  assert.deepEqual(await ask(data, request('stage', 4, fx.stage_b2, fx.b2)), [{ type: 'staged', id: 4 }]);
  assert.deepEqual(await ask(data, request('read', 32, fx.read_bodies_b1_b2), 2), [
    { type: 'body', id: 32, index: 0, last: false, bytes: fx.b1 },
    { type: 'refused', id: 32, reason: 'Missing' },
  ]);
}));

// Only the service can obtain a read permit for an account body that is not
// ordered; it reads a rotation's staged body back before permitting it.
test('read bodies serves an account log its staged body', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await ask(data, request('append', 1, fx.append_account_genesis, fx.account_genesis));
  assert.deepEqual(await ask(data, request('read', 2, fx.read_bodies_account_b1)), [{ type: 'refused', id: 2, reason: 'Missing' }]);
  assert.deepEqual(await ask(data, request('stage', 3, fx.stage_account_b1, fx.b1)), [{ type: 'staged', id: 3 }]);
  assert.deepEqual(await ask(data, request('read', 4, fx.read_bodies_account_b1)),
    [{ type: 'body', id: 4, index: 0, last: true, bytes: fx.b1 }]);
}));

test('one MiB body stages, appends and reads over /v1/data', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b4, fx.b4)), [{ type: 'staged', id: 2 }]);
  const [ack] = await ask(data, request('append', 3, fx.append_c4, fx.c4));
  assert.equal(ack.type, 'acked');
  assert.equal(ack.event_id, fx.c4_id);
  assert.equal(ack.receipt, 'verified');
  // Parse the large frame locally: native example argv cannot carry a MiB body.
  data.send(request('read', 4, fx.read_bodies_b4));
  const [frame] = await data.next();
  assert.equal(frame.slice(0, 26), '00030200000004000100100000');
  assert.equal(frame.slice(26), fx.b4);
}));

test('subscriptions send heads after the cursor, with receipts for base logs', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const watch = await socket(mf, '/v1/data');
  // The current head (position 1) is not after the cursor, so nothing is sent
  // until c1 is ordered.
  watch.send(request('subscribe', 40, fx.subscribe, 1));
  await sleep(300);
  assert.deepEqual(watch.inbox, []);
  await content(data, fx);
  assert.deepEqual(decode(...await watch.next()), [{ type: 'head', id: 40, head: fx.c1_head, receipt: 'verified' }]);
  watch.send(request('subscribe', 41, fx.subscribe_account, 0));
  await sleep(300);
  assert.deepEqual(watch.inbox, []);
  assert.deepEqual(await ask(data, request('append', 4, fx.append_account_genesis, fx.account_genesis)),
    [acked(4, fx.account, fx.account_genesis_id, fx.account_head, null)]);
  assert.deepEqual(decode(...await watch.next()), [{ type: 'head', id: 41, head: fx.account_head, receipt: null }]);
}));

test('the subscription cap holds for subscribes that arrive together', () => withEdge(async mf => {
  const fx = fixtures();
  const watch = await socket(mf, '/v1/data');
  // Empty logs send nothing after cursor 0, so only refusals are visible.
  for (let batch = 0; batch < 60; batch += 6) {
    for (let i = batch; i < batch + 6; i++) watch.send(request('subscribe', i, fx.subscribe_many[i], 0));
    await sleep(300);
  }
  assert.deepEqual(watch.inbox, []);
  // Eight at once, all checked against 60 before any upgrade completes.
  for (let i = 60; i < 68; i++) watch.send(request('subscribe', i, fx.subscribe_many[i], 0));
  const refused = decode(...await watch.next(4));
  await sleep(500);
  assert.deepEqual(watch.inbox, [], 'exactly four refused');
  assert.deepEqual(refused.map(r => [r.type, r.reason]), Array(4).fill(['refused', 'Unavailable']));
}));

test('stream_stops_at_deadline', () => withEdge(async mf => {
  const deadline = Date.now() + 3_000;
  const fx = fixtures(); // subscribe_short expires three seconds after this call
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const watch = await socket(mf, '/v1/data');
  watch.send(request('subscribe', 50, fx.subscribe_short, 0));
  assert.deepEqual(decode(...await watch.next()), [{ type: 'head', id: 50, head: fx.genesis_head, receipt: 'verified' }]);
  // A concurrent subscription on the same socket, with a full window.
  watch.send(request('subscribe', 51, fx.subscribe_account, 0));
  // Only the expired subscription ends; the socket stays open.
  assert.deepEqual(decode(...await watch.next(1, 6_000)), [{ type: 'refused', id: 50, reason: 'Expired' }]);
  assert.ok(Date.now() >= deadline, 'refused no earlier than the deadline');
  assert.equal(watch.isClosed, null);
  // c1 is ordered but the ended subscription sends nothing; the other one
  // still gets its log's head.
  await content(data, fx);
  assert.deepEqual(await ask(data, request('append', 4, fx.append_account_genesis, fx.account_genesis)),
    [acked(4, fx.account, fx.account_genesis_id, fx.account_head, null)]);
  assert.deepEqual(decode(...await watch.next()), [{ type: 'head', id: 51, head: fx.account_head, receipt: null }]);
  // A request on the same socket still succeeds.
  const [events] = await ask(watch, request('read', 52, fixtures().read_1_2));
  assert.deepEqual([events.type, events.items.length], ['events', 2]);
  await sleep(200);
  assert.deepEqual(watch.inbox, []);
  assert.equal(watch.isClosed, null);
}));

test('a newer Subscribe for the same log renews the subscription before its deadline', () => withEdge(async mf => {
  const fx = fixtures();
  const deadline = Date.now() + 3_000;
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const watch = await socket(mf, '/v1/data');
  watch.send(request('subscribe', 60, fx.subscribe_short, 1));
  await sleep(300);
  watch.send(request('subscribe', 61, fx.subscribe, 1));
  await sleep(Math.max(0, deadline - Date.now()) + 500);
  assert.equal(watch.isClosed, null, 'the replaced deadline no longer applies');
  await content(data, fx);
  assert.deepEqual(decode(...await watch.next()), [{ type: 'head', id: 61, head: fx.c1_head, receipt: 'verified' }]);
  await sleep(200);
  assert.deepEqual(watch.inbox, [], 'only the renewed subscription sends');
}));

test('data socket closes on frames it cannot decode', () => withEdge(async mf => {
  const text = await socket(mf, '/v1/data');
  text.send('hello');
  assert.equal((await text.closed()).code, 1003);
  const garbage = await socket(mf, '/v1/data');
  garbage.send(new Uint8Array([0, 1, 9, 0, 0, 0, 1]));
  assert.equal((await garbage.closed()).code, 1002);
  // A Credit grant must be positive and carry request id 0.
  for (const frame of [credit(0), credit(1, 7), new Uint8Array([...credit(1), 0])]) {
    const bad = await socket(mf, '/v1/data');
    bad.send(frame);
    assert.equal((await bad.closed()).code, 1002);
  }
}));

test('granting more than 64 MiB of unused window closes the socket with 1008', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  // Up to the bound is allowed, and the socket keeps serving.
  data.send(credit(MAX_WINDOW - INITIAL_WINDOW));
  assert.equal((await ask(data, request('read', 2, fx.read_1_2)))[0].type, 'events');
  // The Events frame used some window; the grant now goes past the bound.
  data.send(credit(1 << 20));
  assert.equal((await data.closed()).code, 1008);
}));

// Opens a data socket and gets one verified permit answered on it: the socket
// is then admitted and holds its share of the isolate's memory budget.
async function admitted(mf, fx, id = 1) {
  const data = await socket(mf, '/v1/data');
  const [events] = await ask(data, request('read', id, fx.read_1_2));
  assert.equal(events.type, 'events');
  return data;
}

test('a socket count is not a limit: many idle lanes, presence joins and authz sessions share one isolate', async () => {
  const a = await backend();
  try {
    await withEdge(async mf => {
      const fx = fixtures();
      const data = await socket(mf, '/v1/data');
      await genesis(data, fx);
      // Receive lanes, each holding a subscription as a device's does.
      const lanes = [];
      for (let i = 0; i < 24; i++) {
        const lane = await socket(mf, '/v1/data');
        lane.send(request('subscribe', 1, fx.subscribe, 1));
        assert.deepEqual((await ask(lane, request('read', 2, fx.read_1_2))).map(f => f.type), ['events'], `lane ${i}`);
        lanes.push(lane);
      }
      for (let i = 0; i < 12; i++) await joined(mf, fx.presence, 10 + i);
      const sessions = await Promise.all(Array.from({ length: 24 }, () => socket(mf, '/v1/authz')));
      assert.deepEqual(sessions.map(s => s.status), Array(24).fill(101));
      // Every lane's subscription is live.
      await content(data, fx);
      for (const lane of lanes)
        assert.deepEqual(decode(...await lane.next()), [{ type: 'head', id: 1, head: fx.c1_head, receipt: 'verified' }]);
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: a.url, ready: true }]) });
  } finally { await a.close(); }
});

test('a socket with no verified permit closes after 5 s; credit does not extend it', () => withEdge(async mf => {
  const opened = Date.now();
  const crediting = await socket(mf, '/v1/data');
  const silent = await socket(mf, '/v1/data');
  const timer = setInterval(() => { if (!crediting.isClosed) crediting.send(credit(1024)); }, 500);
  try {
    for (const s of [crediting, silent]) {
      const closed = await s.closed(8_000);
      assert.deepEqual([closed.code, closed.reason], [1008, 'no permit']);
    }
    const waited = Date.now() - opened;
    assert.ok(waited >= 4_900 && waited < 7_000, `${waited} ms`);
  } finally { clearInterval(timer); }
}));

test('a socket not yet admitted closes at its first refused request, and verifies nothing after it', () => withEdge(async mf => {
  const fx = fixtures();
  // Sent together: the refusal closes the socket, and the valid permit behind
  // it is not served.
  const both = await socket(mf, '/v1/data');
  both.send(request('read', 10, '00'.repeat(200)));
  both.send(request('read', 11, fx.read_1_2));
  assert.deepEqual(decode(...await both.next()), [{ type: 'refused', id: 10, reason: 'Malformed' }]);
  assert.deepEqual(Object.values(await both.closed(1_000)), [1008, 'refused']);
  await sleep(200);
  assert.deepEqual(both.inbox, []);
  const forged = await socket(mf, '/v1/data');
  assert.deepEqual(await ask(forged, request('read', 9, '00'.repeat(200))), [{ type: 'refused', id: 9, reason: 'Malformed' }]);
  assert.deepEqual(Object.values(await forged.closed(1_000)), [1008, 'refused']);
  // A burst led by a valid permit is all served on one socket.
  const burst = await socket(mf, '/v1/data');
  for (let id = 20; id < 28; id++) burst.send(request('read', id, fx.read_1_2));
  const answers = decode(...await burst.next(8));
  assert.deepEqual(answers.map(a => [a.type, a.id]).sort(), Array.from({ length: 8 }, (_, i) => ['events', 20 + i]));
  // Once admitted, a refusal ends only its request.
  assert.deepEqual(await ask(burst, request('read', 30, '00'.repeat(200))), [{ type: 'refused', id: 30, reason: 'Malformed' }]);
  assert.equal((await ask(burst, request('read', 31, fx.read_1_2)))[0].type, 'events');
  assert.equal(burst.isClosed, null);
  // The closed sockets took no budget: more are admitted.
  for (let i = 0; i < 7; i++) await admitted(mf, fx, 40 + i);
}));

test('only a request whose permit verifies keeps an admitted socket from idling', () => withEdge(async mf => {
  const fx = fixtures();
  const refused = await admitted(mf, fx);
  const admittedAt = Date.now();
  const served = await admitted(mf, fx, 2);
  // Refused requests at 3, 6 and 9 s do not move the idle timer; a served one at 6 s does.
  for (const at of [3_000, 6_000, 9_000]) {
    await sleep(admittedAt + at - Date.now());
    assert.deepEqual(await ask(refused, request('read', at, '00'.repeat(200))), [{ type: 'refused', id: at, reason: 'Malformed' }]);
    if (at === 6_000) assert.equal((await ask(served, request('read', 3, fx.read_1_2)))[0].type, 'events');
  }
  const closed = await refused.closed(3_000);
  assert.deepEqual([closed.code, closed.reason], [1000, 'idle']);
  const waited = Date.now() - admittedAt;
  assert.ok(waited >= 9_900 && waited < 11_500, `${waited} ms`);
  await sleep(admittedAt + 12_000 - Date.now());
  assert.equal(served.isClosed, null, 'served at 6 s, so not idle until 16 s');
}));

test('an admitted socket closes after 10 s with nothing in flight; a subscription keeps it', () => withEdge(async mf => {
  const fx = fixtures();
  const opened = Date.now();
  const reader = await admitted(mf, fx);
  const crediting = await admitted(mf, fx, 2);
  const timer = setInterval(() => { if (!crediting.isClosed) crediting.send(credit(1024)); }, 500);
  const watch = await socket(mf, '/v1/data');
  watch.send(request('subscribe', 40, fx.subscribe, 0));
  try {
    for (const s of [reader, crediting]) {
      const closed = await s.closed(13_000);
      assert.deepEqual([closed.code, closed.reason], [1000, 'idle']);
    }
    const waited = Date.now() - opened;
    assert.ok(waited >= 9_900 && waited < 12_000, `${waited} ms`);
    assert.equal(watch.isClosed, null, 'subscribed');
  } finally { clearInterval(timer); }
  // More sockets are admitted once the idle sockets have closed.
  const fill = [];
  for (let i = 0; i < 7; i++) fill.push(await admitted(mf, fx, 50 + i));
  watch.ws.close();
}));

// The edge behind a log object that answers late and R2 reads that can be held.
async function withSlowEdge(run, bindings, options = {}) {
  const mf = new Miniflare({
    ...config(bindings),
    ...options,
    scriptPath: resolve(root, 'tests/sync-worker/edge-fixture.mjs'),
    durableObjects: {
      LOG: { className: 'SlowLog', useSQLite: true },
      RELAY: { className: 'PairingRelay', useSQLite: true },
    },
  });
  const post = (path, body) => mf.dispatchFetch(`http://edge.invalid${path}`, { method: 'POST', body: JSON.stringify(body) })
    .then(r => r.json());
  const control = {
    log: (log, holds) => post(`/control/log?log=${log}`, holds),
    edge: settings => post('/control/edge', settings),
    budget: (settings = {}) => post('/control/budget', settings),
  };
  try { await run(mf, control); } finally { await mf.dispose(); }
}
const frameHeader = frame => ({ tag: parseInt(frame.slice(4, 6), 16), id: parseInt(frame.slice(6, 14), 16) });

test('one MiB compound publication needs one request and one reply without descriptor read', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const before = await control.log(fx.base, { action: 'calls' });
  const [answer] = await ask(data, publish(140, fx.stage_b4, fx.append_c4, fx.c4, fx.b4));
  assert.equal(answer.type, 'published');
  assert.equal(answer.proof_head.position, 2);
  const after = await control.log(fx.base, { action: 'calls' });
  assert.deepEqual([after.stage - before.stage, after.append - before.append, after.read - before.read],
    [1, 1, 0]);
  assert.equal((await control.edge({})).gets, 0, 'no edge R2 read for the proof');
}));

test('compound mismatched, expired, forged and control permits never reach storage hooks', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const original = await control.log(fx.base, { action: 'calls' });
  const forged = fx.stage_b1.slice(0, -2) + (fx.stage_b1.endsWith('00') ? '01' : '00');
  const cases = [
    [fx.stage_b2, fx.append_c1, fx.c1, fx.b2],
    [fx.stage_b1, fx.append_c2, fx.c2, fx.b1],
    [fx.stage_b1, fx.append_control, fx.control, fx.b1],
    [fx.append_c1, fx.stage_b1, fx.c1, fx.b1],
    [forged, fx.append_c1, fx.c1, fx.b1],
    [expiring(0).stage_b1, fx.append_c1, fx.c1, fx.b1],
    [fx.stage_b1, fx.append_account_genesis, fx.account_genesis, fx.b1],
    [fx.stage_b1, fx.append_c1, fx.c1, fx.b2],
  ];
  for (let i = 0; i < cases.length; i++) {
    const [stage, append, event, body] = cases[i];
    const [answer] = await ask(data, publish(150 + i, stage, append, event, body));
    assert.equal(answer.type, 'refused', `case ${i}`);
  }
  assert.deepEqual(await control.log(fx.base, { action: 'calls' }), original);
  assert.deepEqual(await ask(data, request('append', 180, fx.append_c1, fx.c1)),
    [{ type: 'refused', id: 180, reason: 'NotStaged' }]);
}));

test('compound waits for R2 put before append and sends no intermediate frame', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await control.log(fx.base, { holdPut: true });
  data.send(publish(190, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
  const calls = await control.log(fx.base, { action: 'waitForPut' });
  assert.equal(calls.stage, 1);
  assert.equal(calls.append, 1, 'genesis only, while body put is pending');
  assert.deepEqual(data.inbox, [], 'no premature Published or Staged');
  await control.log(fx.base, { action: 'releasePut' });
  const [answer] = decode(...await data.next());
  assert.equal(answer.type, 'published');
  assert.equal(answer.commitment, fx.c1_commitment);
}));

test('compound append rechecks epoch after R2 HEAD while a removal closes it', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await control.log(fx.base, { holdHead: true });
  data.send(publish(198, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
  await control.log(fx.base, { action: 'waitForHead' });
  const [removal] = await ask(data, request('append', 199, fx.append_removal, fx.control));
  assert.deepEqual([removal.type, removal.event_id, removal.head.position, removal.receipt],
    ['acked', fx.control_id, 2, 'verified']);
  await control.log(fx.base, { action: 'releaseHead' });
  assert.deepEqual(decode(...await data.next()), [{ type: 'refused', id: 198, reason: 'Epoch' }]);
  const [read] = await ask(data, request('read', 200, fx.read_1_64));
  assert.equal(read.items.length, 2);
  assert.deepEqual(read.head, removal.head);
}));

test('compound expiry during R2 await never appends; another account continues', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await control.log(fx.base, { holdPut: true });
  data.send(publish(192, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
  await control.log(fx.base, { action: 'waitForPut' });
  const other = await socket(mf, '/v1/data');
  assert.equal((await ask(other, request('read', 193, fx.home_read_events)))[0].type, 'events');
  await control.edge({ ahead: WINDOW + 1_000 });
  await control.log(fx.base, { action: 'releasePut' });
  assert.deepEqual(decode(...await data.next()), [{ type: 'refused', id: 192, reason: 'Expired' }]);
  assert.equal((await control.log(fx.base, { action: 'calls' })).append, 1);
  await control.edge({ ahead: 0 });
  const [retry] = await ask(data, publish(194, fixtures().stage_b1, fixtures().append_c1, fx.c1, fx.b1));
  assert.equal(retry.commitment, fx.c1_commitment);
}));

test('compound append failure after durable stage retries at original position with stored proof', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await control.log(fx.base, { holdStage: true });
  data.send(publish(195, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
  assert.equal((await control.log(fx.base, { action: 'waitForStage' })).append, 1);
  await control.log(fx.base, { failSync: true });
  await control.log(fx.base, { action: 'releaseStage' });
  assert.deepEqual(decode(...await data.next()), [{ type: 'refused', id: 195, reason: 'Unavailable' }]);
  await control.log(fx.base, {});
  const [retry] = await ask(data, publish(196, fixtures().stage_b1, fixtures().append_c1, fx.c1, fx.b1));
  assert.equal(retry.type, 'published');
  assert.deepEqual([retry.head, retry.commitment, retry.proof_head], [fx.c1_head, fx.c1_commitment, fx.c1_head]);
  assert.deepEqual((await ask(data, request('read', 197, fx.read_1_2)))[0].items.map(i => i.commitment),
    [fx.genesis_commitment, fx.c1_commitment]);
}));

test('sync failure cannot release a signed read of an unconfirmed append', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await ask(data, request('stage', 2, fx.stage_b1, fx.b1));
  await control.log(fx.base, { failSync: true });
  assert.deepEqual(await ask(data, request('append', 3, fx.append_c1, fx.c1)),
    [{ type: 'refused', id: 3, reason: 'Unavailable' }]);
  for (const [id, permit] of [[4, fx.read_1_2], [5, fx.read_controls_0]]) {
    assert.deepEqual(await ask(data, request('read', id, permit)),
      [{ type: 'refused', id, reason: 'Unavailable' }], 'no signed Events before durable read');
  }
  await control.log(fx.base, {});
  const [read] = await ask(data, request('read', 6, fx.read_1_2));
  assert.equal(read.receipt, 'verified');
  assert.deepEqual(read.head, fx.c1_head);
  assert.equal(read.items[1].commitment, fx.c1_commitment);
  const [controls] = await ask(data, request('read', 7, fx.read_controls_0));
  assert.equal(controls.receipt, null);
  assert.deepEqual(controls.head, fx.genesis_head);
  assert.deepEqual(controls.coverage, { order: fx.c1_order, head: fx.c1_head, receipt: 'verified' });
  // Retry never allocates a new position.
  assert.deepEqual(await ask(data, request('append', 8, fx.append_c1, fx.c1)),
    [acked(8, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
}));

test('private object ack waits for its own deadline and is charged to Credit', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await control.log(fx.account, { storeHomeObjects: 2_500 });
  const short = expiring(2_000);
  assert.deepEqual(await ask(data, request('storeHome', 71, short.home_store, fx.home_bundle)),
    [{ type: 'refused', id: 71, reason: 'Expired' }]);
  assert.equal(data.isClosed, null);
  await control.log(fx.account, {});
  const expected = [{ type: 'home_objects_stored', id: 72, prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest }];
  assert.deepEqual(await ask(data, request('storeHome', 72, fixtures().home_store, fx.home_bundle)), expected);
  // Exactly the 71-byte ack was charged; refused frames use no Credit.
  data.send(credit(MAX_WINDOW - INITIAL_WINDOW + 71));
  data.send(request('read', 73, fixtures().home_read_events));
  assert.deepEqual(decode(...await data.next()), [{ type: 'events', id: 73, items: [], head: null, receipt: null }]);
}));

test('every data frame is gated on its own permit deadline; the socket stays open', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b1, fx.b1)), [{ type: 'staged', id: 2 }]);
  const expired = id => [{ type: 'refused', id, reason: 'Expired' }];
  // Each object call finishes inside its window, then answers after the
  // edge's deadline: the frame is withheld and only that id ends Expired.
  await control.log(fx.base, { append: 2_500, stage: 2_500, read: 2_500, controls: 2_500 });
  let short = expiring(2_000);
  assert.deepEqual(await ask(data, request('append', 3, short.append_c1, fx.c1)), expired(3));
  short = expiring(2_000);
  assert.deepEqual(await ask(data, request('stage', 4, short.stage_b2, fx.b2)), expired(4));
  short = expiring(2_000);
  assert.deepEqual(await ask(data, request('read', 5, short.read_1_2)), expired(5));
  short = expiring(2_000);
  assert.deepEqual(await ask(data, request('read', 10, short.read_controls_0)), expired(10));
  await control.log(fx.base, {});
  // The commit and the staged body stood: an exact retry returns the original
  // Ack, and c2 orders against the staged b2.
  assert.deepEqual(await ask(data, request('append', 6, fixtures().append_c1, fx.c1)),
    [acked(6, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
  assert.deepEqual(await ask(data, request('append', 7, fixtures().append_c2, fx.c2)),
    [acked(7, fx.base, fx.c2_id, fx.c2_head, 'verified')]);
  // A body stream held between frames: b1 is sent, then the deadline passes
  // before b2 and the stream ends Expired.
  await control.edge({ bodyHolds: { [`b/${fx.base}/${fx.b2_commitment}`]: 2_500 } });
  short = expiring(2_000);
  assert.deepEqual(await ask(data, request('read', 8, short.read_bodies_b1_b2), 2), [
    { type: 'body', id: 8, index: 0, last: false, bytes: fx.b1 },
    { type: 'refused', id: 8, reason: 'Expired' },
  ]);
  await control.edge({});
  await sleep(200);
  assert.deepEqual(data.inbox, []);
  assert.equal(data.isClosed, null);
  assert.equal((await ask(data, request('read', 9, fixtures().read_1_64)))[0].items.length, 3);
}));

test('without credit the edge sends at most its initial window and fetches no body ahead of credit', () => withSlowEdge(async (mf, control) => {
  const BODY_FRAME = 7 + 2 + 4 + 65536;
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b3, fx.b3)), [{ type: 'staged', id: 2 }]);
  assert.deepEqual((await ask(data, request('append', 3, fx.append_c3, fx.c3)))[0].type, 'acked');
  const gets = async () => (await control.edge({})).gets;
  assert.equal(await gets(), 0);
  // This client reads every frame but grants no credit until told to below.
  const stalled = await socket(mf, '/v1/data');
  const header = frame => ({ ...frameHeader(frame), index: parseInt(frame.slice(14, 16), 16), last: frame.slice(16, 18) === '01' });
  const stream = async (id, from, count) => {
    const frames = await stalled.next(count, 15_000);
    assert.equal(frames.length, count);
    assert.deepEqual(frames.map(header), Array.from({ length: count },
      (_, i) => ({ tag: 2, id, index: from + i, last: from + i === 63 })), 'in order');
    assert.ok(frames.every(f => f.length / 2 === BODY_FRAME));
  };
  // Each request asks for 64 bodies of 64 KiB, about 4 MiB. Two whole
  // streams fit the initial window, with less than one body frame left.
  for (const id of [10, 11]) {
    stalled.send(request('read', id, fx.read_bodies_b3_x64));
    await stream(id, 0, 64);
  }
  assert.ok(128 * BODY_FRAME <= INITIAL_WINDOW && 129 * BODY_FRAME > INITIAL_WINDOW);
  // The third waits for credit: nothing is sent and no further body is read.
  stalled.send(request('read', 12, fx.read_bodies_b3_x64));
  // A request waiting behind it still ends at its own deadline.
  const deadline = Date.now() + 2_000;
  stalled.send(request('read', 13, expiring(2_000).read_1_2));
  assert.deepEqual(decode(...await stalled.next(1, 6_000)), [{ type: 'refused', id: 13, reason: 'Expired' }]);
  assert.ok(Date.now() >= deadline, 'refused no earlier than the deadline');
  assert.equal(await gets(), 128);
  // A small private-object acknowledgement also waits behind the queued read,
  // and only its own id expires. The immutable write itself survives.
  const shortHome = expiring(2_000);
  stalled.send(request('storeHome', 14, shortHome.home_store, fx.home_bundle));
  assert.deepEqual(decode(...await stalled.next(1, 6_000)), [{ type: 'refused', id: 14, reason: 'Expired' }]);
  assert.deepEqual(await ask(data, request('storeHome', 15, fixtures().home_store, fx.home_bundle)),
    [{ type: 'home_objects_stored', id: 15, prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest }]);
  // Credit for three bodies resumes the stream in order, three bodies more.
  stalled.send(credit(3 * BODY_FRAME));
  await stream(12, 0, 3);
  await sleep(500);
  assert.deepEqual(stalled.inbox, []);
  assert.equal(await gets(), 131);
  // Then the rest.
  stalled.send(credit(61 * BODY_FRAME));
  await stream(12, 3, 61);
  assert.equal(await gets(), 192);
  await sleep(200);
  assert.deepEqual(stalled.inbox, []);
  assert.equal(stalled.isClosed, null);
}));

test('compound proof queued behind Credit expires without buffering proof or blocking another account', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const writer = await socket(mf, '/v1/data');
  await genesis(writer, fx);
  assert.equal((await ask(writer, request('stage', 2, fx.stage_b3, fx.b3)))[0].type, 'staged');
  assert.equal((await ask(writer, request('append', 3, fx.append_c3, fx.c3)))[0].type, 'acked');
  const stalled = await socket(mf, '/v1/data');
  for (const id of [10, 11]) {
    stalled.send(request('read', id, fx.read_bodies_b3_x64));
    assert.equal((await stalled.next(64, 15_000)).length, 64);
  }
  stalled.send(request('read', 12, fx.read_bodies_b3_x64));
  stalled.send(publish(13, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
  assert.equal((await control.log(fx.base, { action: 'waitForAppend', count: 3 })).append, 3);
  assert.deepEqual(stalled.inbox, [], 'proof cannot bypass the queued body window');
  const independent = await socket(mf, '/v1/data');
  assert.equal((await ask(independent, request('read', 14, fx.home_read_events)))[0].type, 'events');
  await control.edge({ ahead: WINDOW + 1_000 });
  stalled.send(credit(64 * (7 + 2 + 4 + 65536)));
  const replies = decode(...await stalled.next(2));
  assert.deepEqual(replies.map(r => [r.id, r.type, r.reason]).sort((a,b) => a[0]-b[0]),
    [[12, 'refused', 'Expired'], [13, 'refused', 'Expired']]);
  await control.edge({ ahead: 0 });
  const [retried] = await ask(writer, publish(15, fixtures().stage_b1, fixtures().append_c1, fx.c1, fx.b1));
  assert.equal(retried.proof_head.position, 3);
  assert.equal(retried.commitment, (await ask(writer, request('read', 16, fx.read_1_64)))[0].items[2].commitment);
}));

test('a body waiter released after its deadline ends Expired without reading R2', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b3, fx.b3)), [{ type: 'staged', id: 2 }]);
  assert.deepEqual((await ask(data, request('append', 3, fx.append_c3, fx.c3)))[0].type, 'acked');
  const stalled = await socket(mf, '/v1/data');
  // Two whole 64-body streams use the initial window.
  for (const id of [10, 11]) {
    stalled.send(request('read', id, fx.read_bodies_b3_x64));
    assert.equal((await stalled.next(64, 15_000)).length, 64);
  }
  stalled.send(request('read', 12, fx.read_bodies_b3_x64));
  await sleep(300);
  const before = (await control.edge({})).gets;
  // The edge's clock passes the permit's deadline before its waiter timer
  // fires; credit then releases the waiter, which must not read the body.
  await control.edge({ ahead: WINDOW + 1_000 });
  stalled.send(credit(MAX_FRAME));
  assert.deepEqual(decode(...await stalled.next()), [{ type: 'refused', id: 12, reason: 'Expired' }]);
  assert.equal((await control.edge({})).gets, before);
  assert.equal(stalled.isClosed, null);
}));

test('a socket keeps at most one initial window in flight, even with credit granted ahead', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const greedy = await socket(mf, '/v1/data');
  // Allowed: the unused window may reach 64 MiB. The read after it is
  // handled after the grant.
  greedy.send(credit(MAX_WINDOW - INITIAL_WINDOW));
  assert.equal((await ask(greedy, request('read', 1, fx.read_1_2)))[0].type, 'events');
  // Two 64-body reads hold 128 body frames in flight, less than one frame
  // short of an initial window. The window covers all of a third read, but
  // credit for three frames lets exactly three more be in flight.
  for (const id of [10, 11]) {
    greedy.send(request('read', id, fx.read_bodies_b3_x64));
    assert.equal((await greedy.next(64, 15_000)).length, 64);
  }
  assert.ok(128 * BODY_FRAME + 2048 <= INITIAL_WINDOW && 129 * BODY_FRAME > INITIAL_WINDOW);
  greedy.send(request('read', 12, fx.read_bodies_b3_x64));
  greedy.send(credit(3 * BODY_FRAME));
  assert.deepEqual((await greedy.next(3, 15_000)).map(f => frameHeader(f).id), [12, 12, 12]);
  // The fourth frame's wait began as the third was sent. Past its deadline,
  // credit for one frame releases it, and it ends Expired without a read.
  const before = (await control.edge({})).gets;
  await control.edge({ ahead: WINDOW + 1_000 });
  greedy.send(credit(BODY_FRAME));
  const [after] = await greedy.next();
  assert.deepEqual(frameHeader(after), { tag: 6, id: 12 }, 'a Refused, not a fourth Body');
  assert.deepEqual(decode(after), [{ type: 'refused', id: 12, reason: 'Expired' }]);
  assert.equal((await control.edge({ ahead: WINDOW + 1_000 })).gets, before);
  await control.edge({});
}));

const B4_FRAME = 7 + 2 + 4 + (1 << 20);
async function orderB4(data, fx) {
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b4, fx.b4)), [{ type: 'staged', id: 2 }]);
  assert.equal((await ask(data, request('append', 3, fx.append_c4, fx.c4)))[0].type, 'acked');
}
// A device that reads eight one-MiB bodies and grants no credit, so all of
// them stay in flight against the budget.
async function hoard(mf, fx) {
  const device = await socket(mf, '/v1/data');
  for (let id = 10; id < 18; id++) device.send(request('read', id, fx.read_bodies_b4));
  const frames = await device.next(8, 15_000);
  assert.deepEqual(frames.map(f => [frameHeader(f).tag, f.length / 2]), Array(8).fill([2, B4_FRAME]));
  return device;
}

test('past the bulk part bulk frames wait for credit; small replies and presence go on, and closes release', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB4(data, fx);
  await orderB3(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  // Hoarders hold one-MiB body frames until less of the bulk part is left
  // than a last device's two 64-body reads ask for, but more than they take
  // before they wait, so that device waits for the budget, not its window.
  const { limits } = await control.budget();
  const left = async () => limits.bulk - (await control.budget()).frames;
  const hoards = [];
  while (await left() >= 128 * BODY_FRAME) hoards.push(await hoard(mf, fx));
  assert.ok(await left() < INITIAL_WINDOW - BODY_FRAME, `${await left()} bytes left`);
  const last = await socket(mf, '/v1/data');
  for (const id of [10, 11]) last.send(request('read', id, fx.read_bodies_b3_x64));
  await budgetUntil(control, budget => budget.waiting === 1, 'had the last device waiting');
  assert.ok(last.inbox.length < 128);
  // A small reply still has the reserve: a read of two events takes more
  // than one 64 KiB frame while it is built.
  assert.equal((await ask(data, request('read', 4, fx.read_1_2)))[0].type, 'events');
  // A one-MiB request is not held: it is refused before its permit is
  // verified, and the admitted socket stays open.
  assert.deepEqual(await ask(data, request('stage', 6, fx.stage_b4, fx.b4)), [{ type: 'refused', id: 6, reason: 'Unavailable' }]);
  assert.equal(data.isClosed, null);
  // Presence still flows: a waiting bulk frame cannot use the reserve that
  // presence takes from, so cursors never go dark for a catch-up.
  a.send(presence(1, sealed(0xa1)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0xa1))]);
  // Credit from another socket frees one MiB of budget: the waiting bodies
  // are sent and nothing waits.
  hoards[0].send(credit(B4_FRAME));
  const streamed = await last.next(128, 15_000);
  assert.deepEqual(streamed.map(f => frameHeader(f).id).sort(), [...Array(64).fill(10), ...Array(64).fill(11)]);
  await budgetUntil(control, budget => budget.waiting === 0, 'had nothing waiting');
  // A close returns all its socket held: a reader waiting for the budget is
  // served in full when a hoarder closes, whether on a frame that does not
  // decode or by the client. The reader then hoards in turn.
  for (const close of [s => s.send(new Uint8Array([0, 1, 9, 0, 0, 0, 1])), s => s.ws.close()]) {
    const reader = await socket(mf, '/v1/data');
    for (let id = 20; id < 28; id++) reader.send(request('read', id, fx.read_bodies_b4));
    await budgetUntil(control, budget => budget.waiting === 1, 'had the reader waiting');
    close(hoards.pop());
    const frames = await reader.next(8, 15_000);
    assert.ok(frames.length === 8 && frames.every(f => f.length / 2 === B4_FRAME));
    hoards.push(reader);
  }
}));

// A Body frame's header, and its body in hex.
const bodyFrame = frame => ({ ...frameHeader(frame), index: parseInt(frame.slice(14, 16), 16), last: frame.slice(16, 18) === '01' });
const inOrder = (id, count, last = count - 1) =>
  Array.from({ length: count }, (_, index) => ({ tag: 2, id, index, last: index === last }));

test('a body stream reads up to 16 bodies from R2 at once and sends them in permit order', () => withSlowEdge(async (mf, control) => {
  const DELAY = 100;
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const start = charged(await control.budget());
  const { limits } = await control.budget();
  const reader = await socket(mf, '/v1/data');
  await control.edge({ bodyDelay: DELAY });
  // Two batches of 64 bodies, one after the other, as a bootstrap reads them.
  const began = Date.now();
  for (const id of [10, 11]) {
    reader.send(request('read', id, fx.read_bodies_b3_x64));
    const frames = await reader.next(64, 15_000);
    assert.deepEqual(frames.map(bodyFrame), inOrder(id, 64));
    assert.ok(frames.every(f => f.slice(26) === fx.b3), 'exact body bytes');
    creditFor(reader, frames);
  }
  const took = Date.now() - began;
  // 128 reads of 100 ms, 16 at a time, take eight rounds: 0.8 s, not the
  // 12.8 s of one at a time, nor the 0.2 s of a whole batch at once.
  assert.ok(took >= 8 * DELAY && took < 32 * DELAY, `${took} ms`);
  assert.equal((await control.edge({})).peak, 16);
  await settles(control, plus(start, limits.socket), 'every frame credited back');
  reader.ws.close();
  await settles(control, start, 'closed');
}));

test('a body missing mid-stream ends it after the bodies before it, and the reads after it return their charges', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const start = charged(await control.budget());
  const { limits } = await control.budget();
  const reader = await socket(mf, '/v1/data');
  // The 21st read finds nothing while later reads are in flight.
  await control.edge({ bodyDelay: 50, missAt: 20 });
  reader.send(request('read', 10, fx.read_bodies_b3_x64));
  const frames = await reader.next(21, 15_000);
  assert.deepEqual(frames.slice(0, 20).map(bodyFrame), inOrder(10, 20, 63));
  assert.deepEqual(decode(frames[20]), [{ type: 'refused', id: 10, reason: 'Missing' }]);
  await sleep(500);
  assert.deepEqual(reader.inbox, []);
  creditFor(reader, frames.slice(0, 20));
  await settles(control, plus(start, limits.socket), 'unsent reads refunded');
  assert.equal(reader.isClosed, null);
  await control.edge({});
}));

test('body reads in flight when their socket closes return its budget exactly once', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const start = charged(await control.budget());
  const reader = await socket(mf, '/v1/data');
  await control.edge({ bodyDelay: 2_000 });
  reader.send(request('read', 10, fx.read_bodies_b3_x64));
  // 16 reads hold their frames' window; the request frame's own charge,
  // while it is handled, is less than one more.
  const held = b => Math.floor((b.frames - start.frames) / BODY_FRAME);
  await budgetUntil(control, b => held(b) === 16, 'held 16 body reads');
  assert.deepEqual(reader.inbox, [], 'none sent yet');
  // The edge closes it, on a frame that does not decode.
  reader.send(new Uint8Array([0, 1, 9, 0, 0, 0, 1]));
  assert.equal((await reader.closed()).code, 1002);
  await settles(control, start, 'closed with 16 reads in flight');
  // Past the reads' delay, whether they finished or the runtime dropped them
  // with the socket, nothing more is returned.
  await sleep(2_500);
  assert.deepEqual(charged(await control.budget()), start, 'nothing returned twice');
}));

// What the edge's memory budget has charged, as the fixture reads it back.
const charged = ({ fixed, frames }) => ({ fixed, frames });
const plus = (start, fixed, frames = 0) => ({ fixed: start.fixed + fixed, frames: start.frames + frames });
// Waits until the budget has charged exactly `expected`, and fails if it does
// not within 5 s: a leak never settles.
async function settles(control, expected, what) {
  let now;
  for (let i = 0; i < 100; i++) {
    now = charged(await control.budget());
    if (now.fixed === expected.fixed && now.frames === expected.frames) return;
    await sleep(50);
  }
  assert.deepEqual(now, expected, what);
}
// Returns the bytes of `frames` to the window by Credit, as a device does.
const creditFor = (device, frames) => device.send(credit(frames.reduce((n, f) => n + f.length / 2, 0)));

test('every way a data socket closes returns exactly what it held to the budget', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const start = charged(await control.budget());
  const { limits } = await control.budget();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  data.ws.close();
  await settles(control, start, 'closed by the client after its requests');
  for (const [how, close, code] of [
    ['by the client', s => s.ws.close(), null],
    ['on a frame that does not decode', s => s.send(new Uint8Array([0, 1, 9, 0, 0, 0, 1])), 1002],
    ['on a text frame', s => s.send('text'), 1003],
    ['on a grant past the window bound', s => s.send(credit(MAX_WINDOW)), 1008],
  ]) {
    // A socket with a subscription, a presence join and 64 bodies in flight.
    const device = await socket(mf, '/v1/data');
    device.send(request('subscribe', 1, fx.subscribe, 2));
    device.send(presenceJoin(2, fx.presence));
    device.send(request('read', 3, fx.read_bodies_b3_x64));
    assert.equal((await device.next(65, 15_000)).length, 65);
    await settles(control, plus(start, limits.socket + 2 * limits.stream, 64 * BODY_FRAME + 14), `held before closing ${how}`);
    close(device);
    if (code) assert.equal((await device.closed()).code, code);
    await settles(control, start, `closed ${how}`);
  }
  // A request still being handled, here a read held at its log object,
  // returns its own charge when its socket closes, not when (or if) its
  // handling ends.
  await control.log(fx.base, { read: 60_000 });
  const reader = await socket(mf, '/v1/data');
  reader.send(request('read', 1, fx.read_1_2));
  await budgetUntil(control, b => b.fixed === start.fixed + limits.socket, 'admitted the reader');
  reader.ws.close();
  await settles(control, start, 'closed while a request was handled');
}));

test('ends of requests, subscriptions, joins and authz sessions return their charges', async () => {
  const backends = await backend();
  try {
    await withSlowEdge(async (mf, control) => {
      const fx = fixtures();
      const start = charged(await control.budget());
      const { limits } = await control.budget();
      const data = await socket(mf, '/v1/data');
      await genesis(data, fx);
      await orderB3(data, fx);
      data.ws.close();
      await settles(control, start, 'set up');
      // An admitted device that has credited back what it received.
      const device = await socket(mf, '/v1/data');
      device.send(request('read', 1, fx.read_1_2));
      creditFor(device, await device.next());
      const admitted = plus(start, limits.socket);
      await settles(control, admitted, 'admitted');

      // A subscription replaced before its deadline keeps one charge, and
      // returns it when the replacement ends Expired; a presence join returns
      // its charge when it ends Expired.
      // Short permits expire 3 s after creation; do not spend their lifetime on setup.
      const streamPermits = fixtures();
      device.send(request('subscribe', 10, streamPermits.subscribe_short, 2));
      device.send(request('subscribe', 11, streamPermits.subscribe_short, 2));
      device.send(presenceJoin(12, streamPermits.presence_short));
      const [snapshot] = await device.next();
      const first = decode(snapshot)[0];
      assert.deepEqual([first.type, first.event, first.id], ['peers', 'snapshot', 12], JSON.stringify(first));
      creditFor(device, [snapshot]);
      await settles(control, plus(admitted, 2 * limits.stream), 'one subscription and one join');
      const ended = decode(...await device.next(2, 6_000)).map(f => [f.type, f.id, f.reason]).sort((a, b) => a[1] - b[1]);
      assert.deepEqual(ended, [['refused', 11, 'Expired'], ['refused', 12, 'Expired']]);
      await settles(control, admitted, 'subscription and join ended Expired');

      // A join replaced at another epoch carries its charge to the new join,
      // which returns it when its upgrade is refused.
      device.send(presenceJoin(20, fx.presence));
      creditFor(device, await device.next());
      await settles(control, plus(admitted, limits.stream), 'joined');
      assert.deepEqual(await ask(device, presenceJoin(21, fx.presence_stale)), [{ type: 'refused', id: 21, reason: 'Epoch' }]);
      await settles(control, admitted, 'join at another epoch refused');

      // A log object restart ends a subscription and a read waiting on the
      // object, and then a join; each returns its charge, the read its
      // window take.
      device.send(request('subscribe', 30, fx.subscribe, 2));
      await settles(control, plus(admitted, limits.stream), 'subscribed');
      await control.log(fx.base, { read: 10_000 });
      device.send(request('read', 31, fx.read_1_2));
      for (let i = 0; i < 100 && (await control.budget()).frames <= admitted.frames; i++) await sleep(50);
      assert.ok((await control.budget()).frames > admitted.frames, 'the read took its window');
      await control.log(fx.base, { action: 'abort' });
      const restarted = decode(...await device.next(2)).map(f => [f.type, f.id, f.reason]).sort((a, b) => a[1] - b[1]);
      assert.deepEqual(restarted, [30, 31].map(id => ['refused', id, 'Unavailable']));
      await settles(control, admitted, 'subscription and read ended by a log object restart');
      device.send(presenceJoin(32, fx.presence));
      creditFor(device, await device.next());
      await settles(control, plus(admitted, limits.stream), 'joined again');
      await control.log(fx.base, { action: 'abort' });
      assert.deepEqual(decode(...await device.next()), [{ type: 'refused', id: 32, reason: 'Unavailable' }]);
      await settles(control, admitted, 'join ended by a log object restart');

      // A body frame released by Credit after its deadline is refunded unsent.
      await starve(device, fx);
      await control.edge({ ahead: WINDOW + 1_000 });
      device.send(credit(128 * BODY_FRAME));
      assert.deepEqual(decode(...await device.next()), [{ type: 'refused', id: 12, reason: 'Expired' }]);
      await control.edge({});
      await settles(control, admitted, 'body withheld at its deadline');
      device.ws.close();
      await settles(control, start, 'device closed');

      // Authz sessions: closed by the device, ended by the backend, and
      // refused when no backend accepts.
      const session = await socket(mf, '/v1/authz');
      assert.equal(session.status, 101);
      await settles(control, plus(start, limits.socket), 'authz session');
      session.ws.close();
      await settles(control, start, 'authz closed by the device');
      const dropped = await socket(mf, '/v1/authz');
      assert.equal(dropped.status, 101);
      await settles(control, plus(start, limits.socket), 'second authz session');
      backends.drop();
      assert.equal((await dropped.closed()).code, 1011);
      await settles(control, start, 'authz ended by its backend');
      backends.refuse(true);
      assert.equal((await socket(mf, '/v1/authz')).status, 503);
      await settles(control, start, 'authz upgrade refused');
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: backends.url, ready: true }]) });
  } finally { await backends.close(); }
});

// Polls the budget until `ready(budget)`, failing after 5 s.
async function budgetUntil(control, ready, what) {
  for (let i = 0; i < 100; i++) {
    const now = await control.budget();
    if (ready(now)) return now;
    await sleep(50);
  }
  assert.fail(`budget never ${what}: ${JSON.stringify(await control.budget())}`);
}

test('near the fixed share limit only lasting costs are shed, and a 4.2 MB read still completes', async () => {
  const authz = await backend();
  try {
    await withSlowEdge(async (mf, control) => {
      const fx = fixtures();
      const data = await socket(mf, '/v1/data');
      await genesis(data, fx);
      const reader = await socket(mf, '/v1/data');
      reader.send(request('read', 1, fx.read_1_2));
      creditFor(reader, await reader.next());
      // Other devices' sockets, stood in for, leave less of the fixed share
      // than one subscription costs.
      const { fixed, limits } = await control.budget();
      const ballast = limits.fixed - fixed - limits.stream + 1;
      assert.equal((await control.budget({ ballast })).ballast, ballast);
      // Nothing more that lasts is admitted: not a new socket at its first
      // permit, a subscription, a presence join or an authz session.
      const late = await socket(mf, '/v1/data');
      assert.deepEqual(await ask(late, request('read', 1, fx.read_1_2)), [{ type: 'refused', id: 1, reason: 'Unavailable' }]);
      assert.equal((await late.closed()).code, 1013);
      assert.deepEqual(await ask(reader, request('subscribe', 2, fx.subscribe, 1)), [{ type: 'refused', id: 2, reason: 'Unavailable' }]);
      assert.deepEqual(await ask(reader, presenceJoin(3, fx.presence)), [{ type: 'refused', id: 3, reason: 'Unavailable' }]);
      assert.equal((await socket(mf, '/v1/authz')).status, 503);
      // The frames share is untouched: a read of 64 events takes its 4.2 MB
      // bound and is answered.
      const [events] = await ask(reader, request('read', 4, fx.read_1_64));
      assert.deepEqual([events.type, events.items.length], ['events', 1]);
      assert.equal(reader.isClosed, null);
      // Once the others' sockets go, lasting costs are admitted again.
      await control.budget({ ballast: 0 });
      assert.equal((await ask(await socket(mf, '/v1/data'), request('read', 5, fx.read_1_2)))[0].type, 'events');
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: authz.url, ready: true }]) });
  } finally { await authz.close(); }
});

test('while catch-ups wait for the budget, an outbox socket, subscription, join and authz session are admitted', async () => {
  const authz = await backend();
  try {
    await withSlowEdge(async (mf, control) => {
      const fx = fixtures();
      const data = await socket(mf, '/v1/data');
      await genesis(data, fx);
      await orderB4(data, fx);
      // Devices catching up, each reading eight one-MiB bodies and crediting
      // none, until the bulk part is full and the next body waits.
      const catchups = [];
      for (let full = false; !full;) {
        const device = await socket(mf, '/v1/data');
        for (let id = 10; id < 18; id++) device.send(request('read', id, fx.read_bodies_b4));
        catchups.push(device);
        full = (await budgetUntil(control, b => b.waiting > 0 || device.inbox.length === 8, 'took or waited')).waiting > 0;
        assert.ok(catchups.length <= 8, 'the bulk part holds fewer than eight catch-ups');
      }
      // Seven more devices start catching up; each is admitted and waits for
      // the budget.
      for (let i = 0; i < 7; i++) {
        const device = await socket(mf, '/v1/data');
        device.send(request('read', 10, fx.read_bodies_b4));
        await budgetUntil(control, b => b.waiting === 2 + i || device.inbox.length > 0, `had ${2 + i} waiting`);
        assert.deepEqual([device.inbox, device.isClosed], [[], null], `catch-up ${i} waits, admitted`);
        catchups.push(device);
      }
      // A device that starts typing opens its outbox link and publishes.
      const outbox = await socket(mf, '/v1/data');
      const [published] = await ask(outbox, publish(1, fx.stage_b1, fx.append_c1, fx.c1, fx.b1));
      assert.equal(published.type, 'published');
      // Its lane resubscribes and it joins presence; its authz session reconnects.
      const before = await control.budget();
      outbox.send(request('subscribe', 2, fx.subscribe, published.proof_head.position));
      await budgetUntil(control, b => b.fixed === before.fixed + before.limits.stream, 'charged the subscription');
      const typing = await joined(mf, fx.presence, 3);
      const session = await socket(mf, '/v1/authz');
      assert.equal(session.status, 101);
      // Credit from the first two catch-ups serves every waiting one.
      for (const device of catchups.slice(0, 2)) creditFor(device, await device.next(8));
      await budgetUntil(control, b => b.waiting === 0, 'had nothing waiting');
      for (const device of catchups.slice(-7)) assert.equal(frameHeader((await device.next())[0]).tag, 2);
      for (const s of [data, outbox, typing, session, ...catchups]) s.ws.close();
      await settles(control, { fixed: 0, frames: 0 }, 'all closed');
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: authz.url, ready: true }]) });
  } finally { await authz.close(); }
});

// Credits one body back, as a device does when it has received it, then sends
// a request the edge refuses using no budget. Frames on a socket are handled
// in order, so once the refusal arrives the edge has handled the Credit and
// taken whatever it freed. Bodies arriving meanwhile are left uncredited.
async function creditOne(device, id) {
  device.send(credit(BODY_FRAME));
  device.send(request('read', id, '00'.repeat(200)));
  for (;;) if (frameHeader((await device.next())[0]).tag === 6) return;
}

test('bulk frames are served in arrival order across sockets: a 4.2 MB read is not starved by streaming catch-ups', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  // Devices catching up on 64 KiB bodies, four 64-body reads each, crediting
  // none yet, until the bulk part is full and the next body waits.
  const streams = [];
  while ((await control.budget()).waiting === 0) {
    assert.ok(streams.length < 4, 'the bulk part holds fewer than four catch-ups');
    const device = await socket(mf, '/v1/data');
    for (let id = 10; id < 14; id++) device.send(request('read', id, fx.read_bodies_b3_x64));
    streams.push(device);
    await budgetUntil(control, b => b.waiting > 0 || device.inbox.length === 128, 'took or waited');
  }
  assert.equal(streams.length, 3);
  for (const device of streams) device.inbox.splice(0);
  // Another device then reads 64 events, which takes a 4.2 MB bound, and waits
  // behind the body that waited first.
  const reader = await socket(mf, '/v1/data');
  reader.send(request('read', 1, fx.read_1_64));
  await budgetUntil(control, b => b.waiting === 2, 'had the reader waiting');
  // The catch-ups credit one body at a time, in turn. Each Credit frees one
  // body's budget; bodies asked for after the reader wait behind it, so it is
  // served once about 65 have been credited. Were the freed budget retaken
  // body by body, it would wait until its deadline however many were.
  let step = 0;
  while (!reader.inbox.length) {
    assert.ok(step < 3 * 64, `the reader was not served after ${step} bodies were credited`);
    await creditOne(streams[step % 3], 100 + step);
    step++;
  }
  const [events] = decode(...await reader.next());
  assert.deepEqual([events.type, events.items.length], ['events', 2]);
  for (const s of [data, reader, ...streams]) s.ws.close();
  await settles(control, { fixed: 0, frames: 0 }, 'all closed');
}));

// A socket must credit back, within this long, what it held when it began.
const STALL = 120_000;
// What a read of two events takes before it is answered, and the two Body
// frames of a read of b1 and b2.
const READ_BOUND = 7 + 2 + 1 + 1 + 82 + 300 + 2 * (4 + 149 + 4 + 2 + 32 + 4 + 65536);
const B1_B2 = 7 + 2 + 4 + 1024 + 7 + 2 + 4 + 4096;
async function orderAll(data, fx) {
  await genesis(data, fx);
  await content(data, fx);
  assert.deepEqual(await ask(data, request('stage', 4, fx.stage_b2, fx.b2)), [{ type: 'staged', id: 4 }]);
  assert.equal((await ask(data, request('append', 5, fx.append_c2, fx.c2)))[0].type, 'acked');
  await orderB4(data, fx);
  await orderB3(data, fx);
}
// A device's data socket that takes frames by `fill`, credits none of them,
// and then subscribes, so it is never idle.
async function hoarder(mf, control, fx, fill) {
  const device = await socket(mf, '/v1/data');
  await fill(device);
  const { fixed, limits } = await control.budget();
  device.send(request('subscribe', 1, fx.subscribe, 1000));
  await budgetUntil(control, b => b.fixed === fixed + limits.stream, 'charged the subscription');
  return device;
}

test('one device that fills the frames half and credits nothing is closed 1013 after 120 s; waiting frames are then served', () => withSlowEdge(async (mf, control) => {
  const T = Date.now();
  await control.edge({ frozen: T });
  const fx = fixtures(T);
  const data = await socket(mf, '/v1/data');
  await orderAll(data, fx);
  data.ws.close();
  const start = await budgetUntil(control, b => b.frames === 0 && b.fixed === 0, 'settled after setup');
  const { limits } = start;
  // Four sockets of one device. Three take one-MiB bodies until the bulk part
  // has less than one left, the third ending on 64 KiB bodies, one of which
  // waits; the fourth takes small reads until a read of two events no longer
  // fits the frames half, though a request frame still does.
  const bodies = (device, ids, permit) => ids.forEach(id => device.send(request('read', id, permit)));
  const hoards = [];
  for (const count of [8, 8, 7]) {
    hoards.push(await hoarder(mf, control, fx, async device => {
      bodies(device, Array.from({ length: count }, (_, i) => 10 + i), fx.read_bodies_b4);
      assert.equal((await device.next(count, 15_000)).length, count);
    }));
  }
  hoards[2].send(request('read', 20, fx.read_bodies_b3_x64));
  await budgetUntil(control, b => b.waiting === 1, 'had the third socket waiting');
  assert.ok(limits.bulk - (await control.budget()).frames < BODY_FRAME);
  hoards.push(await hoarder(mf, control, fx, async device => {
    for (let id = 100; ; id += 8) {
      const left = limits.frames - (await control.budget()).frames;
      if (left < READ_BOUND) return;
      const count = Math.min(8, Math.ceil((left - READ_BOUND + 1) / B1_B2));
      bodies(device, Array.from({ length: count }, (_, i) => id + i), fx.read_bodies_b1_b2);
      assert.equal((await device.next(2 * count, 15_000)).length, 2 * count);
    }
  }));
  assert.ok((await control.budget()).frames > limits.frames - READ_BOUND, 'the frames half is full');
  // Just short of two minutes on, another device asks for a read of two
  // events and a one-MiB body, and both wait for the budget.
  await control.edge({ frozen: T + STALL - 1_000 });
  const late = fixtures(T + STALL - 1_000);
  const small = await socket(mf, '/v1/data');
  const bulk = await socket(mf, '/v1/data');
  small.send(request('read', 1, late.read_1_2));
  bulk.send(request('read', 2, late.read_bodies_b4));
  await budgetUntil(control, b => b.waiting === 3, 'had both readers waiting');
  // At two minutes the hoarding sockets are closed, returning all they held,
  // and the waiting frames are served.
  await control.edge({ frozen: T + STALL });
  for (const device of hoards) assert.deepEqual(await device.closed(), { code: 1013, reason: 'credit stalled' });
  const [answer] = await small.next();
  const [events] = decode(answer);
  assert.deepEqual([events.type, events.items.length], ['events', 2]);
  const [body] = await bulk.next();
  assert.deepEqual([frameHeader(body).tag, body.length / 2], [2, B4_FRAME]);
  creditFor(small, [answer]);
  creditFor(bulk, [body]);
  await settles(control, plus(charged(start), 2 * limits.socket), 'only the readers are charged');
  for (const s of [small, bulk]) s.ws.close();
  await settles(control, charged(start), 'all closed');
}));

test('a socket that keeps crediting back what it held is not closed however long it holds frames; one that falls behind is', () => withSlowEdge(async (mf, control) => {
  const T = Date.now();
  await control.edge({ frozen: T });
  const fx = fixtures(T);
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  data.ws.close();
  const start = await budgetUntil(control, b => b.frames === 0 && b.fixed === 0, 'settled after setup');
  const stream = (device, id, permit) => {
    device.send(request('read', id, permit));
    return device.next(64, 15_000);
  };
  // Credits back `frames`; the refused forged request that follows shows the
  // edge has handled the Credit.
  const pay = async (device, frames, id) => {
    creditFor(device, frames);
    assert.deepEqual(await ask(device, request('read', id, '00'.repeat(200))), [{ type: 'refused', id, reason: 'Malformed' }]);
  };
  // Two sockets each take 64 bodies of 64 KiB. A stall time begins when a
  // socket begins to hold frames, owing what it holds then, and again each
  // time it has paid that, owing what it holds by then.
  let steadyFrames, laggingFrames;
  const steady = await hoarder(mf, control, fx, async d => { steadyFrames = await stream(d, 10, fx.read_bodies_b3_x64); });
  const lagging = await hoarder(mf, control, fx, async d => { laggingFrames = await stream(d, 10, fx.read_bodies_b3_x64); });
  // 100 s on, each credits back half: a new stall time owing the other half.
  await control.edge({ frozen: T + 100_000 });
  await pay(steady, steadyFrames.splice(0, 32), 20);
  await pay(lagging, laggingFrames.splice(0, 32), 20);
  // 200 s on, one takes 64 more bodies and then credits back the rest of the
  // first; the other credits back all of the rest but one body, and reads two
  // events, whose unused bound the edge returns, which pays nothing.
  await control.edge({ frozen: T + 200_000 });
  const later = fixtures(T + 200_000);
  assert.equal((await stream(steady, 11, later.read_bodies_b3_x64)).length, 64);
  await pay(steady, steadyFrames, 21);
  await pay(lagging, laggingFrames.slice(1), 21);
  assert.equal((await ask(lagging, request('read', 22, later.read_1_2)))[0].type, 'events');
  // Other devices' frames, stood in for, fill the frames half until a read
  // of two events waits. At 220 s, two minutes after its stall time began,
  // the socket that still owes a body is closed; the other has held frames
  // all along but paid what it owed each time, and is not.
  const { frames, limits } = await control.budget();
  await control.budget({ frames: limits.frames - frames - (READ_BOUND - 1) });
  await control.edge({ frozen: T + 100_000 + STALL });
  const reader = await socket(mf, '/v1/data');
  reader.send(request('read', 1, fixtures(T + 100_000 + STALL).read_1_2));
  assert.deepEqual(await lagging.closed(), { code: 1013, reason: 'credit stalled' });
  // The body it returned lets the read through.
  assert.equal(decode(...await reader.next())[0].type, 'events');
  assert.equal(steady.isClosed, null);
  await control.budget({ frames: 0 });
  for (const s of [steady, reader]) s.ws.close();
  await settles(control, charged(start), 'all closed');
}));

test('a waiting frame released from another socket\'s request leaves the frames waiting behind it waiting', () => withSlowEdge(async (mf, control) => {
  const T = Date.now();
  await control.edge({ frozen: T });
  const fx = fixtures(T);
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await content(data, fx);
  await orderB4(data, fx);
  data.ws.close();
  const start = await budgetUntil(control, b => b.frames === 0 && b.fixed === 0, 'settled after setup');
  // Other devices' frames, stood in for, fill the frames half until a read
  // of two events waits. Its permit ends 3 s on, by real time; a one-MiB body
  // read asked for after it, on a permit that lasts, waits behind it.
  const { frames, limits } = start;
  const standIn = limits.frames - frames - (READ_BOUND - 1);
  await control.budget({ frames: standIn });
  const device = await socket(mf, '/v1/data');
  device.send(request('read', 1, fixtures(T - WINDOW + 3_000).read_1_2));
  await budgetUntil(control, b => b.waiting === 1, 'had the read waiting');
  // The read was seen waiting, so its 3 s timer was armed by now: waiting to
  // 3.5 s past this point is past the stale timer whatever the receipt delays.
  const armed = Date.now();
  device.send(request('read', 2, fx.read_bodies_b4));
  // Budget freed in another request lets the read through, but no bulk frame.
  await control.budget({ frames: standIn - BODY_FRAME });
  const [events] = decode(...await device.next());
  assert.deepEqual([events.type, events.id], ['events', 1]);
  // Past the read's deadline its wait has long ended; the body still waits,
  // and is sent once the stand-in goes.
  await sleep(armed + 3_500 - Date.now());  // 3 s permit, 0.5 s margin
  assert.deepEqual(device.inbox, []);
  await control.budget({ frames: 0 });
  const [body] = await device.next();
  assert.deepEqual([frameHeader(body).tag, frameHeader(body).id, body.length / 2], [2, 2, B4_FRAME]);
  device.ws.close();
  await settles(control, charged(start), 'all closed');
}));

// ---- presence --------------------------------------------------------------

// Presence frames are data-wire version 3: PresenceJoin (tag 33) carries a
// presence permit, Presence (tag 34) opaque sealed bytes under the join's id.
function presenceFrame(tag, id, bytes) {
  const head = Buffer.alloc(11);
  head.writeUInt16BE(3); head[2] = tag; head.writeUInt32BE(id, 3); head.writeUInt32BE(bytes.length, 7);
  return new Uint8Array(Buffer.concat([head, Buffer.from(bytes)]));
}
const presenceJoin = (id, permit) => presenceFrame(33, id, unhex(permit));
const presence = (id, bytes) => presenceFrame(34, id, bytes);
// A stand-in for a 393-byte sealed presence frame; the Worker never opens one.
const sealed = (byte, size = 393) => new Uint8Array(size).fill(byte);
const BODY_FRAME = 7 + 2 + 4 + 65536;

// Opens a data socket and joins presence; returns it with its roster snapshot.
async function joined(mf, permit, id) {
  const device = await socket(mf, '/v1/data');
  device.send(presenceJoin(id, permit));
  const [snapshot] = decode(...await device.next());
  assert.equal(snapshot.type, 'peers', JSON.stringify(snapshot));
  assert.deepEqual([snapshot.id, snapshot.event], [id, 'snapshot']);
  device.slot = snapshot.slot;
  device.others = snapshot.others;
  return device;
}
const peers = (id, others, event, slot) => ({ type: 'peers', id, others, event, slot });
const relayed = (id, from, bytes) => ({ type: 'presence', id, from, sealed: hex(bytes) });

test('presence reaches only the other joined devices of the base, and Peers carry no identity', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  assert.equal(a.others, 0);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(b.others, 1);
  assert.notEqual(a.slot, b.slot);
  assert.deepEqual(decode(...await a.next()), [peers(1, 1, 'joined', b.slot)]);
  const c = await joined(mf, fx.presence, 3);
  assert.equal(c.others, 2);
  for (const [device, id] of [[a, 1], [b, 2]])
    assert.deepEqual(decode(...await device.next()), [peers(id, 2, 'joined', c.slot)]);
  // Forwarded as-is to every other device, under each one's own join id.
  a.send(presence(1, sealed(0xa1)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0xa1))]);
  assert.deepEqual(decode(...await c.next()), [relayed(3, a.slot, sealed(0xa1))]);
  // A frame under an id with no join is dropped silently.
  b.send(presence(9, sealed(0xb9)));
  // A fixed wait: nothing is sent, so there is no event to await.
  await sleep(300);
  assert.deepEqual([a.inbox, b.inbox, c.inbox], [[], [], []], 'never echoed to its sender');
  // A device that leaves is announced by slot only.
  c.ws.close();
  for (const [device, id] of [[a, 1], [b, 2]])
    assert.deepEqual(decode(...await device.next()), [peers(id, 1, 'left', c.slot)]);
  assert.deepEqual([a.isClosed, b.isClosed], [null, null]);
}));

test('a presence join needs a presence permit at the open epoch, and a presence permit serves nothing else', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  // A Subscribe permit cannot join presence; before admission that closes the socket.
  const subscriber = await socket(mf, '/v1/data');
  assert.deepEqual(await ask(subscriber, presenceJoin(1, fx.subscribe)), [{ type: 'refused', id: 1, reason: 'Scope' }]);
  assert.equal((await subscriber.closed()).code, 1008);
  const device = await socket(mf, '/v1/data');
  assert.deepEqual(await ask(device, presenceJoin(2, fx.presence_stale)), [{ type: 'refused', id: 2, reason: 'Epoch' }]);
  assert.deepEqual(await ask(device, request('subscribe', 3, fx.presence, 0)), [{ type: 'refused', id: 3, reason: 'Scope' }]);
  assert.deepEqual(await ask(device, request('read', 4, fx.presence)), [{ type: 'refused', id: 4, reason: 'Scope' }]);
  const forged = fx.presence.slice(0, -2) + (fx.presence.endsWith('00') ? '01' : '00');
  assert.deepEqual(await ask(device, presenceJoin(5, forged)), [{ type: 'refused', id: 5, reason: 'Scope' }]);
  assert.deepEqual(await ask(device, presenceJoin(6, expiring(0).presence)), [{ type: 'refused', id: 6, reason: 'Expired' }]);
  // The removal closes the epoch: a live join ends, and a new one is refused.
  const live = await joined(mf, fx.presence, 7);
  assert.equal((await ask(data, request('append', 8, fx.append_removal, fx.control)))[0].type, 'acked');
  assert.deepEqual(decode(...await live.next()), [{ type: 'refused', id: 7, reason: 'Epoch' }]);
  assert.deepEqual(await ask(device, presenceJoin(9, fixtures().presence)), [{ type: 'refused', id: 9, reason: 'Epoch' }]);
  assert.deepEqual([device.isClosed, live.isClosed], [null, null]);
}));

test('an ordered control ends every presence join with Refused{Epoch}; a rejoin gets a fresh roster', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  assert.equal((await ask(data, request('append', 3, fx.append_control, fx.control)))[0].type, 'acked');
  assert.deepEqual(decode(...await a.next()), [{ type: 'refused', id: 1, reason: 'Epoch' }]);
  assert.deepEqual(decode(...await b.next()), [{ type: 'refused', id: 2, reason: 'Epoch' }]);
  // An ended join forwards nothing.
  a.send(presence(1, sealed(0xa1)));
  await sleep(300);
  assert.deepEqual(b.inbox, []);
  // This control kept the epoch open, so both rejoin on the same sockets.
  a.send(presenceJoin(4, fixtures().presence));
  const [again] = decode(...await a.next());
  assert.deepEqual([again.type, again.id, again.others, again.event], ['peers', 4, 0, 'snapshot']);
  b.send(presenceJoin(5, fixtures().presence));
  const [bAgain] = decode(...await b.next());
  assert.deepEqual([bAgain.others, bAgain.event], [1, 'snapshot']);
  assert.deepEqual(decode(...await a.next()), [peers(4, 1, 'joined', bAgain.slot)]);
  b.send(presence(5, sealed(0xb5)));
  assert.deepEqual(decode(...await a.next()), [relayed(4, bAgain.slot, sealed(0xb5))]);
}));

test('a same-epoch renewal moves the deadline and keeps the upstream; an unrenewed join ends Expired', () => withEdge(async mf => {
  const fx = fixtures(); // presence_short expires three seconds after this call
  const deadline = Date.now() + 3_000;
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence_short, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  // Renewed under a new id before the deadline: no new snapshot, and b sees
  // no left or joined, so the upstream socket was kept.
  a.send(presenceJoin(5, fx.presence));
  await sleep(Math.max(0, deadline - Date.now()) + 500);
  assert.deepEqual([a.inbox, b.inbox, a.isClosed], [[], [], null]);
  b.send(presence(2, sealed(0xb1)));
  assert.deepEqual(decode(...await a.next()), [relayed(5, b.slot, sealed(0xb1))]);
  a.send(presence(5, sealed(0xa5)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0xa5))]);
  // The old id no longer carries frames.
  a.send(presence(1, sealed(0xa1)));
  await sleep(300);
  assert.deepEqual(b.inbox, []);
  // A join that is not renewed ends at its deadline, and the others see it leave.
  const short = Date.now() + 2_000;
  const c = await joined(mf, expiring(2_000).presence, 3);
  for (const device of [a, b]) assert.equal(decode(...await device.next())[0].event, 'joined');
  assert.deepEqual(decode(...await c.next(1, 6_000)), [{ type: 'refused', id: 3, reason: 'Expired' }]);
  assert.ok(Date.now() >= short, 'refused no earlier than the deadline');
  assert.deepEqual(decode(...await a.next()), [peers(5, 1, 'left', c.slot)]);
  assert.deepEqual(decode(...await b.next()), [peers(2, 1, 'left', c.slot)]);
  assert.equal(c.isClosed, null);
}));

test('a join at another epoch replaces the held one instead of renewing it', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  // The held join's upstream closes, so b sees a leave; the new epoch is not
  // the log's, so the new join is refused. Only the new id hears about it.
  a.send(presenceJoin(3, fx.presence_stale));
  assert.deepEqual(decode(...await a.next()), [{ type: 'refused', id: 3, reason: 'Epoch' }]);
  assert.deepEqual(decode(...await b.next()), [peers(2, 0, 'left', a.slot)]);
  a.send(presence(1, sealed(0xa1)));
  await sleep(300);
  assert.deepEqual([a.inbox, b.inbox, a.isClosed], [[], [], null]);
}));

test('a presence frame over 512 sealed bytes closes the socket with 1009; 512 is forwarded', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  a.send(presence(1, sealed(0x5a, 512)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0x5a, 512))]);
  a.send(presence(1, sealed(0x5b, 513)));
  assert.equal((await a.closed()).code, 1009);
  assert.deepEqual(decode(...await b.next()), [peers(2, 0, 'left', a.slot)]);
}));

test('a join forwards ten a second after a burst of twenty; over 100 drops a minute closes 1008', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  // The edge's clock stands still, so only the steps below refill the bucket.
  const t = Date.now();
  await control.edge({ frozen: t });
  for (let i = 0; i < 25; i++) a.send(presence(1, sealed(i)));
  assert.deepEqual(decode(...await b.next(20)), Array.from({ length: 20 }, (_, i) => relayed(2, a.slot, sealed(i))));
  // A fixed wait for frames that must not arrive.
  await sleep(300);
  assert.deepEqual(b.inbox, [], 'the 21st to 25th were dropped');
  await control.edge({ frozen: t + 1_000 });
  for (let i = 0; i < 12; i++) a.send(presence(1, sealed(100 + i)));
  assert.deepEqual(decode(...await b.next(10)), Array.from({ length: 10 }, (_, i) => relayed(2, a.slot, sealed(100 + i))));
  // 7 drops so far; 93 more make exactly 100 in the minute, which is allowed.
  for (let i = 0; i < 93; i++) a.send(presence(1, sealed(0xee)));
  // The edge handles a socket's frames in order, so this read's answer comes
  // after all 93 were counted.
  assert.equal((await ask(a, request('read', 3, fx.read_1_2)))[0].type, 'events');
  assert.deepEqual([b.inbox, a.isClosed], [[], null]);
  a.send(presence(1, sealed(0xef)));
  assert.deepEqual(Object.values(await a.closed()), [1008, 'presence rate']);
  assert.deepEqual(decode(...await b.next()), [peers(2, 0, 'left', a.slot)]);
  await control.edge({});
}));

// The device grants no credit: two 64-body reads use its initial window and
// a third (id 12) waits. Needs b3 ordered.
async function starve(device, fx) {
  for (const id of [10, 11]) {
    device.send(request('read', id, fx.read_bodies_b3_x64));
    assert.equal((await device.next(64, 15_000)).length, 64);
  }
  device.send(request('read', 12, fx.read_bodies_b3_x64));
  // A fixed wait for the read to reach its window wait; it sends nothing.
  await sleep(300);
}
async function orderB3(data, fx) {
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b3, fx.b3)), [{ type: 'staged', id: 2 }]);
  assert.equal((await ask(data, request('append', 3, fx.append_c3, fx.c3)))[0].type, 'acked');
}

test('presence is dropped, never queued, while the receiver has content waiting for window', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  await starve(b, fx);
  for (let i = 0; i < 5; i++) a.send(presence(1, sealed(0xc0 + i)));
  await sleep(500);
  assert.deepEqual(b.inbox, [], 'presence did not take window ahead of the waiting read');
  // Credit releases only the content; the dropped presence never follows.
  b.send(credit(64 * BODY_FRAME));
  const frames = await b.next(64, 15_000);
  assert.ok(frames.every(f => frameHeader(f).tag === 2 && frameHeader(f).id === 12));
  await sleep(300);
  assert.deepEqual(b.inbox, []);
  // With nothing waiting and window to spare, presence flows again.
  a.send(presence(1, sealed(0xd0)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0xd0))]);
}));

test('presence is dropped while a small frame waits for the budget, and flows again once it is sent', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  // Other devices' frames, stood in for, fill the frames half, reserve and
  // all, until a read of two events no longer fits but a presence frame does.
  const reader = await socket(mf, '/v1/data');
  const read = request('read', 1, fx.read_1_2);
  const { frames, limits } = await control.budget();
  const room = 2 * read.length + 16 * 1024;
  assert.equal((await control.budget({ frames: limits.frames - frames - room })).inFlight, limits.frames - frames - room);
  reader.send(read);
  await budgetUntil(control, budget => budget.waiting === 1, 'had the reader waiting');
  // a's frame is forwarded before its forged request is refused, and the
  // object sends a's leave to b after the frame. b's leave waits behind the
  // reader, and the frame is dropped, not sent ahead of the reader.
  a.send(presence(1, sealed(0xa1)));
  assert.deepEqual(await ask(a, request('read', 2, '00'.repeat(200))), [{ type: 'refused', id: 2, reason: 'Malformed' }]);
  a.ws.close();
  await budgetUntil(control, budget => budget.waiting === 2, "had b's leave waiting");
  assert.deepEqual(b.inbox, []);
  await control.budget({ frames: 0 });
  assert.equal(decode(...await reader.next())[0].type, 'events');
  assert.deepEqual(decode(...await b.next()), [peers(2, 0, 'left', a.slot)]);
  // Nothing waits now, so presence flows again.
  const c = await joined(mf, fx.presence, 3);
  assert.equal(decode(...await b.next())[0].event, 'joined');
  c.send(presence(3, sealed(0xc1)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, c.slot, sealed(0xc1))]);
}));

test('a join whose Peers back up behind content ends Unavailable; a rejoin gets a fresh roster', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const a = await joined(mf, fx.presence, 1);
  await starve(a, fx);
  // b's join and eight leave-and-rejoin rounds make 17 Peers for a; only 16 may wait.
  const b = await joined(mf, fx.presence, 2);
  for (let i = 0; i < 8; i++) {
    assert.deepEqual(await ask(b, presenceJoin(3 + 2 * i, fx.presence_stale)),
      [{ type: 'refused', id: 3 + 2 * i, reason: 'Epoch' }]);
    b.send(presenceJoin(4 + 2 * i, fx.presence));
    assert.equal(decode(...await b.next())[0].event, 'snapshot');
  }
  assert.deepEqual(decode(...await a.next()), [{ type: 'refused', id: 1, reason: 'Unavailable' }]);
  // Credit releases only the read; the ended join's Peers are never sent.
  a.send(credit(64 * BODY_FRAME));
  const frames = await a.next(64, 15_000);
  assert.ok(frames.every(f => frameHeader(f).tag === 2 && frameHeader(f).id === 12));
  await sleep(300);
  assert.deepEqual(a.inbox, []);
  a.send(presenceJoin(30, fx.presence));
  const [again] = decode(...await a.next());
  assert.deepEqual([again.type, again.id, again.event, again.others], ['peers', 30, 'snapshot', 1]);
}));

test('a Peers still waiting for window at the deadline it was queued under ends a renewed join Unavailable', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  await orderB3(data, fx);
  const a = await joined(mf, fx.presence, 1);
  await starve(a, fx);
  // Renewed to a short deadline, b's join queues a Peers for a under it; a
  // then renews again to a long one.
  const deadline = Date.now() + 2_000;
  a.send(presenceJoin(4, expiring(2_000).presence));
  // Fixed waits for the renewal and the Peers to arrive; neither sends anything.
  await sleep(300);
  const b = await joined(mf, fx.presence, 2);
  await sleep(300);
  a.send(presenceJoin(5, fx.presence));
  assert.deepEqual(decode(...await a.next(1, 6_000)), [{ type: 'refused', id: 5, reason: 'Unavailable' }]);
  assert.ok(Date.now() >= deadline, 'not before the deadline the Peers waited under');
  assert.deepEqual(decode(...await b.next()), [peers(2, 0, 'left', a.slot)]);
}));

test('an empty presence frame is dropped and the join goes on', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  a.send(presence(1, new Uint8Array(0)));
  a.send(presence(1, sealed(0xa1)));
  assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0xa1))]);
  // A fixed wait: nothing else is sent.
  await sleep(300);
  assert.deepEqual([a.inbox, b.inbox, a.isClosed], [[], [], null]);
}));

test('head notices reach a subscription, never a presence join on the same socket', () => withEdge(async mf => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  a.send(request('subscribe', 40, fx.subscribe, 1));
  await content(data, fx);
  assert.deepEqual(decode(...await a.next()), [{ type: 'head', id: 40, head: fx.c1_head, receipt: 'verified' }]);
  // The edge ends a join whose upstream sends anything but presence, so a
  // head notice on it would show here as Refused.
  await sleep(300);
  assert.deepEqual(a.inbox, []);
  const b = await joined(mf, fx.presence, 2);
  assert.deepEqual(decode(...await a.next()), [peers(1, 1, 'joined', b.slot)]);
}));

test('a log object restart ends presence joins Unavailable; rejoins get a fresh roster', () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  await control.log(fx.base, { action: 'abort' });
  assert.deepEqual(decode(...await a.next()), [{ type: 'refused', id: 1, reason: 'Unavailable' }]);
  assert.deepEqual(decode(...await b.next()), [{ type: 'refused', id: 2, reason: 'Unavailable' }]);
  a.send(presenceJoin(3, fixtures().presence));
  const [aAgain] = decode(...await a.next());
  assert.deepEqual([aAgain.id, aAgain.others, aAgain.event], [3, 0, 'snapshot']);
  b.send(presenceJoin(4, fixtures().presence));
  const [bAgain] = decode(...await b.next());
  assert.deepEqual([bAgain.id, bAgain.others, bAgain.event], [4, 1, 'snapshot']);
  assert.deepEqual(decode(...await a.next()), [peers(3, 1, 'joined', bAgain.slot)]);
  a.send(presence(3, sealed(0xa3)));
  assert.deepEqual(decode(...await b.next()), [relayed(4, aAgain.slot, sealed(0xa3))]);
  // Content was not affected.
  assert.equal((await ask(data, request('read', 5, fixtures().read_1_2)))[0].items.length, 1);
}));

// The append stops inside the log object after its R2 check, before
// ordering, or at its storage sync, after ordering.
for (const [where, hold, wait, release] of [['its R2 check', 'holdHead', 'waitForHead', 'releaseHead'],
  ['its storage sync', 'holdSync', 'waitForSync', 'releaseSync']])
test(`presence never waits on an append held at ${where}, and the append completes unaffected`, () => withSlowEdge(async (mf, control) => {
  const fx = fixtures();
  const data = await socket(mf, '/v1/data');
  await genesis(data, fx);
  assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b1, fx.b1)), [{ type: 'staged', id: 2 }]);
  const a = await joined(mf, fx.presence, 1);
  const b = await joined(mf, fx.presence, 2);
  assert.equal(decode(...await a.next())[0].event, 'joined');
  await control.log(fx.base, { [hold]: true });
  data.send(request('append', 3, fx.append_c1, fx.c1));
  await control.log(fx.base, { action: wait });
  for (let i = 0; i < 5; i++) {
    a.send(presence(1, sealed(0x10 + i)));
    assert.deepEqual(decode(...await b.next()), [relayed(2, a.slot, sealed(0x10 + i))]);
    b.send(presence(2, sealed(0x20 + i)));
    assert.deepEqual(decode(...await a.next()), [relayed(1, b.slot, sealed(0x20 + i))]);
  }
  assert.deepEqual(data.inbox, [], 'the append is still held');
  await control.log(fx.base, { action: release });
  assert.deepEqual(decode(...await data.next()), [acked(3, fx.base, fx.c1_id, fx.c1_head, 'verified')]);
  // Presence caused no append: the log holds the genesis and c1 only.
  assert.equal((await control.log(fx.base, { action: 'calls' })).append, 2);
  assert.equal((await ask(data, request('read', 4, fx.read_1_64)))[0].items.length, 2);
}));

test('a presence canary never reaches log object storage, R2 or Worker output', async () => {
  const output = [];
  const capture = stream => stream.on('data', chunk => output.push(chunk));
  const canary = Buffer.concat([Buffer.from('CANARY-LBL-7f3'), Buffer.from('CANARY-TXT-91a'),
    Buffer.alloc(16, 0x7f), Buffer.from('CANARY-HDL')]);
  const blob = new Uint8Array(393);
  blob.set(canary, 40);
  await withSlowEdge(async (mf, control) => {
    const fx = fixtures();
    const data = await socket(mf, '/v1/data');
    await genesis(data, fx);
    assert.deepEqual(await ask(data, request('stage', 2, fx.stage_b1, fx.b1)), [{ type: 'staged', id: 2 }]);
    const a = await joined(mf, fx.presence, 1);
    const b = await joined(mf, fx.presence, 2);
    assert.equal(decode(...await a.next())[0].event, 'joined');
    for (let i = 0; i < 20; i++) a.send(presence(1, blob));
    assert.equal((await b.next(20)).length, 20);
    // Malformed and oversized presence take the failure paths too.
    b.send(presence(2, new Uint8Array(600).fill(0x41)));
    assert.equal((await b.closed()).code, 1009);
    // A known diagnostic proves the capture sees Worker console output.
    await control.log(fx.base, { failSync: true });
    assert.deepEqual(await ask(data, request('append', 3, fx.append_c1, fx.c1)), [{ type: 'refused', id: 3, reason: 'Unavailable' }]);
    await control.log(fx.base, {});
    const stored = JSON.stringify(await control.log(fx.base, { action: 'dump' }));
    const keys = await (await mf.dispatchFetch('http://edge.invalid/control/r2', { method: 'POST' })).json();
    assert.ok(stored.includes(fx.genesis_commitment), 'the dump sees stored rows');
    const slots = [a.slot, b.slot].flatMap(slot =>
      [slot.toString(16).padStart(8, '0'), ...(slot >= 1_000_000 ? [String(slot)] : [])]);
    for (const needle of [canary.toString('hex'), hex(blob), 'CANARY', ...slots]) {
      assert.ok(!stored.toLowerCase().includes(needle.toLowerCase()), `stored ${needle}`);
      assert.ok(!keys.join().includes(needle), `R2 ${needle}`);
    }
    await sleep(300);
    const printed = Buffer.concat(output).toString('latin1');
    assert.match(printed, /test sync failure/);
    for (const needle of ['CANARY', canary.toString('hex'), canary.toString('base64').slice(0, 16), ...slots])
      assert.ok(!printed.includes(needle), `printed ${needle}`);
  }, undefined, { handleRuntimeStdio(stdout, stderr) { capture(stdout); capture(stderr); },
    handleStructuredLogs({ level, message }) { output.push(Buffer.from(`${level} ${message}\n`)); } });
});

// A loopback WebSocket backend that echoes every binary frame.
async function backend() {
  let refuse = false, upgrades = 0;
  const received = [], sockets = new Set(), raw = new Set();
  const http = createServer((req, res) => { res.writeHead(404); res.end(); });
  http.on('connection', s => { raw.add(s); s.on('close', () => raw.delete(s)); });
  const wss = new WebSocketServer({ noServer: true });
  http.on('upgrade', (req, s, head) => {
    upgrades++;
    if (refuse || req.url !== '/v1/channel') { s.destroy(); return; }
    wss.handleUpgrade(req, s, head, peer => {
      sockets.add(peer);
      peer.on('close', () => sockets.delete(peer));
      peer.on('message', (bytes, binary) => { received.push(hex(bytes)); peer.send(bytes, { binary }); });
    });
  });
  await new Promise(ok => http.listen(0, '127.0.0.1', ok));
  return {
    url: `http://127.0.0.1:${http.address().port}/v1/channel`,
    received, upgrades: () => upgrades, connections: () => sockets.size,
    refuse: value => { refuse = value; },
    drop: () => { for (const s of sockets) s.terminate(); },
    close: async () => { for (const s of sockets) s.terminate(); for (const s of raw) s.destroy(); wss.close(); await new Promise(ok => http.close(ok)); },
  };
}

test('authz_proxy_pins_one_backend', async () => {
  const a = await backend(), b = await backend(), c = await backend();
  const backends = [{ url: a.url, ready: true }, { url: b.url, ready: true }, { url: c.url, ready: false }];
  try {
    await withEdge(async mf => {
      const frame = n => new Uint8Array(64).fill(n);
      const x = await socket(mf, '/v1/authz');
      const y = await socket(mf, '/v1/authz');
      assert.equal(x.status, 101);
      assert.equal(y.status, 101);
      // Each connection is pinned to one ready backend; successive connections
      // take different ones, and an unready backend is never contacted.
      assert.deepEqual([a.connections(), b.connections(), c.upgrades()], [1, 1, 0]);
      x.send(frame(1));
      assert.deepEqual(await x.next(), [hex(frame(1))]);
      y.send(frame(2));
      assert.deepEqual(await y.next(), [hex(frame(2))]);
      const [xs, ys] = a.received.includes(hex(frame(1))) ? [a, b] : [b, a];
      assert.deepEqual([xs.received, ys.received], [[hex(frame(1))], [hex(frame(2))]]);
      // x's backend drops: x is closed, never moved, and nothing is replayed.
      xs.drop();
      assert.equal((await x.closed()).code, 1011);
      const z = await socket(mf, '/v1/authz');
      z.send(frame(3));
      assert.deepEqual(await z.next(), [hex(frame(3))]);
      assert.deepEqual([...a.received, ...b.received].sort(), [frame(1), frame(2), frame(3)].map(hex));
      for (const s of [y, z]) s.ws.close();
      // A backend that refuses the upgrade is skipped before any frame flows.
      a.refuse(true);
      for (let i = 0; i < 2; i++) {
        const w = await socket(mf, '/v1/authz');
        assert.equal(w.status, 101);
        w.send(frame(4 + i));
        assert.deepEqual(await w.next(), [hex(frame(4 + i))]);
        w.ws.close();
      }
      assert.ok(!a.received.includes(hex(frame(4))) && !a.received.includes(hex(frame(5))));
      // An oversized frame ends the session without reaching the backend.
      a.refuse(false);
      const big = await socket(mf, '/v1/authz');
      big.send(new Uint8Array(3_212_604));
      assert.equal((await big.closed()).code, 1009);
      assert.ok(![...a.received, ...b.received].some(r => r.length > 1000));
      // No ready backend accepts: 503.
      a.refuse(true);
      b.refuse(true);
      assert.equal((await socket(mf, '/v1/authz')).status, 503);
    }, { AUTHZ_BACKENDS: JSON.stringify(backends) });
  } finally { await Promise.all([a.close(), b.close(), c.close()]); }
});

test('an authz session outlives the upgrade timeout', async () => {
  const a = await backend();
  try {
    await withEdge(async mf => {
      const x = await socket(mf, '/v1/authz');
      assert.equal(x.status, 101);
      await sleep(2_600);
      assert.equal(x.isClosed, null, 'still open past the 2 s upgrade timeout');
      const frame = new Uint8Array(32).fill(7);
      x.send(frame);
      assert.deepEqual(await x.next(), [hex(frame)]);
      assert.equal(x.isClosed, null);
      x.ws.close();
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: a.url, ready: true }]) });
  } finally { await a.close(); }
});

// Sends 1 MiB frames one at a time through an authz session, each echoed, so
// each round trip carries 2 MiB through the edge.
const MIB = 1 << 20;
async function roundTrips(session, count) {
  for (let i = 0; i < count; i++) {
    const frame = new Uint8Array(MIB).fill(i + 1);
    session.send(frame);
    const [echo] = await session.next(1, 10_000);
    assert.ok(echo === hex(frame), `round trip ${i + 1} echoed`);
  }
}

test('a long authz session carrying more than 8 MiB at a low rate stays open', async () => {
  const a = await backend();
  try {
    await withSlowEdge(async (mf, control) => {
      const x = await socket(mf, '/v1/authz');
      assert.equal(x.status, 101);
      // 8 MiB in each rolling 60 s, 24 MiB over 122 s of the edge's clock.
      await roundTrips(x, 4);
      await control.edge({ ahead: 61_000 });
      await roundTrips(x, 4);
      await control.edge({ ahead: 122_000 });
      await roundTrips(x, 4);
      assert.equal(x.isClosed, null);
      x.ws.close();
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: a.url, ready: true }]) });
  } finally { await a.close(); }
});

test('an authz session above 8 MiB in 60 s closes with 1008 before forwarding', async () => {
  const a = await backend();
  try {
    await withSlowEdge(async mf => {
      const x = await socket(mf, '/v1/authz');
      await roundTrips(x, 4);
      x.send(new Uint8Array(MIB).fill(9));
      assert.equal((await x.closed()).code, 1008);
      assert.equal(a.received.length, 4, 'the frame over the rate is not forwarded');
    }, { AUTHZ_BACKENDS: JSON.stringify([{ url: a.url, ready: true }]) });
  } finally { await a.close(); }
});

test('relay_ttl_and_limits', async () => {
  const mf = new Miniflare({
    ...config(),
    scriptPath: resolve(root, 'tests/sync-worker/relay-fixture.mjs'),
    durableObjects: {
      LOG: { className: 'LogObject', useSQLite: true },
      RELAY: { className: 'FixtureRelay', useSQLite: true },
    },
  });
  const name = 'ab'.repeat(32);
  const TIME_START = 1_900_000_000_000;
  const control = (action, ...args) => mf.dispatchFetch(`http://edge.invalid/control?name=${name}`,
    { method: 'POST', body: JSON.stringify({ action, args }) }).then(r => r.json());
  const at = (side, index) => `http://edge.invalid/v1/pair/${name}?side=${side}&index=${index}`;
  const put = (side, index, body) => mf.dispatchFetch(at(side, index), { method: 'POST', body }).then(r => r.status);
  const get = async (side, index) => {
    const response = await mf.dispatchFetch(at(side, index));
    return { status: response.status, body: hex(await response.arrayBuffer()) };
  };
  const message = (n, size = 100) => new Uint8Array(size).fill(n);
  try {
    await control('control', { clock: TIME_START });
    assert.deepEqual(await get('show', 0), { status: 204, body: '' });
    assert.deepEqual(await control('inspect'), [], 'a read stores nothing');
    assert.equal(await put('show', 0, message(1)), 204);
    assert.deepEqual(await get('show', 0), { status: 200, body: hex(message(1)) });
    assert.deepEqual(await get('show', 0), { status: 200, body: hex(message(1)) }, 'reads are repeatable');
    assert.deepEqual(await get('join', 0), { status: 204, body: '' });
    // An exact resend is idempotent; other bytes or a gap conflict.
    assert.equal(await put('show', 0, message(1)), 204);
    assert.equal(await put('show', 0, message(9)), 409);
    assert.equal(await put('show', 2, message(2)), 409);
    for (let i = 1; i < 4; i++) assert.equal(await put('show', i, message(i + 1)), 204);
    assert.equal(await put('show', 4, message(5)), 429);
    // Each side has its own four.
    assert.equal(await put('join', 0, message(8192, 8192)), 204);
    assert.equal(await put('join', 1, message(1, 8193)), 413);
    assert.equal(await put('join', 1, new Uint8Array(0)), 400);
    for (const query of ['side=other&index=0', 'side=show&index=-1', 'side=show&index=x', 'side=show', 'index=0'])
      assert.equal((await mf.dispatchFetch(`http://edge.invalid/v1/pair/${name}?${query}`)).status, 400, query);
    assert.equal((await mf.dispatchFetch(at('show', 0), { method: 'PUT', body: 'x' })).status, 405);
    // Just before the TTL everything is served; at 300 s it is gone.
    await control('control', { clock: TIME_START + 299_999 });
    assert.equal((await get('show', 3)).status, 200);
    await control('control', { clock: TIME_START + 300_000 });
    assert.equal((await get('show', 0)).status, 410);
    assert.deepEqual(await control('inspect'), []);
    assert.deepEqual(await get('show', 0), { status: 204, body: '' });
    // The alarm also removes an idle relay at its TTL.
    await control('control', { clock: TIME_START + 400_000 });
    assert.equal(await put('join', 0, message(7)), 204);
    await control('control', { clock: TIME_START + 700_000 });
    await control('sweep');
    assert.deepEqual(await control('inspect'), []);
  } finally { await mf.dispose(); }
});

test('local config names the edge entry point and holds no secrets or deploy target', () => {
  const toml = readFileSync(resolve(root, 'services/sync-worker/wrangler.local.toml'), 'utf8');
  assert.match(toml, /^main = "src\/edge\.mjs"$/m);
  assert.match(toml, /^AUTHZ_BACKENDS = /m);
  for (const secret of ['RECEIPT_KEY', 'RECEIPT_CERT', 'HOSTING_ROOT'])
    assert.doesNotMatch(toml, new RegExp(`^\\s*${secret}\\s*=`, 'm'));
  for (const forbidden of [/account_id/, /^\s*routes?\s*=/m, /^\s*\[\[?routes?/m, /zone/, /workers_dev\s*=\s*true/])
    assert.doesNotMatch(toml, forbidden);
});
