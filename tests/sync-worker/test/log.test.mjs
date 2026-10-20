import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../../crypto-worker/node_modules/miniflare/dist/src/index.js';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const fx = JSON.parse(readFileSync(resolve(root, 'tests/sync-worker/permit-fixtures.json')));
const temporary = [];
test.after(() => { for (const path of temporary) rmSync(path, { recursive: true, force: true }); });
function config(path) {
  const dir = path ?? mkdtempSync(join(tmpdir(), 'bh-log-do-'));
  if (!path) temporary.push(dir);
  return {
    rootPath: root, modulesRoot: root, modules: true,
    scriptPath: resolve(root, 'tests/sync-worker/log-fixture.mjs'),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2026-07-01',
    durableObjects: { LOG: { className: 'FixtureLog', useSQLite: true } },
    r2Buckets: ['BODIES'],
    bindings: { HOSTING_ROOT: fx.root },
    durableObjectsPersist: join(dir, 'do'),
    r2Persist: join(dir, 'r2'),
  };
}
async function call(mf, action, args = [], bytes = [], log = fx.base) {
  const response = await mf.dispatchFetch(`http://fixture.invalid/?log=${log}`, {
    method: 'POST', body: JSON.stringify({ action, args, bytes }),
  });
  const result = await response.json();
  if (response.status !== 200) return { status: response.status, ...result };
  return result;
}
const stage = (mf, permit, body, log) => call(mf, 'stage', [permit, body], [0, 1], log);
const append = async (mf, permit, event, log) => {
  const { commitment, ...result } = await call(mf, 'append', [permit, event], [0, 1], log);
  return result; // Existing legacy assertions concern only the old Ack fields.
};
const clock = (mf, ms, log) => call(mf, 'control', [{ clock: ms }], [], log);
const inspect = (mf, log) => call(mf, 'inspect', [], [], log);
const r2 = (mf, ...args) => call(mf, 'r2', args);
const key = commitment => `b/${fx.base}/${commitment}`;
const ack = (head, id) => ({ position: head.position, hash: head.hash, eventId: id });
const id = byte => byte.repeat(32);
const genesisAck = ack(fx.genesis_head, id('01'));
const c1Ack = ack(fx.c1_head, fx.c1_id);

async function withLog(run, path) {
  const mf = new Miniflare(config(path));
  try {
    await clock(mf, fx.t0);
    await run(mf);
  } finally { await mf.dispose(); }
}
async function genesis(mf) {
  assert.deepEqual(await append(mf, fx.append_genesis, fx.genesis), genesisAck);
}

const storeHome = (mf, permit = fx.home_store, bundle = fx.home_bundle, log = fx.account) =>
  call(mf, 'storeHomeObjects', [permit, bundle], [0, 1], log);
const homeAck = { prefixDigest: fx.home_prefix, bundleDigest: fx.home_digest };

test('private_home_objects_sync_retry_conflict_and_no_append', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  const traced = await call(mf, 'traced', ['storeHomeObjects', fx.home_store, fx.home_bundle], [1,2], fx.account);
  assert.deepEqual(traced, { result: homeAck, trace: ['sync', 'synced', 'resolved'] });
  assert.deepEqual(await storeHome(mf), homeAck);
  assert.deepEqual(await storeHome(mf, fx.home_store_conflict, fx.home_conflict), { refused: 'Conflict' });
  assert.deepEqual(await storeHome(mf, fx.home_store, fx.home_conflict), { refused: 'Scope' });
  const state = await inspect(mf, fx.account);
  assert.deepEqual(state.events, []);
  assert.deepEqual(state.bodies, []);
  assert.deepEqual(await call(mf, 'read', [1, 3], [], fx.account), []);
  assert.deepEqual(await call(mf, 'controls', [0], [], fx.account), []);
  assert.deepEqual(await r2(mf, 'list'), []);
  assert.deepEqual(await call(mf, 'privateObjects', [], [], fx.account),
    [{ prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest, bundle: fx.home_bundle }]);
  // Even the same digest must not overwrite different stored bytes.
  await call(mf, 'corruptPrivateBundle', [fx.home_prefix, fx.home_conflict], [1], fx.account);
  assert.deepEqual(await storeHome(mf), { refused: 'Conflict' });
}));

test('private_home_objects_failed_sync_no_ack_then_exact_retry', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  await call(mf, 'control', [{ failSync: true }], [], fx.account);
  assert.deepEqual(await storeHome(mf), { refused: 'Unavailable' });
  await call(mf, 'control', [{ failSync: false }], [], fx.account);
  assert.deepEqual(await storeHome(mf), homeAck);
  assert.equal((await call(mf, 'privateObjects', [], [], fx.account)).length, 1);
}));

test('private_home_objects_scope_and_deadline_at_use', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await storeHome(mf, fx.home_store, fx.home_bundle, fx.base), { refused: 'Scope' });
  const otherAccount = '02' + 'f1'.repeat(32);
  await clock(mf, fx.t0, otherAccount);
  assert.deepEqual(await storeHome(mf, fx.home_store, fx.home_bundle, otherAccount), { refused: 'Scope' });
  assert.deepEqual(await call(mf, 'privateObjects', [], [], otherAccount), []);
  assert.deepEqual(await storeHome(mf, fx.home_store_base), { refused: 'Malformed' });
  await clock(mf, fx.t0 + fx.window, fx.account);
  assert.deepEqual(await storeHome(mf), { refused: 'Expired' });
  assert.deepEqual(await call(mf, 'privateObjects', [], [], fx.account), []);
}));

test('private_home_objects_survive_workerd_restart_and_sweep_after_lost_response', async () => {
  const path = mkdtempSync(join(tmpdir(), 'bh-home-restart-'));
  temporary.push(path);
  await withLog(async mf => {
    await clock(mf, fx.t0, fx.account);
    assert.deepEqual(await storeHome(mf), homeAck); // client loses this response
  }, path);
  // New workerd process; no in-memory owner or authz cache survives.
  await withLog(async mf => {
    await clock(mf, fx.t0, fx.account);
    assert.deepEqual(await call(mf, 'privateObjects', [], [], fx.account),
      [{ prefix_digest: fx.home_prefix, bundle_digest: fx.home_digest, bundle: fx.home_bundle }]);
    assert.deepEqual(await storeHome(mf), homeAck);
    await clock(mf, fx.t1, fx.account);
    await call(mf, 'sweep', [], [], fx.account);
    assert.equal((await call(mf, 'privateObjects', [], [], fx.account)).length, 1);
    assert.deepEqual((await inspect(mf, fx.account)).events, []);
  }, path);
});

test('append_requires_staged_body', () => withLog(async mf => {
  await genesis(mf);
  const before = await inspect(mf);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), { refused: 'NotStaged' });
  assert.deepEqual(await inspect(mf), before);
  assert.deepEqual(await call(mf, 'head'), fx.genesis_head);
}));

test('ack_after_storage_sync', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  const traced = await call(mf, 'traced', ['append', fx.append_c1, fx.c1], [1, 2]);
  assert.deepEqual(traced, { result: { ...c1Ack, commitment: fx.c1_commitment }, trace: ['sync', 'synced', 'resolved'] });
  // A failed sync releases no Ack, though the ordered row may already be
  // committed; the exact retry then reports the original position.
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  await call(mf, 'control', [{ failSync: true }]);
  const failed = await call(mf, 'traced', ['append', fx.append_c2, fx.c2], [1, 2]);
  assert.deepEqual(failed, { result: { refused: 'Unavailable' }, trace: ['sync', 'resolved'] });
  await call(mf, 'control', [{ failSync: false }]);
  assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_head, id('04')));
  assert.equal((await inspect(mf)).events.length, 3);
}));

test('bounded reads expose immutable rows only after storage sync', () => withLog(async mf => {
  await genesis(mf);
  const before = await inspect(mf);
  for (const [method, args] of [['read', [1, 64]], ['controls', [0]]]) {
    await call(mf, 'control', [{ failSync: true }]);
    assert.deepEqual(await call(mf, 'traced', [method, ...args]),
      { result: { refused: 'Unavailable' }, trace: ['sync', 'resolved'] });
    await call(mf, 'control', [{ failSync: false }]);
    const retry = await call(mf, 'traced', [method, ...args]);
    assert.deepEqual(retry.trace, ['sync', 'synced', 'resolved']);
    assert.equal(retry.result.length, 1);
    assert.equal(retry.result[0].commitment, fx.genesis_commitment);
  }
  assert.deepEqual(await inspect(mf), before, 'reads allocate no position or writes');
}));

test('append_returns_stored_commitment_on_new_and_exact_retry', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  const first = await call(mf, 'append', [fx.append_c1, fx.c1], [0, 1]);
  assert.deepEqual(first, { ...c1Ack, commitment: fx.c1_commitment });
  assert.deepEqual(await call(mf, 'append', [fx.append_c1_again, fx.c1], [0, 1]), first);
  assert.equal((await inspect(mf)).events.length, 2);
}));

test('lost_response_same_bytes_same_ack', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  const first = await append(mf, fx.append_c1, fx.c1);
  assert.deepEqual(first, c1Ack);
  // The response is "lost"; a fresh permit retries the exact same bytes.
  assert.deepEqual(await append(mf, fx.append_c1_again, fx.c1), first);
  const state = await inspect(mf);
  assert.equal(state.events.length, 2);
  assert.equal(state.events[1].commitment, fx.c1_commitment);
  assert.deepEqual(await call(mf, 'head'), fx.c1_head);
}));

test('same_id_different_bytes_conflict', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  const before = await inspect(mf);
  assert.deepEqual(await append(mf, fx.append_c1_other, fx.c1_other), { refused: 'Conflict' });
  assert.deepEqual(await inspect(mf), before);
}));

test('expired_permit_at_use', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t0 + fx.window);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), { refused: 'Expired' });
  assert.equal((await inspect(mf)).events.length, 1);
  await clock(mf, fx.t0 + fx.window - 1);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
}));

test('expired_permit_at_use: the deadline is rechecked when ordering, after the R2 check', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t0 + fx.window - 1);
  await call(mf, 'control', [{ advanceAfterHead: 1 }]);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), { refused: 'Expired' });
  const state = await inspect(mf);
  assert.equal(state.events.length, 1);
  assert.deepEqual(state.bodies.map(b => b.state), ['staging']);
}));

test('epoch_mismatch_refused', () => withLog(async mf => {
  // An empty log has no epoch until its genesis control is ordered.
  assert.deepEqual(await append(mf, fx.append_content_on_empty, fx.c1), { refused: 'Epoch' });
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1_other_epoch, fx.c1), { refused: 'Epoch' });
  assert.equal((await inspect(mf)).events.length, 1);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
}));

test('control_predecessor_checked', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await append(mf, fx.append_control_stale, fx.control), { refused: 'Predecessor' });
  assert.equal((await inspect(mf)).events.length, 1);
  const ordered = await append(mf, fx.append_control, fx.control);
  assert.equal(ordered.position, 2);
  assert.equal((await inspect(mf)).events[1].commitment, fx.control_commitment);
  // Its exact retry reports the original outcome even though the head moved.
  assert.deepEqual(await append(mf, fx.append_control_stale, fx.control), ordered);
  assert.deepEqual(await append(mf, fx.append_genesis, fx.genesis), genesisAck);
  assert.equal((await inspect(mf)).events.length, 2);
}));

test('stored_commitment_route_matches_permit', () => withLog(async mf => {
  // The route is the commitment byte after the event digest.
  const route = commitment => parseInt(commitment.slice(2 * 138, 2 * 139), 16);
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  let events = (await inspect(mf)).events;
  // Each stored commitment equals the one ordered natively on that route.
  assert.deepEqual(events.map(e => [e.control, route(e.commitment), e.commitment]),
    [[1, 1, fx.genesis_commitment], [0, 0, fx.c1_commitment]]);
  await withLog(async other => {
    await genesis(other);
    assert.equal((await append(other, fx.append_control, fx.control)).position, 2);
    events = (await inspect(other)).events;
    assert.deepEqual([events[1].control, route(events[1].commitment), events[1].commitment],
      [1, 1, fx.control_commitment]);
  });
  await clock(mf, fx.t0, fx.account);
  const account = await append(mf, fx.append_account_genesis, fx.account_genesis, fx.account);
  assert.equal(account.position, 1);
  events = (await inspect(mf, fx.account)).events;
  assert.deepEqual([events[0].control, events[0].commitment], [1, fx.account_genesis_commitment]);
}));

const CLOSED = '00'.repeat(32);
async function c1(mf) {
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
}

test('control_predecessor_is_control_head', () => withLog(async mf => {
  await genesis(mf);
  await c1(mf);
  // Content moved the log head but not the control head.
  assert.deepEqual(await append(mf, fx.append_control_after_log_head, fx.control), { refused: 'Predecessor' });
  assert.equal((await inspect(mf)).events.length, 2);
  assert.deepEqual(await append(mf, fx.append_control, fx.control),
    ack(fx.control_after_c1_head, id('03')));
  const state = await inspect(mf);
  assert.deepEqual(state.events.map(e => [e.position, e.control]), [[1, 1], [2, 0], [3, 1]]);
  assert.equal(state.events[2].commitment, fx.control_after_c1_commitment);
  assert.deepEqual(JSON.parse(state.meta.control), fx.control_after_c1_head);
  // Content still orders after the control, at the log head.
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_after_control_head, id('04')));
  assert.equal((await inspect(mf)).events[3].commitment, fx.c2_after_control_commitment);
}));

test('two_controls_same_predecessor_one_wins', () => withLog(async mf => {
  await genesis(mf);
  await c1(mf);
  // Both name the genesis, the control head behind c1; the first ordered wins.
  assert.equal((await append(mf, fx.append_control, fx.control)).position, 3);
  assert.deepEqual(await append(mf, fx.append_control2, fx.control2), { refused: 'Predecessor' });
  assert.equal((await inspect(mf)).events.length, 3);
  // The loser may follow the winner once it names the new control head.
  assert.equal((await append(mf, fx.append_control2_after_control, fx.control2)).position, 4);
  assert.equal((await inspect(mf)).events[3].commitment, fx.control2_after_control_commitment);
}));

test('removal_control_closes_epoch', () => withLog(async mf => {
  await genesis(mf);
  assert.equal((await inspect(mf)).meta.epoch, fx.epoch);
  assert.equal((await append(mf, fx.append_removal, fx.removal)).position, 2);
  assert.equal((await inspect(mf)).meta.epoch, CLOSED);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  const before = await inspect(mf);
  // The old K, and a permit naming the closed epoch itself, are both refused.
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), { refused: 'Epoch' });
  assert.deepEqual(await append(mf, fx.append_c1_closed_epoch, fx.c1), { refused: 'Epoch' });
  assert.deepEqual(await inspect(mf), before);
}));

test('content_before_closure_ordered', () => withLog(async mf => {
  await genesis(mf);
  await c1(mf);
  // The removal names the control head, behind the content just ordered.
  assert.deepEqual(await append(mf, fx.append_removal, fx.removal), ack(fx.removal_after_c1_head, id('06')));
  const state = await inspect(mf);
  assert.deepEqual(state.events.map(e => [e.event_id, e.control]), [[id('01'), 1], [fx.c1_id, 0], [id('06'), 1]]);
  assert.equal(state.events[2].commitment, fx.removal_after_c1_commitment);
  // The content's exact retry still reports where it was ordered; new content is refused.
  assert.deepEqual(await append(mf, fx.append_c1_again, fx.c1), c1Ack);
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c2, fx.c2), { refused: 'Epoch' });
  assert.equal((await inspect(mf)).events.length, 3);
}));

test('exact_retry_route_must_match', () => withLog(async mf => {
  await genesis(mf);
  await c1(mf);
  // The ordered content's exact bytes under a control permit.
  assert.deepEqual(await append(mf, fx.append_c1_as_control, fx.c1), { refused: 'Conflict' });
  assert.deepEqual(await append(mf, fx.append_control, fx.control), ack(fx.control_after_c1_head, id('03')));
  const before = await inspect(mf);
  // The ordered control's exact bytes under a content permit.
  assert.deepEqual(await append(mf, fx.append_control_as_content, fx.control), { refused: 'Conflict' });
  assert.deepEqual(await inspect(mf), before);
  // Each on its own route is still the original Ack.
  assert.deepEqual(await append(mf, fx.append_c1_again, fx.c1), c1Ack);
  assert.deepEqual(await append(mf, fx.append_control, fx.control), ack(fx.control_after_c1_head, id('03')));
}));

test('controls_read_only_controls_after_position', () => withLog(async mf => {
  const controls = after => call(mf, 'controls', [after]);
  assert.deepEqual(await controls(0), []);
  await genesis(mf);
  await c1(mf);
  assert.equal((await append(mf, fx.append_control, fx.control)).position, 3);
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  assert.equal((await append(mf, fx.append_c2, fx.c2)).position, 4);
  const before = await inspect(mf);
  const genesisItem = { commitment: fx.genesis_commitment, event: fx.genesis };
  const controlItem = { commitment: fx.control_after_c1_commitment, event: fx.control };
  assert.deepEqual(await controls(0), [genesisItem, controlItem]);
  assert.deepEqual(await controls(1), [controlItem]);
  assert.deepEqual(await controls(2), [controlItem]);
  assert.deepEqual(await controls(3), []);
  assert.deepEqual(await controls(9), []);
  for (const after of [-1, 1.5, '1', null, 2 ** 53])
    assert.deepEqual(await controls(after), { refused: 'Malformed' });
  assert.deepEqual(await inspect(mf), before);
}));

test('controls_read_only_controls_after_position: at most 64 in order', () => withLog(async mf => {
  await genesis(mf);
  for (const link of fx.chain) assert.equal((await append(mf, link.append, link.event)).refused, undefined);
  const all = [{ commitment: fx.genesis_commitment, event: fx.genesis },
    ...fx.chain.map(link => ({ commitment: link.commitment, event: link.event }))];
  assert.equal(all.length, 66);
  assert.deepEqual(await call(mf, 'controls', [0]), all.slice(0, 64));
  assert.deepEqual(await call(mf, 'controls', [64]), all.slice(64));
}));

test('reclaim_vs_append_race: reclaim first, then restage and append once', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t1);
  await call(mf, 'sweep');
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), null);
  assert.deepEqual((await inspect(mf)).bodies, []);
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), { refused: 'NotStaged' });
  assert.deepEqual(await stage(mf, fx.stage_b1_late, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), c1Ack);
  assert.deepEqual(await append(mf, fx.append_c1_late_again, fx.c1), c1Ack);
  assert.equal((await inspect(mf)).events.length, 2);
}));

test('reclaim_vs_append_race: append first, the reclaim skips the ordered row', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  await clock(mf, fx.t1);
  await call(mf, 'sweep');
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), 1024);
  assert.deepEqual((await inspect(mf)).bodies.map(b => b.state), ['ordered']);
}));

test('reclaim_vs_append_race: a reclaim during the append R2 check refuses the append', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t1);
  await call(mf, 'control', [{ reclaimAfterHead: true }]);
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), { refused: 'NotStaged' });
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), null);
  const state = await inspect(mf);
  assert.equal(state.events.length, 1);
  assert.deepEqual(state.bodies, []);
}));

test('reclaim_vs_append_race: a reclaim and restage during the append R2 check refuse the append', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t1);
  // The append's HEAD sees the old object; then the sweep deletes it and a
  // restage inserts a fresh staging row of the same length, its put stalled.
  await call(mf, 'control', [{ restageAfterHead: { permit: fx.stage_b1_late, body: fx.b1 } }]);
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), { refused: 'NotStaged' });
  assert.deepEqual(await call(mf, 'failStalledPut'), { refused: 'Unavailable' });
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), null);
  const state = await inspect(mf);
  assert.equal(state.events.length, 1);
  assert.deepEqual(state.bodies.map(b => b.state), ['staging']);
  assert.deepEqual(await stage(mf, fx.stage_b1_late, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), c1Ack);
}));

test('reclaim_resumes_after_crash', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await clock(mf, fx.t1);
  await call(mf, 'control', [{ crashAfterMark: true }]);
  assert.equal((await call(mf, 'sweep')).status, 500);
  await clock(mf, fx.t1); // the aborted instance lost its test clock
  assert.deepEqual((await inspect(mf)).bodies.map(b => b.state), ['reclaiming']);
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), 1024);
  assert.deepEqual(await stage(mf, fx.stage_b1_late, fx.b1), { refused: 'Reclaiming' });
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), { refused: 'NotStaged' });
  await call(mf, 'sweep');
  assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), null);
  assert.deepEqual((await inspect(mf)).bodies, []);
  assert.deepEqual(await stage(mf, fx.stage_b1_late, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1_late, fx.c1), c1Ack);
}));

test('restart_preserves_order_and_index', async () => {
  const path = mkdtempSync(join(tmpdir(), 'bh-log-do-'));
  try {
    await withLog(async mf => {
      await genesis(mf);
      assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
      assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
    }, path);
    // A new workerd process over the same persisted DO SQLite and R2 files.
    await withLog(async mf => {
      assert.deepEqual(await call(mf, 'head'), fx.c1_head);
      assert.deepEqual(await call(mf, 'read', [1, 2]), [
        { commitment: fx.genesis_commitment, event: fx.genesis },
        { commitment: fx.c1_commitment, event: fx.c1 },
      ]);
      assert.deepEqual(await append(mf, fx.append_c1_again, fx.c1), c1Ack);
      assert.equal(await r2(mf, 'head', key(fx.b1_commitment)), 1024);
      assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
      assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_head, id('04')));
      assert.deepEqual((await inspect(mf)).events.map(e => e.position), [1, 2, 3]);
    }, path);
  } finally { rmSync(path, { recursive: true, force: true }); }
});

test('reads_do_not_change_head', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  const before = await inspect(mf);
  assert.deepEqual(await call(mf, 'head'), fx.c1_head);
  assert.equal((await call(mf, 'read', [1, 64])).length, 2);
  assert.deepEqual(await call(mf, 'read', [2, 2]), [{ commitment: fx.c1_commitment, event: fx.c1 }]);
  assert.deepEqual(await call(mf, 'read', [3, 66]), []);
  for (const range of [[0, 1], [1, 65], [2, 1], [1.5, 2], ['1', 2]])
    assert.deepEqual(await call(mf, 'read', range), { refused: 'Malformed' });
  assert.deepEqual(await inspect(mf), before);
  assert.deepEqual(await call(mf, 'head'), fx.c1_head);
}));

test('permits bind the root, the log object and the exact bytes', () => withLog(async mf => {
  await genesis(mf);
  const before = await inspect(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1_other_root, fx.b1), { refused: 'Scope' });
  assert.deepEqual(await stage(mf, fx.stage_b1_account, fx.b1), { refused: 'Scope' });
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b2), { refused: 'Scope' });
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2.slice(0, 2048)), { refused: 'Scope' });
  assert.deepEqual(await append(mf, fx.stage_b1, fx.c1), { refused: 'Scope' });
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1_other), { refused: 'Scope' });
  assert.deepEqual(await append(mf, fx.append_c1, 'ff'), { refused: 'Malformed' });
  assert.deepEqual((await inspect(mf)).events, before.events);
  assert.deepEqual(await r2(mf, 'list'), [key(fx.b1_commitment)]);
}));

test('append checks the exact staged R2 length before ordering', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  await r2(mf, 'put', key(fx.b1_commitment), fx.b1.slice(0, 1000));
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), { refused: 'NotStaged' });
  assert.equal((await inspect(mf)).events.length, 1);
}));

test('an account-home log uses the same object class', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await append(mf, fx.append_account_genesis, fx.account_genesis, fx.account),
    { position: 1, hash: fx.account_genesis_commitment.slice(-64), eventId: id('07') });
  assert.deepEqual(await append(mf, fx.append_genesis, fx.genesis, fx.account), { refused: 'Scope' });
  assert.deepEqual(await call(mf, 'head'), { position: 0, hash: '00'.repeat(32) });
}));

test('subscribers receive the current head and each new head', () => withLog(async mf => {
  const response = await mf.dispatchFetch(`http://fixture.invalid/subscribe?log=${fx.base}`, {
    headers: { Upgrade: 'websocket' },
  });
  assert.equal(response.status, 101);
  const socket = response.webSocket;
  const notices = [];
  let wake;
  socket.addEventListener('message', event => { notices.push(Buffer.from(event.data).toString('hex')); wake?.(); });
  socket.accept();
  const next = async count => { while (notices.length < count) await new Promise(r => { wake = r; }); };
  await next(1);
  assert.equal(notices[0], '00'.repeat(40));
  await genesis(mf);
  await next(2);
  assert.equal(notices[1], fx.genesis_head.position.toString(16).padStart(16, '0') + fx.genesis_head.hash);
  socket.close();
}));

// ---- presence --------------------------------------------------------------

// The object's presence messages to the edge: `0 || others:u16 || event:u8 ||
// slot:u32` for the roster, `1 || from:u32 || sealed` for a forwarded frame.
const EVENTS = ['snapshot', 'joined', 'left'];
const hex = bytes => Buffer.from(bytes).toString('hex');
function relay(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes[0] === 0 && bytes.length === 8)
    return { others: view.getUint16(1), event: EVENTS[bytes[3]], slot: view.getUint32(4) };
  if (bytes[0] === 1) return { from: view.getUint32(1), sealed: Buffer.from(bytes.subarray(5)).toString('hex') };
  return { unknown: Buffer.from(bytes).toString('hex') };
}
async function upgrade(mf, path, headers = {}) {
  const response = await mf.dispatchFetch(`http://fixture.invalid${path}?log=${fx.base}`, {
    headers: { Upgrade: 'websocket', ...headers },
  });
  if (response.status !== 101) return { status: response.status };
  const ws = response.webSocket;
  const inbox = [];
  let closed = null;
  let wake = () => {};
  ws.addEventListener('message', event => { inbox.push(new Uint8Array(event.data)); wake(); });
  ws.addEventListener('close', event => { closed = { code: event.code, reason: event.reason }; wake(); });
  ws.accept();
  const until = async (ready, ms = 5000) => {
    const end = Date.now() + ms;
    while (!ready()) {
      if (Date.now() > end) throw new Error('timed out waiting for the socket');
      await new Promise(done => { wake = done; setTimeout(done, 50); });
    }
  };
  return {
    status: 101, ws, inbox,
    send: bytes => ws.send(bytes),
    async next(count = 1) { await until(() => inbox.length >= count || closed); return inbox.splice(0, count); },
    async closed(ms) { await until(() => closed, ms); return closed; },
    get isClosed() { return closed; },
  };
}
// A presence socket at `epoch`, with its roster snapshot read.
async function present(mf, epoch = fx.epoch) {
  const socket = await upgrade(mf, '/presence', epoch === null ? {} : { 'X-Bh-Epoch': epoch });
  if (socket.status !== 101) return socket;
  const [snapshot] = (await socket.next()).map(relay);
  assert.equal(snapshot.event, 'snapshot');
  socket.slot = snapshot.slot;
  socket.others = snapshot.others;
  return socket;
}
const frame = (byte, size = 393) => new Uint8Array(size).fill(byte);
const settle = () => new Promise(done => setTimeout(done, 300));

test('presence joins only at the open epoch, and the roster and frames name random slots only', () => withLog(async mf => {
  // No genesis yet: the log has no epoch to join.
  assert.equal((await upgrade(mf, '/presence', { 'X-Bh-Epoch': fx.epoch })).status, 409);
  await genesis(mf);
  for (const epoch of [null, CLOSED, 'e2'.repeat(32), fx.epoch.toUpperCase()])
    assert.equal((await present(mf, epoch)).status, 409, String(epoch));
  const a = await present(mf);
  const b = await present(mf);
  assert.deepEqual([a.others, b.others], [0, 1]);
  assert.notEqual(a.slot, b.slot);
  assert.deepEqual((await a.next()).map(relay), [{ others: 1, event: 'joined', slot: b.slot }]);
  const attached = await call(mf, 'attachments');
  assert.deepEqual(attached.map(Object.keys), [['epoch', 'slot'], ['epoch', 'slot']]);
  assert.deepEqual(attached.map(x => x.epoch), [fx.epoch, fx.epoch]);
  assert.deepEqual(attached.map(x => x.slot).sort(), [a.slot, b.slot].sort());
  a.send(frame(0x11));
  assert.deepEqual((await b.next()).map(relay), [{ from: a.slot, sealed: hex(frame(0x11)) }]);
  await settle();
  assert.deepEqual(a.inbox, [], 'never back to its sender');
  // Oversized or text frames close only that socket.
  b.send(frame(0x12, 513));
  assert.equal((await b.closed()).code, 1009);
  assert.deepEqual((await a.next()).map(relay), [{ others: 0, event: 'left', slot: b.slot }]);
  assert.equal(a.isClosed, null);
}));

test('presence is relayed, never stored: SQL, key-value, R2, persisted files and console stay clean', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bh-presence-'));
  temporary.push(dir);
  const output = [];
  const capture = stream => stream.on('data', chunk => output.push(chunk));
  const canary = Buffer.concat([Buffer.from('CANARY-LBL-7f3'), Buffer.from('CANARY-TXT-91a'), Buffer.from('CANARY-HDL')]);
  const blob = new Uint8Array(393);
  blob.set(canary, 40);
  const mf = new Miniflare({ ...config(dir), handleRuntimeStdio(stdout, stderr) { capture(stdout); capture(stderr); },
    handleStructuredLogs({ level, message }) { output.push(Buffer.from(`${level} ${message}\n`)); } });
  let slots;
  try {
    await clock(mf, fx.t0);
    await genesis(mf);
    const a = await present(mf);
    const b = await present(mf);
    await a.next();
    for (let i = 0; i < 50; i++) a.send(blob);
    const received = (await b.next(50)).map(relay);
    assert.ok(received.every(r => r.from === a.slot && r.sealed === hex(blob)));
    slots = [a.slot, b.slot];
    const bySlot = list => list.sort((x, y) => x.slot - y.slot);
    assert.deepEqual(bySlot(await call(mf, 'attachments')),
      bySlot([{ epoch: fx.epoch, slot: a.slot }, { epoch: fx.epoch, slot: b.slot }]));
    // A known diagnostic proves the capture sees the object's console output.
    await call(mf, 'control', [{ failSync: true }]);
    assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { refused: 'Unavailable' });
    await call(mf, 'control', [{ failSync: false }]);
    const stored = JSON.stringify(await call(mf, 'dump'));
    assert.ok(stored.includes(fx.genesis_commitment), 'the dump sees stored rows');
    assert.deepEqual((await inspect(mf)).events.length, 1, 'no event from presence');
    const keys = JSON.stringify(await r2(mf, 'list'));
    for (const needle of [hex(blob), canary.toString('hex'), 'CANARY'])
      assert.ok(!stored.includes(needle) && !keys.includes(needle), `stored ${needle}`);
  } finally { await mf.dispose(); }
  // Nothing the object persisted on disk holds the canary.
  const files = [];
  const walk = path => { for (const entry of readdirSync(path, { withFileTypes: true })) {
    const full = join(path, entry.name);
    if (entry.isDirectory()) walk(full); else files.push(full);
  } };
  walk(dir);
  assert.ok(files.length > 0, 'persisted files exist');
  for (const file of files) assert.equal(readFileSync(file).indexOf(canary.subarray(0, 14)), -1, file);
  const printed = Buffer.concat(output).toString('latin1');
  assert.match(printed, /test sync failure/);
  const needles = ['CANARY', canary.toString('hex'), canary.toString('base64').slice(0, 16),
    ...slots.flatMap(slot => [slot.toString(16).padStart(8, '0'), ...(slot >= 1_000_000 ? [String(slot)] : [])])];
  for (const needle of needles) assert.ok(!printed.includes(needle), `printed ${needle}`);
});

test('head notices reach only subscriptions; an ordered control closes every presence socket', () => withLog(async mf => {
  await genesis(mf);
  const watch = await upgrade(mf, '/subscribe');
  assert.equal((await watch.next()).length, 1);
  const a = await present(mf);
  const b = await present(mf);
  await a.next();
  await c1(mf);
  assert.equal((await watch.next()).length, 1);
  await settle();
  assert.deepEqual([a.inbox, b.inbox], [[], []], 'no head notice on presence sockets');
  assert.deepEqual(await call(mf, 'presenceOpen'), [true, true]);
  assert.equal((await append(mf, fx.append_control, fx.control)).position, 3);
  // The object has closed and let go of both presence sockets at once.
  assert.deepEqual(await call(mf, 'presenceOpen'), []);
  assert.equal((await watch.next()).length, 1);
  assert.equal(watch.isClosed, null);
  // That control kept the epoch open: a fresh join has a fresh roster, and the
  // closed sockets forward nothing to it.
  const again = await present(mf);
  assert.equal(again.others, 0);
  a.send(frame(0x44));
  await settle();
  assert.deepEqual(again.inbox, []);
  // This harness's client reports the object's close only after about 10 s,
  // so the 4409 code itself is checked end to end in the edge tests.
  const late = await present(mf);
  assert.equal(late.others, 1);
  assert.deepEqual((await again.next()).map(relay), [{ others: 1, event: 'joined', slot: late.slot }]);
  again.send(frame(0x45));
  assert.deepEqual((await late.next()).map(relay), [{ from: again.slot, sealed: hex(frame(0x45)) }]);
  // An exact retry of the control orders nothing and closes nothing.
  assert.equal((await append(mf, fx.append_control, fx.control)).position, 3);
  await settle();
  assert.deepEqual([again.isClosed, late.isClosed], [null, null]);
}));

test('per-base presence buckets drop whole frames over 200 in or 5,000 sends a second', () => withLog(async mf => {
  await genesis(mf);
  const a = await present(mf);
  const b = await present(mf);
  await a.next();
  // The object's clock stands at t0 until moved.
  for (let i = 0; i < 250; i++) a.send(frame(i % 256));
  assert.equal((await b.next(200)).length, 200);
  await settle();
  assert.deepEqual(b.inbox, [], '201st to 250th dropped');
  await clock(mf, fx.t0 + 1_000);
  a.send(frame(0xaa));
  assert.deepEqual((await b.next()).map(relay), [{ from: a.slot, sealed: hex(frame(0xaa)) }]);
  // 29 receivers: 5,000 sends cover 172 frames; the 173rd would be partial,
  // so it and the rest are dropped whole.
  const more = [];
  for (let i = 0; i < 28; i++) more.push(await present(mf));
  await settle();
  for (const socket of [a, b, ...more]) socket.inbox.splice(0);
  await clock(mf, fx.t0 + 2_000);
  for (let i = 0; i < 200; i++) a.send(frame(0xbb));
  for (const socket of [b, ...more]) assert.equal((await socket.next(172)).length, 172);
  await settle();
  assert.deepEqual([b, ...more].map(s => s.inbox.length), Array(29).fill(0));
}));

test('a frame over the per-base in bucket is dropped before any socket attachment is read', () => withLog(async mf => {
  await genesis(mf);
  const a = await present(mf);
  const others = [];
  for (let i = 0; i < 9; i++) others.push(await present(mf));
  await settle();
  for (const socket of [a, ...others]) socket.inbox.splice(0);
  // The object's clock stands at t0: 200 frames empty the in bucket.
  for (let i = 0; i < 200; i++) a.send(frame(0x31));
  for (const socket of others) assert.equal((await socket.next(200)).length, 200);
  const before = await call(mf, 'attachmentReads');
  for (let i = 0; i < 50; i++) a.send(frame(0x32));
  // An oversized frame closes `a` after the 50 in order, and its leave is the
  // event that shows they were handled.
  a.send(frame(0x33, 513));
  for (const socket of others)
    assert.deepEqual((await socket.next()).map(relay), [{ others: 8, event: 'left', slot: a.slot }]);
  // Only the leave read attachments: the leaver's, and each other socket's once.
  assert.equal(await call(mf, 'attachmentReads') - before, 10);
}));

test('log entrypoint and local config expose no public route or deploy target', async () => {
  const mf = new Miniflare({ ...config(), scriptPath: resolve(root, 'services/sync-worker/src/log.mjs'),
    durableObjects: { LOG: { className: 'LogObject', useSQLite: true } } });
  try {
    const response = await mf.dispatchFetch('http://fixture.invalid/', { method: 'POST', body: '{}' });
    assert.equal(response.status, 404);
  } finally { await mf.dispose(); }
  const toml = readFileSync(resolve(root, 'services/sync-worker/wrangler.local.toml'), 'utf8');
  for (const forbidden of [/account_id/, /^\s*routes?\s*=/m, /^\s*\[\[?routes?/m, /zone/, /workers_dev\s*=\s*true/])
    assert.doesNotMatch(toml, forbidden);
  for (const binding of ['LOG', 'RELAY', 'BODIES']) assert.match(toml, new RegExp(`(name|binding) = "${binding}"`));
});
