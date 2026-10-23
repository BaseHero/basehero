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
  return result;
};
const clock = (mf, ms, log) => call(mf, 'control', [{ clock: ms }], [], log);
const inspect = (mf, log) => call(mf, 'inspect', [], [], log);
const r2 = (mf, ...args) => call(mf, 'r2', args);
const key = commitment => `b/${fx.base}/${commitment}`;
const ack = (head, id) => ({ position: head.position, hash: head.hash, eventId: id });
const genesisAck = ack(fx.genesis_head, fx.genesis_id);
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
  assert.deepEqual(await call(mf, 'controls', [0], [], fx.account), { items: [], endpoint: null });
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

test('populated legacy account-home order store refuses without relabeling other accounts', async () => {
  const path = mkdtempSync(join(tmpdir(), 'bh-account-order-legacy-'));
  temporary.push(path);
  let before;
  await withLog(async mf => {
    await clock(mf, fx.t0, fx.account);
    assert.deepEqual(await append(mf, fx.append_account_genesis, fx.account_genesis, fx.account),
      ack(fx.account_genesis_head, fx.account_genesis_id));
    assert.deepEqual(await call(mf, 'removeOrderMarker', [], [], fx.account), { ok: true });
    before = await inspect(mf, fx.account);
    assert.equal(before.meta.order_format, undefined);
    assert.equal(before.events.length, 1);
  }, path);
  await withLog(async mf => {
    assert.deepEqual(await call(mf, 'head', [], [], fx.account), { refused: 'Unavailable' });
    assert.deepEqual(await inspect(mf, fx.account), before, 'no relabel, reset or row rewrite');
    const healthy = '02' + 'f2'.repeat(32);
    await clock(mf, fx.t0, healthy);
    assert.deepEqual(await call(mf, 'controls', [0], [], healthy), { items: [], endpoint: null });
  }, path);
});

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

const directoryStore = (mf, permit, body, log = fx.account) =>
  call(mf, 'storeDirectoryEntry', [permit, body], [0, 1], log);
const directoryRead = (mf, after = null, permit = fx.directory_read, log = fx.account) =>
  call(mf, 'readDirectory', [permit, after], [0], log);

test('directory_entry_versions_only_increase', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_2, fx.directory_other), { ok: true });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { refused: 'Conflict' });
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_other }]);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_conflict, fx.directory_other), { refused: 'Conflict' });
}));

test('directory_retry_with_same_bytes_is_ok', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_conflict, fx.directory_other), { refused: 'Conflict' });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_other), { refused: 'Scope' });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_2, fx.directory_other), { ok: true });
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_other }]);
  assert.deepEqual(await r2(mf, 'list'), [`d/${fx.account}/${fx.directory_entry}/${fx.directory_other_digest}`]);
}));

test('directory_update_deletes_the_superseded_revision', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  const old = `d/${fx.account}/${fx.directory_entry}/${fx.directory_digest}`;
  const current = `d/${fx.account}/${fx.directory_entry}/${fx.directory_other_digest}`;
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  assert.equal(await r2(mf, 'head', old), 1024);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_2, fx.directory_other), { ok: true });
  assert.equal(await r2(mf, 'head', old), null);
  assert.equal(await r2(mf, 'head', current), 1024);
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_other }]);
}));

test('directory_retry_deletes_nothing', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  const current = `d/${fx.account}/${fx.directory_entry}/${fx.directory_digest}`;
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  assert.deepEqual(await r2(mf, 'list'), [current]);
  assert.equal(await r2(mf, 'head', current), 1024);
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_body }]);
}));

test('directory_read_of_a_just_superseded_revision_is_retryable', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  await directoryStore(mf, fx.directory_store_1, fx.directory_body);
  await call(mf, 'control', [{ supersedeOnDirectoryRead: { permit: fx.directory_store_2, body: fx.directory_other } }], [], fx.account);
  assert.deepEqual(await directoryRead(mf), { refused: 'Missing' });
  assert.deepEqual(await directoryRead(mf), { entries: [{ entry: fx.directory_entry, body: fx.directory_other }], more: false });
}));

test('directory_failed_sync_retries_without_exposing_new_revision_early', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  await directoryStore(mf, fx.directory_store_1, fx.directory_body);
  await call(mf, 'control', [{ failSync: true }], [], fx.account);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_2, fx.directory_other), { refused: 'Unavailable' });
  assert.deepEqual(await directoryRead(mf), { refused: 'Unavailable' });
  await call(mf, 'control', [{ failSync: false }], [], fx.account);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_2, fx.directory_other), { ok: true });
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_other }]);
}));

test('directory_ids_are_stored_verbatim', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await directoryStore(mf, fx.directory_store_1, fx.directory_body), { ok: true });
  const dump = await call(mf, 'dump', [], [], fx.account);
  assert.deepEqual(dump.rows.private_directory, [{ entry: fx.directory_entry, version: 1,
    digest: fx.directory_digest, len: 1024 }]);
  assert.deepEqual((await directoryRead(mf)).entries, [{ entry: fx.directory_entry, body: fx.directory_body }]);
  assert.deepEqual((await inspect(mf, fx.account)).events, []);
  assert.deepEqual(await r2(mf, 'list'), [`d/${fx.account}/${fx.directory_entry}/${fx.directory_digest}`]);
  assert.deepEqual(Object.keys(dump.rows).filter(name => name.includes('directory')), ['private_directory']);
}));

test('directory_read_pages_entries_in_entry_order', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  for (const { permit } of [...fx.directory_page].reverse())
    assert.deepEqual(await directoryStore(mf, permit, fx.directory_body), { ok: true });
  const first = await directoryRead(mf);
  assert.equal(first.more, true);
  assert.deepEqual(first.entries, fx.directory_page.slice(0, 64).map(({ entry }) => ({ entry, body: fx.directory_body })));
  assert.deepEqual(await directoryRead(mf, fx.directory_page[63].entry), {
    entries: fx.directory_page.slice(64).map(({ entry }) => ({ entry, body: fx.directory_body })), more: false });
  assert.deepEqual(await directoryRead(mf, fx.directory_page[65].entry), { entries: [], more: false });
  assert.deepEqual(await directoryRead(mf, 'ff'.repeat(32)), { entries: [], more: false });
}));

test('retire_deletes_only_the_named_bundle', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  await storeHome(mf);
  assert.deepEqual(await storeHome(mf, fx.home_store_other), { prefixDigest: '07'.repeat(32), bundleDigest: fx.home_digest });
  assert.deepEqual(await call(mf, 'retireHomeObjects', [fx.directory_retire], [0], fx.account), { ok: true });
  assert.deepEqual(await call(mf, 'privateObjects', [], [], fx.account), [
    { prefix_digest: '07'.repeat(32), bundle_digest: fx.home_digest, bundle: fx.home_bundle },
  ]);
  assert.deepEqual(await call(mf, 'retireHomeObjects', [fx.directory_retire], [0], fx.account), { ok: true });
}));

test('directory_permit_for_a_base_log_refused', () => withLog(async mf => {
  assert.deepEqual(await directoryRead(mf, null, fx.directory_read_base, fx.base), { refused: 'Malformed' });
  assert.deepEqual(await directoryStore(mf, fx.directory_store_base, fx.directory_body, fx.base), { refused: 'Malformed' });
}));

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
  assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_head, fx.c2_id));
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
    const items = method === 'controls' ? retry.result.items : retry.result;
    assert.equal(items.length, 1);
    assert.equal(items[0].commitment, fx.genesis_commitment);
    if (method === 'controls') assert.equal(retry.result.endpoint, fx.genesis_commitment);
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

test('same_nonce_different_original_cannot_retrieve_first_ack', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  const before = await inspect(mf);
  assert.deepEqual(await append(mf, fx.append_c1_other, fx.c1_other), { refused: 'NotStaged' });
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
  // The canonical route is the byte after version and base.
  const route = commitment => parseInt(commitment.slice(2 * 34, 2 * 35), 16);
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
    ack(fx.control_after_c1_head, fx.control_id));
  const state = await inspect(mf);
  assert.deepEqual(state.events.map(e => [e.position, e.control]), [[1, 1], [2, 0], [3, 1]]);
  assert.equal(state.events[2].commitment, fx.control_after_c1_commitment);
  assert.deepEqual(JSON.parse(state.meta.control), fx.control_after_c1_head);
  // Content still orders after the control, at the log head.
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_after_control_head, fx.c2_id));
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
  assert.deepEqual(await append(mf, fx.append_removal, fx.removal), ack(fx.removal_after_c1_head, fx.removal_id));
  const state = await inspect(mf);
  assert.deepEqual(state.events.map(e => [e.event_id, e.control]), [[fx.genesis_id, 1], [fx.c1_id, 0], [fx.removal_id, 1]]);
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
  // Wrong-route identity does not retrieve the content Ack; predecessor
  // admission refuses this stale control grant independently.
  assert.deepEqual(await append(mf, fx.append_c1_as_control, fx.c1), { refused: 'Predecessor' });
  assert.deepEqual(await append(mf, fx.append_control, fx.control), ack(fx.control_after_c1_head, fx.control_id));
  const before = await inspect(mf);
  // This orderer is content-blind: a signed permit for wrong-route bytes may
  // append them, but has a different ID and the full reader rejects its class.
  const wrongRoute = await append(mf, fx.append_control_as_content, fx.control);
  assert.equal(wrongRoute.position, before.events.length + 1);
  assert.notEqual(wrongRoute.eventId, fx.control_id);
  assert.equal((await inspect(mf)).events.length, before.events.length + 1);
  // Each on its own route is still the original Ack.
  assert.deepEqual(await append(mf, fx.append_c1_again, fx.c1), c1Ack);
  assert.deepEqual(await append(mf, fx.append_control, fx.control), ack(fx.control_after_c1_head, fx.control_id));
}));

test('controls_read_only_controls_after_position', () => withLog(async mf => {
  const controls = after => call(mf, 'controls', [after]);
  assert.deepEqual(await controls(0), { items: [], endpoint: null });
  await genesis(mf);
  await c1(mf);
  assert.equal((await append(mf, fx.append_control, fx.control)).position, 3);
  assert.deepEqual(await stage(mf, fx.stage_b2, fx.b2), { ok: true });
  assert.equal((await append(mf, fx.append_c2, fx.c2)).position, 4);
  const before = await inspect(mf);
  const genesisItem = { commitment: fx.genesis_commitment, event: fx.genesis };
  const controlItem = { commitment: fx.control_after_c1_commitment, event: fx.control };
  assert.deepEqual(await controls(0), { items: [genesisItem, controlItem], endpoint: fx.c2_after_control_commitment });
  assert.deepEqual(await controls(1), { items: [controlItem], endpoint: fx.c2_after_control_commitment });
  assert.deepEqual(await controls(2), { items: [controlItem], endpoint: fx.c2_after_control_commitment });
  assert.deepEqual(await controls(3), { items: [], endpoint: fx.c2_after_control_commitment });
  assert.deepEqual(await controls(9), { items: [], endpoint: fx.c2_after_control_commitment });
  for (const after of [-1, 1.5, '1', null, 2 ** 53])
    assert.deepEqual(await controls(after), { refused: 'Malformed' });
  assert.deepEqual(await inspect(mf), before);
}));

test('control page freezes its trailing content endpoint before an append', () => withLog(async mf => {
  await genesis(mf);
  await c1(mf);
  await call(mf, 'control', [{ appendOnControlRead: { permit: fx.append_control, event: fx.control } }]);
  const page = await call(mf, 'controls', [0]);
  assert.deepEqual(page, { items: [{ commitment: fx.genesis_commitment, event: fx.genesis }],
    endpoint: fx.c1_commitment });
  assert.equal((await inspect(mf)).events[2].commitment, fx.control_after_c1_commitment);
  assert.deepEqual(await call(mf, 'controls', [3, 4]), { refused: 'Missing' });
}));

test('sparse bounded control read uses the control partial index, not a content scan', () => withLog(async mf => {
  const plan = await call(mf, 'controlPlan', [1, 2 ** 53 - 1]);
  assert.ok(plan.some(row => row.detail.includes('USING INDEX events_controls')), JSON.stringify(plan));
}));

test('controls_read_only_controls_after_position: at most 64 in order', () => withLog(async mf => {
  await genesis(mf);
  for (const link of fx.chain) assert.equal((await append(mf, link.append, link.event)).refused, undefined);
  const all = [{ commitment: fx.genesis_commitment, event: fx.genesis },
    ...fx.chain.map(link => ({ commitment: link.commitment, event: link.event }))];
  assert.equal(all.length, 66);
  assert.deepEqual(await call(mf, 'controls', [0]), { items: all.slice(0, 64), endpoint: fx.chain.at(-1).commitment });
  assert.deepEqual(await call(mf, 'controls', [64]), { items: all.slice(64), endpoint: fx.chain.at(-1).commitment });
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

// An account log's staging body is served, so the service can read a
// rotation's body back before it permits the append; a base log's never is.
test('ordered_bodies_serves_account_staging_never_base_staging_or_reclaiming', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b1, fx.b1), { ok: true });
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.b1_commitment]]), [null]);
  assert.deepEqual(await append(mf, fx.append_c1, fx.c1), c1Ack);
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.b1_commitment]]), [1024]);
  await clock(mf, fx.t0, fx.account);
  assert.deepEqual(await stage(mf, fx.stage_b1_account, fx.b1, fx.account), { ok: true });
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.b1_commitment, fx.b2_commitment]], [], fx.account),
    [1024, null]);
  // Once a sweep marks it, it is not served, though its object remains.
  await clock(mf, fx.t1, fx.account);
  await call(mf, 'control', [{ crashAfterMark: true }], [], fx.account);
  assert.equal((await call(mf, 'sweep', [], [], fx.account)).status, 500);
  await clock(mf, fx.t1, fx.account);
  assert.deepEqual((await inspect(mf, fx.account)).bodies.map(b => b.state), ['reclaiming']);
  assert.equal(await r2(mf, 'head', `b/${fx.account}/${fx.b1_commitment}`), 1024);
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.b1_commitment]], [], fx.account), [null]);
}));

// No row with its object left behind: a reclaimed account body is never
// taken for an ordered one.
test('reclaim_deletes_the_object_before_its_row', () => withLog(async mf => {
  await clock(mf, fx.t0, fx.account);
  const object = `b/${fx.account}/${fx.b1_commitment}`;
  assert.deepEqual(await stage(mf, fx.stage_b1_account, fx.b1, fx.account), { ok: true });
  await clock(mf, fx.t1, fx.account);
  await call(mf, 'control', [{ crashAfterDelete: true }], [], fx.account);
  assert.equal((await call(mf, 'sweep', [], [], fx.account)).status, 500);
  await clock(mf, fx.t1, fx.account);
  assert.equal(await r2(mf, 'head', object), null);
  assert.deepEqual((await inspect(mf, fx.account)).bodies.map(b => b.state), ['reclaiming']);
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.b1_commitment]], [], fx.account), [null]);
  await call(mf, 'sweep', [], [], fx.account);
  assert.deepEqual((await inspect(mf, fx.account)).bodies, []);
  assert.equal(await r2(mf, 'head', object), null);
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
      assert.deepEqual(await append(mf, fx.append_c2, fx.c2), ack(fx.c2_head, fx.c2_id));
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
    { ...fx.account_genesis_head, eventId: fx.account_genesis_id });
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

const rekeyAck = ack(fx.rekey_head, fx.rekey_id);
test('attached_seal_set_is_retained_after_the_reclaim_window', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b3, fx.b3), { ok: true });
  assert.deepEqual(await stage(mf, fx.stage_s1, fx.s1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_rekey, fx.rekey), rekeyAck);
  // Both bodies were ordered with the event, in the same transaction.
  assert.deepEqual((await inspect(mf)).bodies.map(b => b.state), ['ordered', 'ordered']);
  // A day and an hour later the sweep reclaims neither.
  await clock(mf, fx.t1);
  await call(mf, 'sweep');
  assert.equal(await r2(mf, 'head', key(fx.s1_commitment)), 4096);
  assert.equal(await r2(mf, 'head', key(fx.b3_commitment)), 1024);
  assert.deepEqual(await call(mf, 'orderedBodies', [[fx.s1_commitment, fx.b3_commitment]]), [4096, 1024]);
  // The ordered control carries the epoch it names.
  assert.equal((await inspect(mf)).meta.epoch, fx.other_epoch);
}));

test('rekey_append_without_its_staged_seal_set_is_refused', () => withLog(async mf => {
  await genesis(mf);
  assert.deepEqual(await stage(mf, fx.stage_b3, fx.b3), { ok: true });
  const before = await inspect(mf);
  assert.deepEqual(await append(mf, fx.append_rekey, fx.rekey), { refused: 'NotStaged' });
  assert.deepEqual(await inspect(mf), before);
  assert.deepEqual(await call(mf, 'head'), fx.genesis_head);
  // Its own body stays staging, so it can still be ordered with its set.
  assert.deepEqual(await stage(mf, fx.stage_s1, fx.s1), { ok: true });
  assert.deepEqual(await append(mf, fx.append_rekey, fx.rekey), rekeyAck);
}));
