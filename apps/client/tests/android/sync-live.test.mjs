import test from 'node:test';
import assert from 'node:assert/strict';
import { checkLiveEndpoint, scenarioNames, verifyReceipts } from './sync-live.mjs';

const endpoint = (fields = {}) => Buffer.from(JSON.stringify({ edge_url: 'https://sync.example.test',
  hosting_root: '11'.repeat(32), app_root: '22'.repeat(32), policy: '7b7d', policy_signature: '33'.repeat(64),
  max_lifetime_secs: 691200, max_uncertainty_secs: 0, build_floor: 1, appraisal: 'hardware', ...fields }));

test('a live run takes only a hardware HTTPS endpoint reachable from host and emulator', () => {
  assert.equal(checkLiveEndpoint(endpoint()).edge_url, 'https://sync.example.test');
  for (const fields of [{ appraisal: 'synthetic' }, { edge_url: 'http://sync.example.test' },
    { edge_url: 'https://127.0.0.1:8443' }, { edge_url: 'https://10.0.2.2:8443' }, { edge_url: 'https://localhost' }]) {
    assert.throws(() => checkLiveEndpoint(endpoint(fields)), /hardware HTTPS endpoint/, JSON.stringify(fields));
  }
  assert.throws(() => checkLiveEndpoint(Buffer.from('not json')), /hardware HTTPS endpoint/);
});

test('live runs replace the local-storage forgery case with receipt verification', () => {
  const local = scenarioNames(false), live = scenarioNames(true);
  assert.equal(local.at(-1), 'integrity_stop_shown');
  assert(!live.includes('integrity_stop_shown'), 'a live service has no local storage to rewrite');
  assert.deepEqual(live.slice(0, -1), local.slice(0, -1));
  assert.equal(live.at(-1), 'receipts_verify');
  for (const name of ['scan_pair_bootstrap', 'live_both_directions', 'airplane_mode_offline_then_reconnect',
    'update_with_unsynced_work']) assert(live.includes(name));
});

test('every stored receipt verifies to the exact stored position and head', async () => {
  const rows = [
    { log_kind: 1, log_id: 'aa', position: 7, head_hash: 'head7', receipt: 'r7', stopped_reason: null },
    { log_kind: 2, log_id: 'bb', position: 3, head_hash: 'head3', receipt: 'r3', stopped_reason: null },
    { log_kind: 1, log_id: 'cc', position: 0, head_hash: null, receipt: null, stopped_reason: null },
  ];
  const heads = { r7: { position: 7, hash: 'head7' }, r3: { position: 3, hash: 'head3' } };
  const checked = await verifyReceipts(rows, async receipt => heads[receipt]);
  assert.deepEqual(checked.map(c => c.position), [7, 3]);
  await assert.rejects(verifyReceipts(rows, async receipt => ({ ...heads[receipt], hash: 'other' })), /receipt head differs/);
  await assert.rejects(verifyReceipts([rows[2]], async () => ({})), /no stored receipts/);
  await assert.rejects(verifyReceipts([{ ...rows[0], stopped_reason: 3 }], async r => heads[r]), /stopped/);
  await assert.rejects(verifyReceipts(rows, async () => { throw Error('verify failed'); }), /verify failed/);
});
