// Live-endpoint variant of the Android sync acceptance: the same app flows against a
// deployed hardware-attested service instead of the local synthetic stack. A deployed
// service has no local storage to rewrite, so the forged-head case is replaced by
// verifying every stored receipt with the native peer.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const LOCAL = ['scan_pair_bootstrap', 'live_both_directions', 'airplane_mode_offline_then_reconnect',
  'update_with_unsynced_work', 'fold_while_incoming_edit', 'integrity_stop_shown'];

export function scenarioNames(live) {
  return live ? [...LOCAL.slice(0, -1), 'receipts_verify'] : LOCAL;
}

// Early refusal only; the app's build.rs remains the endpoint's authoritative parser.
export function checkLiveEndpoint(bytes) {
  let value;
  try { value = JSON.parse(bytes); } catch { value = null; }
  const url = typeof value?.edge_url === 'string' ? URL.parse(value.edge_url) : null;
  const local = ['127.0.0.1', '10.0.2.2', 'localhost', '[::1]'];
  assert(value?.appraisal === 'hardware' && url?.protocol === 'https:' && !local.includes(url.hostname),
    'a live run needs a hardware HTTPS endpoint reachable from host and emulator');
  return value;
}

// `rows` are an account container's log_progress rows; `verify` is the native peer's
// verify-receipt, which checks the hosting-root-signed receipt for that base.
export async function verifyReceipts(rows, verify) {
  const stored = rows.filter(row => row.receipt);
  assert(stored.length > 0, 'no stored receipts to verify');
  const checked = [];
  for (const row of stored) {
    assert.equal(row.stopped_reason, null, `log ${row.log_id} stopped`);
    const head = await verify(row.receipt, row);
    assert.deepEqual({ position: head?.position, hash: head?.hash }, { position: row.position, hash: row.head_hash },
      `receipt head differs from stored progress for log ${row.log_id}`);
    checked.push({ log_kind: row.log_kind, log_id: row.log_id, ...head });
  }
  return checked;
}

if (process.argv[2] === 'check-endpoint') {
  checkLiveEndpoint(readFileSync(process.argv[3]));
  console.log('PASS hardware HTTPS live endpoint');
}
