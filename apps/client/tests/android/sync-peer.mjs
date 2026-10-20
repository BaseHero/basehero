// Test-only process adapter. The peer uses production bh-host/Owner with a
// labelled software store and synthetic attestation, never Android fixture signup.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { createInterface } from 'node:readline';
import { mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { once } from 'node:events';
import path from 'node:path';

const root = process.env.SYNC_RUN;
assert(root && process.env.CARGO_TARGET_DIR && (process.env.LOCAL_STACK_DIR || process.env.SYNC_LIVE === '1'));
mkdirSync(path.join(root, 'peer'), { recursive: true, mode: 0o700 });
const peer = spawn(process.env.SYNC_PEER_BIN ?? path.join(process.env.CARGO_TARGET_DIR, 'debug/examples/local_sync_device'),
  [path.join(root, 'peer'), process.env.SYNC_HOST_ENDPOINT, 'plain'], { stdio: ['pipe', 'pipe', 'pipe'] });
const exited = once(peer, 'exit');
peer.stderr.on('data', data => appendFileSync(path.join(root, 'peer-stderr.log'), data));
let sequence = 0;
const pending = new Map();
const ready = new Promise(resolve => {
  createInterface({ input: peer.stdout }).on('line', line => {
    const value = JSON.parse(line);
    // Do not put the successful pairing text/SVG or signup recovery kit in logs.
    const logged = structuredClone(value);
    if (logged.ok?.qr) logged.ok.qr = '[omitted]';
    if (logged.ok?.svg) logged.ok.svg = '[omitted]';
    appendFileSync(path.join(root, 'peer-replies.jsonl'), JSON.stringify(logged) + '\n');
    if (value.event === 'ready') resolve(value);
    if (value.reply) {
      const waiter = pending.get(value.reply);
      pending.delete(value.reply);
      if (waiter) { clearTimeout(waiter.timer); value.err ? waiter.reject(Error(value.err)) : waiter.resolve(value.ok); }
    }
  });
});
peer.on('exit', (code, signal) => {
  for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(Error(`peer exited ${code}/${signal}`)); }
  pending.clear();
});
function call(op, args = {}) {
  const seq = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(seq); reject(Error(`peer ${op} timed out`)); }, 310_000);
    pending.set(seq, { resolve, reject, timer });
    peer.stdin.write(JSON.stringify({ seq, op, ...args }) + '\n');
  });
}
async function until(action, label, ms = 120_000) {
  let last;
  for (const end = Date.now() + ms; Date.now() < end; await new Promise(r => setTimeout(r, 250))) {
    last = await action(); if (last) return last;
  }
  throw Error(`timeout: ${label}; ${JSON.stringify(last)}`);
}
let server, runner, candidatePoll;
try {
  await ready;
  await call('signup', { password: 'ripple amber horizon nectar willow' });
  const identity = await call('open');
  await call('save', { window: 'main', note: identity.home, text: 'Existing peer note' });
  await until(async () => (await call('status')).view?.state === 'synced', 'peer existing note Accepted');
  const note = await call('note', { window: 'main', note: identity.home });
  assert.deepEqual(note.accepted_paragraphs, ['Existing peer note']);
  const shown = await call('show');
  assert.match(shown.svg ?? '', /^<svg\b/, 'show must expose the production host QR SVG, not a second QR implementation');
  if (process.env.SYNC_PROBE_ONLY === '1') {
    console.log('PASS production host SVG exposure');
  } else {
    writeFileSync(path.join(root, 'code.svg'), shown.svg, { mode: 0o600 });
    execFileSync('python3', ['apps/client/tests/android/camera-fixture.py', path.join(root, 'code.svg'), path.join(root, 'camera.png')], { stdio: 'inherit' });
    writeFileSync(path.join(root, 'identity.json'), JSON.stringify(identity, null, 2));
    const socket = path.join(root, 'peer.sock');
    server = createServer(connection => {
      createInterface({ input: connection }).on('line', async line => {
        try {
          const request = JSON.parse(line);
          const value = await call(request.op, { ...request, session: shown.session });
          connection.end(JSON.stringify({ ok: value }) + '\n');
        } catch (error) { connection.end(JSON.stringify({ error: String(error) }) + '\n'); }
      });
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
    // The scanner never manufactures this marker: the same native showing host
    // must observe a candidate for its own live session.
    candidatePoll = until(async () => {
      const state = await call('pair-status', { session: shown.session });
      if (state.state === 'failed') throw Error(`pairing failed: ${JSON.stringify(state)}`);
      if (state.state !== 'candidate') return false;
      writeFileSync(path.join(root, 'candidate'), JSON.stringify(state)); return true;
    }, 'showing candidate', 295_000);
    candidatePoll.catch(error => console.error(error));
    runner = spawn('bash', ['apps/client/tests/android/run-scan.sh', 'sync'], { stdio: 'inherit', env: {
      ...process.env, SCAN_IMAGE: path.join(root, 'camera.png'), SCAN_CANDIDATE: path.join(root, 'candidate'),
      SCAN_SCREENSHOTS: path.join(root, 'android'), SYNC_PEER_SOCKET: socket,
    } });
    const [code, signal] = await once(runner, 'exit');
    assert.equal(code, 0, `Android runner exit ${code}/${signal}`);
    await candidatePoll;
  }
} finally {
  server?.close();
  if (runner && runner.exitCode === null && runner.signalCode === null) runner.kill('SIGTERM');
  if (peer.exitCode === null && peer.signalCode === null) await call('quit');
  const [code, signal] = await exited;
  console.log(`PEER_EXIT=${code} SIGNAL=${signal}`);
  assert.equal(code, 0);
}
