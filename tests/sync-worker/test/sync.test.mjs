import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../../crypto-worker/node_modules/miniflare/dist/src/index.js';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const fixture = JSON.parse(readFileSync(resolve(root, 'tests/sync-worker/fixtures.json')));
const temporary = [];
test.after(() => { for (const path of temporary) rmSync(path, { recursive: true, force: true }); });
const config = persist => {
  const path = persist ?? mkdtempSync(join(tmpdir(), 'bh-sync-do-'));
  if (!persist) temporary.push(path);
  return {
    rootPath: root, modulesRoot: root, modules: true,
    scriptPath: resolve(root, 'tests/sync-worker/fixture.mjs'),
    modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
    compatibilityDate: '2026-07-01',
    durableObjects: { BASE: { className: 'FixtureBase', useSQLite: true } },
    durableObjectsPersist: path,
  };
};
function op(kind, grant, options = {}) {
  return { kind, grant, binding: fixture.binding, ...options };
}
async function send(mf, action, payload = {}) {
  const response = await mf.dispatchFetch('http://fixture.invalid/', {
    method: 'POST', body: JSON.stringify({ action, ...payload }),
  });
  return { status: response.status, result: await response.json() };
}
const consume = (mf, request, time = fixture.time) => send(mf, 'consume', { request, time });
const inspect = async mf => (await send(mf, 'inspect')).result;
async function provision(mf) {
  assert.deepEqual(await send(mf, 'provision', { gate: fixture.gate }), { status: 200, result: { ok: true } });
}
function refused(reply) { assert.deepEqual(reply, { status: 403, result: { refusal: 'Unavailable' } }); }

test('native-signed grant for opaque genesis, lost response, fresh approval after runtime restart, exact read', async () => {
  const path = mkdtempSync(join(tmpdir(), 'bh-sync-do-'));
  let mf = new Miniflare(config(path));
  try {
    await provision(mf);
    const first = await consume(mf, op('append', fixture.append, { event: fixture.event }));
    assert.deepEqual(first, { status: 200, result: { ack: fixture.commitment } });
    // Simulate lost Ack by not using `first`, then dispose and recreate workerd
    // with the same local persisted DO SQL, not just a new connection.
    await mf.dispose();
    mf = new Miniflare(config(path));
    const replay = await consume(mf, op('append', fixture.replay, { event: fixture.event }));
    assert.deepEqual(replay, first);
    const read = await consume(mf, op('read', fixture.read, { objects: [fixture.digest] }));
    assert.deepEqual(read, { status: 200, result: { bodies: [fixture.event] } });
    const state = await inspect(mf);
    assert.equal(state.rows.length, 1);
    assert.equal(state.gate.position, 1);
    assert.equal(state.gate.sequence, 3);
    assert.equal(state.gate.last_ack, null); // last operation was a read
  } finally { await mf.dispose(); rmSync(path, { recursive: true, force: true }); }
});

test('expired/stale/wrong key/wrong response binding/mutated approval and conflicting retry do not consume', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    const before = await inspect(mf);
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event }), { earliest: 19, latest: 20 }));
    const mutated = fixture.append.slice(0, -2) + (fixture.append.endsWith('00') ? '01' : '00');
    refused(await consume(mf, op('append', mutated, { event: fixture.event })));
    assert.deepEqual(await inspect(mf), before);
    assert.equal((await consume(mf, op('append', fixture.append, { event: fixture.event }))).status, 200);
    const after = await inspect(mf);
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event })));
    refused(await consume(mf, op('append', fixture.wrong_key, { event: fixture.event })));
    refused(await consume(mf, op('append', fixture.replay, { event: fixture.event, binding: '00'.repeat(32) })));
    refused(await consume(mf, op('append', fixture.conflict, { event: fixture.conflicting_event })));
    assert.deepEqual(await inspect(mf), after);
  } finally { await mf.dispose(); }
});

test('malformed operation and historical body/index corruption refuse without moving gate', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event + '00' })));
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event.toUpperCase() })));
    refused(await consume(mf, op('append', fixture.append + '00', { event: fixture.event })));
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event }),
      { earliest: Number.MAX_SAFE_INTEGER + 1, latest: Number.MAX_SAFE_INTEGER + 1 }));
    assert.equal((await consume(mf, op('append', fixture.append, { event: fixture.event }))).status, 200);
    assert.deepEqual(await consume(mf, op('append', fixture.second_append, { event: fixture.second })),
      { status: 200, result: { ack: fixture.second_commitment } });
    assert.deepEqual(await consume(mf, op('append', fixture.third_append, { event: fixture.third })),
      { status: 200, result: { ack: fixture.third_commitment } });
    const beforeReplay = await inspect(mf);
    assert.equal(beforeReplay.gate.position, 3);
    assert.equal(beforeReplay.gate.sequence, 3);
    assert.equal(beforeReplay.rows.length, 3);
    // Row 1 is neither the head (3) nor the predecessor (2) head validation loads.
    assert.deepEqual(await consume(mf, op('append', fixture.replay_first_after_third, { event: fixture.event })),
      { status: 200, result: { ack: fixture.commitment } });
    const clean = await inspect(mf);
    assert.equal(clean.gate.position, 3);
    assert.equal(clean.gate.sequence, 4);
    assert.equal(clean.rows.length, 3);
    assert.equal(clean.gate.last_ack, fixture.commitment);
    assert.equal(clean.gate.last_approval, fixture.replay_first_after_third);
    refused(await consume(mf, op('read', fixture.read_first_after_third,
      { objects: [fixture.digest, fixture.digest] })));
    assert.deepEqual(await inspect(mf), clean);
    for (const column of ['event', 'commitment', 'event_id', 'event_digest']) {
      const original = clean.rows[0][column];
      const corrupt = original.slice(0, -2) + (original.endsWith('00') ? '01' : '00');
      assert.equal((await send(mf, 'tamper', { column, value: corrupt })).status, 200);
      const damaged = await inspect(mf);
      refused(await consume(mf, op('append', fixture.replay_first_after_clean, { event: fixture.event })));
      assert.deepEqual(await inspect(mf), damaged, `replay changed gate/outcome/rows after ${column} corruption`);
      refused(await consume(mf, op('read', fixture.read_first_after_third, { objects: [fixture.digest] })));
      assert.deepEqual(await inspect(mf), damaged, `read changed gate/outcome/rows after ${column} corruption`);
      assert.equal((await send(mf, 'tamper', { column, value: original })).status, 200);
    }
    assert.deepEqual(await inspect(mf), clean);
    assert.deepEqual(await consume(mf, op('read', fixture.read_first_after_third, { objects: [fixture.digest] })),
      { status: 200, result: { bodies: [fixture.event] } });
  } finally { await mf.dispose(); }
});

test('DO SQL trigger abort rolls back append, gate and replay index; racing grant consumes once', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    const before = await inspect(mf);
    assert.equal((await send(mf, 'breakWrite')).status, 200);
    refused(await consume(mf, op('append', fixture.append, { event: fixture.event })));
    assert.deepEqual(await inspect(mf), before);
  } finally { await mf.dispose(); }
  const racing = new Miniflare(config());
  try {
    await provision(racing);
    const results = await Promise.all([0, 1].map(() => consume(racing, op('append', fixture.append, { event: fixture.event }))));
    assert.deepEqual(results.map(r => r.status).sort(), [200, 403]);
    const state = await inspect(racing);
    assert.equal(state.rows.length, 1);
    assert.equal(state.gate.sequence, 1);
  } finally { await racing.dispose(); }
});

test('final linked Wasm has only audited libsodium imports', () => {
  const module = new WebAssembly.Module(readFileSync(resolve(root, 'services/sync-worker/sync_worker.wasm')));
  assert.deepEqual(WebAssembly.Module.imports(module).map(({ module, name, kind }) => `${module}.${name}:${kind}`).sort(),
    ['__assert_fail','abort','emscripten_asm_const_int','explicit_bzero'].map(name => `env.${name}:function`).sort());
});

test('production entrypoint has no public consume/provision route', async () => {
  const mf = new Miniflare({ ...config(), scriptPath: resolve(root, 'services/sync-worker/src/worker.mjs'),
    durableObjects: { BASE: { className: 'BaseLog', useSQLite: true } } });
  try {
    const response = await mf.dispatchFetch('http://fixture.invalid/', { method: 'POST', body: '{}' });
    assert.equal(response.status, 404);
  } finally { await mf.dispose(); }
});
