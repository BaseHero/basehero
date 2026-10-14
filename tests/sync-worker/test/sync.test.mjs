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
  assert.deepEqual(await send(mf, 'provision', { gate: fixture.gate, bodies: fixture.bodies }), { status: 200, result: { ok: true } });
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

test('detached body stages, the descriptor append requires it, and an exact body read returns it', async () => {
  const path = mkdtempSync(join(tmpdir(), 'bh-sync-do-'));
  let mf = new Miniflare(config(path));
  try {
    await provision(mf);
    // Commit the base genesis first; its referenced body is seeded.
    assert.equal((await consume(mf, op('append', fixture.append, { event: fixture.event }))).status, 200);
    assert.deepEqual(await consume(mf, op('stage', fixture.stage_after_genesis, { body: fixture.stage_body })),
      { status: 200, result: { commitment: fixture.stage_body_commitment } });
    // An event-read grant at the same gate cannot carry the body read.
    refused(await consume(mf, op('readbodies', fixture.read, { objects: [fixture.read_body_object] })));
    // A corrupt stored body under the reference cannot authorise the append.
    assert.equal((await send(mf, 'tamperBody', { column: fixture.stage_body_commitment, value: fixture.mismatched_body })).status, 200);
    refused(await consume(mf, op('append', fixture.append_body, { event: fixture.body_event })));
    assert.equal((await send(mf, 'tamperBody', { column: fixture.stage_body_commitment, value: fixture.stage_body })).status, 200);
    assert.deepEqual(await consume(mf, op('append', fixture.append_body, { event: fixture.body_event })),
      { status: 200, result: { ack: fixture.body_commitment } });
    const beforeRestart = await inspect(mf);
    assert.equal(beforeRestart.gate.position, 2);
    assert.equal(beforeRestart.gate.sequence, 3);
    assert.equal(beforeRestart.rows.length, 2);
    assert.equal(beforeRestart.bodies.length, fixture.bodies.length + 1);
    // A restart keeps both the staged body and the committed descriptor, and the
    // still-unconsumed read grant works against the persisted gate.
    await mf.dispose();
    mf = new Miniflare(config(path));
    const read = op('readbodies', fixture.read_bodies, { objects: [fixture.read_body_object] });
    assert.deepEqual(await consume(mf, read), { status: 200, result: { bodies: [fixture.stage_body] } });
    assert.equal((await inspect(mf)).gate.sequence, 4);
  } finally { await mf.dispose(); rmSync(path, { recursive: true, force: true }); }
});

test('a descriptor append without its referenced body is refused after the genesis', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    // Commit the real genesis first, so ordering cannot be the reason for refusal.
    assert.equal((await consume(mf, op('append', fixture.append, { event: fixture.event }))).status, 200);
    const before = await inspect(mf);
    refused(await consume(mf, op('append', fixture.append_missing_body, { event: fixture.missing_body_event })));
    assert.deepEqual(await inspect(mf), before);
  } finally { await mf.dispose(); }
});

test('an unknown request kind is refused and changes nothing', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    const before = await inspect(mf);
    refused(await consume(mf, op('Stage', fixture.stage, { body: fixture.stage_body })));
    assert.deepEqual(await inspect(mf), before);
  } finally { await mf.dispose(); }
});

test('wrong-size or mismatched bodies and replayed body grants refuse unchanged', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    const before = await inspect(mf);
    // A wrong-size body is refused before planning or approval.
    refused(await consume(mf, op('stage', fixture.stage, { body: '00' })));
    // A grant bound to the staged body cannot stage a different same-sized body,
    // and a tampered grant signature is refused.
    refused(await consume(mf, op('stage', fixture.stage, { body: fixture.mismatched_body })));
    refused(await consume(mf, op('stage', fixture.stage + '00', { body: fixture.stage_body })));
    assert.deepEqual(await inspect(mf), before);
    assert.equal((await consume(mf, op('stage', fixture.stage, { body: fixture.stage_body }))).status, 200);
    const afterStage = await inspect(mf);
    refused(await consume(mf, op('stage', fixture.stage, { body: fixture.stage_body })));
    assert.deepEqual(await inspect(mf), afterStage);
  } finally { await mf.dispose(); }
});

test('staging the same body twice is idempotent; restaging over a corrupt row is refused', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    assert.equal((await consume(mf, op('stage', fixture.stage, { body: fixture.stage_body }))).status, 200);
    assert.equal((await consume(mf, op('stage', fixture.stage_twice, { body: fixture.stage_body }))).status, 200);
    const after = await inspect(mf);
    assert.equal(after.bodies.filter(b => b.commitment === fixture.stage_body_commitment).length, 1);
    assert.equal(after.gate.sequence, 2);
    assert.equal(after.gate.position, 0);
    // Corrupt the stored row with a same-size different body; a restage must not
    // return a false staged receipt, and must leave the gate unchanged.
    assert.equal((await send(mf, 'tamperBody', { column: fixture.stage_body_commitment, value: fixture.mismatched_body })).status, 200);
    const damaged = await inspect(mf);
    refused(await consume(mf, op('stage', fixture.stage_thrice, { body: fixture.stage_body })));
    assert.deepEqual(await inspect(mf), damaged);
    assert.equal(damaged.gate.sequence, 2);
  } finally { await mf.dispose(); }
});

test('a corrupt stored body refuses a body read at a valid gate', async () => {
  const mf = new Miniflare(config());
  try {
    await provision(mf);
    assert.equal((await consume(mf, op('stage', fixture.stage, { body: fixture.stage_body }))).status, 200);
    // Same-size corruption: only the kernel re-derivation can catch it.
    assert.equal((await send(mf, 'tamperBody', { column: fixture.stage_body_commitment, value: fixture.mismatched_body })).status, 200);
    const damaged = await inspect(mf);
    refused(await consume(mf, op('readbodies', fixture.read_bodies_after_stage, { objects: [fixture.read_body_object] })));
    assert.deepEqual(await inspect(mf), damaged);
  } finally { await mf.dispose(); }
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
