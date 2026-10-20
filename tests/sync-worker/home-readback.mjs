// Invoked only with the disposable local stack stopped. No public read route.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../crypto-worker/node_modules/miniflare/dist/src/index.js';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const dir = process.argv[2];
if (!dir) throw new Error('usage: home-readback.mjs STACK_DIR');
const expected = JSON.parse(readFileSync(resolve(dir, 'home-probe.json')));
const mf = new Miniflare({
  rootPath: root, modulesRoot: root, modules: true,
  scriptPath: resolve(root, 'tests/sync-worker/home-readback-fixture.mjs'),
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  compatibilityDate: '2026-07-01',
  durableObjects: { LOG: { className: 'LogObject', useSQLite: true } },
  r2Buckets: ['BODIES'],
  bindings: JSON.parse(readFileSync(resolve(dir, 'bindings.json'))),
  durableObjectsPersist: resolve(dir, 'workerd/do'), r2Persist: resolve(dir, 'workerd/r2'),
});
try {
  const response = await mf.dispatchFetch(`http://fixture.invalid/?log=${expected.log}`);
  assert.equal(response.status, 200);
  const actual = await response.json();
  assert.deepEqual(actual, {
    objects: [{ prefix_digest: expected.prefix, bundle_digest: expected.digest, bundle: expected.bundle }],
    positions: 3, bodies: 0,
  });
  writeFileSync(resolve(dir, 'home-readback.bundle'), Buffer.from(actual.objects[0].bundle, 'hex'), { mode: 0o600 });
  console.log('home-readback: new workerd, one exact immutable bundle, three public positions, no body route');
} finally { await mf.dispose(); }
