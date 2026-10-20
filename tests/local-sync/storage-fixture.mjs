// Test-only: one operation on a local stack's persisted log storage while
// its Worker is stopped (`storage-worker.mjs`). Prints the JSON answer.
// Usage: node storage-fixture.mjs STACK_DIR '{"op":…,"log":…,"args":[…]}'
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../crypto-worker/node_modules/miniflare/dist/src/index.js';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const [dir, request] = process.argv.slice(2);
if (!dir || !request) throw new Error('usage: storage-fixture.mjs STACK_DIR REQUEST');
const mf = new Miniflare({
  rootPath: root, modulesRoot: root, modules: true,
  scriptPath: resolve(root, 'tests/local-sync/storage-worker.mjs'),
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  compatibilityDate: '2026-07-01',
  durableObjects: { LOG: { className: 'LogObject', useSQLite: true } },
  r2Buckets: ['BODIES'],
  bindings: JSON.parse(readFileSync(resolve(dir, 'bindings.json'))),
  durableObjectsPersist: resolve(dir, 'workerd/do'), r2Persist: resolve(dir, 'workerd/r2'),
});
try {
  const response = await mf.dispatchFetch('http://fixture.invalid/', { method: 'POST', body: request });
  const answer = await response.text();
  if (!response.ok) throw new Error(`storage fixture HTTP ${response.status}: ${answer}`);
  console.log(answer);
} finally { await mf.dispose(); }
