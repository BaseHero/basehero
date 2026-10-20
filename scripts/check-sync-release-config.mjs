// Local workerd load of the actual rendered config and bundled module closure.
// No Wrangler, telemetry, provider API, DNS or backend request is used.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Miniflare } from '../tests/crypto-worker/node_modules/miniflare/dist/src/index.js';
const file = resolve(process.argv[2]);
const config = JSON.parse(readFileSync(file, 'utf8'));
assert.equal(config.workers_dev, false);
assert.equal(config.preview_urls, false);
assert.equal(config.vars.RECEIPT_KEY, undefined);
assert.deepEqual(config.migrations, [{ tag: 'v1', new_sqlite_classes: ['LogObject', 'PairingRelay'] }]);
assert.deepEqual(config.rules, [{ type: 'CompiledWasm', globs: ['**/*.wasm'] }]);
const root = dirname(file);
const mf = new Miniflare({
  // Miniflare otherwise fetches Request.cf metadata from Cloudflare.
  cf: false,
  rootPath: root, modulesRoot: root, modules: true,
  scriptPath: resolve(root, config.main), compatibilityDate: config.compatibility_date,
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  durableObjects: Object.fromEntries(config.durable_objects.bindings.map(({ name, class_name }) =>
    [name, { className: class_name, useSQLite: true }])),
  r2Buckets: config.r2_buckets.map(({ binding }) => binding),
  bindings: config.vars,
});
try {
  assert.equal((await mf.dispatchFetch('http://edge.invalid/')).status, 404);
  assert.equal((await mf.dispatchFetch('http://edge.invalid/v1/data')).status, 426);
  const route = `http://edge.invalid/v1/pair/${'42'.repeat(32)}?side=show&index=0`;
  assert.equal((await mf.dispatchFetch(route, { method: 'POST', body: 'throwaway opaque test message' })).status, 204);
  assert.equal(await (await mf.dispatchFetch(route)).text(), 'throwaway opaque test message');
  assert.equal((await mf.dispatchFetch(route, { method: 'POST', body: 'different bytes' })).status, 409);
  console.log('rendered config loads in workerd; route and RELAY checks passed');
} finally { await mf.dispose(); }
