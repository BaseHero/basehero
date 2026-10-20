// Local Miniflare/workerd adapter for wrangler.local.toml. Reads the disposable
// bindings from a private file, not a Cloudflare account or deploy environment.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from '../tests/crypto-worker/node_modules/miniflare/dist/src/index.js';

const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const [dir, host, port] = process.argv.slice(2);
if (!dir || !host || !port) throw new Error('usage: local-edge.mjs STACK_DIR HOST PORT');
const cfg = readFileSync(resolve(root, 'services/sync-worker/wrangler.local.toml'), 'utf8');
const value = (key) => {
  const match = cfg.match(new RegExp(`^${key} = "([^"\\n]+)"$`, 'm'));
  if (!match) throw new Error(`missing ${key} in local Worker config`);
  return match[1];
};
if (!cfg.includes('class_name = "LogObject"') || !cfg.includes('class_name = "PairingRelay"') || !cfg.includes('binding = "BODIES"'))
  throw new Error('local Worker bindings differ from runner');
const bindings = JSON.parse(readFileSync(resolve(dir, 'bindings.json'), 'utf8'));
const mf = new Miniflare({
  rootPath: root, modulesRoot: root, modules: true,
  scriptPath: resolve(root, 'services/sync-worker', value('main')),
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  compatibilityDate: value('compatibility_date'),
  host, port: Number(port),
  durableObjects: { LOG: { className: 'LogObject', useSQLite: true }, RELAY: { className: 'PairingRelay', useSQLite: true } },
  r2Buckets: ['BODIES'],
  bindings,
  durableObjectsPersist: resolve(dir, 'workerd/do'),
  r2Persist: resolve(dir, 'workerd/r2'),
});
try {
  const url = await mf.ready;
  writeFileSync(resolve(dir, 'edge-url'), `${url.origin}\n`, { mode: 0o600 });
  console.log(`local edge listening on ${url.origin}`);
  const stop = async () => { await mf.dispose(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
} catch (error) {
  console.error('local edge startup failed:', error);
  await mf.dispose();
  process.exitCode = 1;
}
