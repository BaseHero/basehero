import { createRequire } from 'node:module';
import { mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(resolve(root, 'server/package.json'));
const { Miniflare } = require('miniflare');
const { build } = require('esbuild');
const args = process.argv.slice(2);
let persist, port, tinfoilUpstream;
const vars = { OPERATOR_TOKEN: 'local-operator', PEPPER: 'local-pepper',
  TINFOIL_API_KEY: 'local-tinfoil-key', TINFOIL_MODELS: 'deepseek-v4-1-flash', ALLOW_TEST_BYPASS: '1',
  GATEWAY_PER_MINUTE: '20', GATEWAY_PER_DAY: '500', GATEWAY_DAILY_COST_USD: '2' };
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--persist') persist = resolve(args[++i]);
  else if (arg === '--port') port = Number(args[++i]);
  else if (arg === '--tinfoil-upstream') tinfoilUpstream = new URL(args[++i]);
  else if (arg === '--var') {
    const pair = args[++i];
    const split = pair?.indexOf('=') ?? -1;
    if (split < 1) throw new Error('expected --var K=V');
    vars[pair.slice(0, split)] = pair.slice(split + 1);
  } else throw new Error(`unknown argument ${arg}`);
}
if (!persist || (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535))) {
  throw new Error('usage: local-server.mjs --persist DIR [--port P] [--tinfoil-upstream URL] [--var K=V]...');
}
if (tinfoilUpstream && (tinfoilUpstream.protocol !== 'http:' ||
    !['127.0.0.1', '[::1]', 'localhost'].includes(tinfoilUpstream.hostname))) {
  throw new Error('test upstream must be loopback HTTP');
}
// Miniflare binds port 0 atomically; a restarted server supplies its observed port.
port ??= 0;
await mkdir(persist, { recursive: true });
const bundle = resolve(persist, 'worker.mjs');
await build({ entryPoints: [resolve(root, 'server/src/index.ts')], outfile: bundle,
  bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:workers'] });
const mf = new Miniflare({
  modules: true, scriptPath: bundle, modulesRoot: persist,
  compatibilityDate: '2026-08-06', host: '127.0.0.1', port,
  durableObjects: Object.fromEntries(['ACCOUNT', 'BASE', 'DIRECTORY', 'INVITES', 'GATEWAY'].map(name =>
    [name, { className: `${name[0]}${name.slice(1).toLowerCase()}DO`, useSQLite: true }])),
  r2Buckets: ['FILES'], bindings: vars,
  outboundService: async request => {
    if (!tinfoilUpstream) return new Response(null, { status: 599 });
    const headers = new Headers(request.headers);
    headers.set('x-test-original-url', request.url);
    const url = new URL(new URL(request.url).pathname, tinfoilUpstream);
    return fetch(url, { method: request.method, headers, body: request.body,
      duplex: 'half', redirect: 'manual' });
  },
  durableObjectsPersist: resolve(persist, 'do'), r2Persist: resolve(persist, 'r2'),
});
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  try { await mf.dispose(); } catch (error) { console.error(error); process.exitCode = 1; }
  process.exit();
}
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.stdin.on('end', stop);
process.stdin.resume();
try {
  const url = await mf.ready;
  console.log(JSON.stringify({ url: url.origin }));
} catch (error) {
  console.error('local Worker startup failed:', error);
  await mf.dispose();
  process.exitCode = 1;
  process.exit();
}
