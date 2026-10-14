import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const config = resolve(root, 'dist/wrangler.jsonc');
const wrangler = resolve(root, 'node_modules/wrangler/bin/wrangler.js');
const requiredColumns = ['email', 'status', 'requested_at', 'consent_source', 'confirmed_at', 'stopped_at', 'confirmation_hash', 'confirmation_expires_at', 'last_sent_at'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Never echo child stdout/stderr or Error objects: Wrangler may include request data.
async function runChild({ kind, args = [], input, env = process.env }) {
  const command = kind === 'build' ? resolve(root, 'scripts/build.mjs') : wrangler;
  const result = spawnSync(process.execPath, [command, ...args], {
    cwd: root, env: { ...env, WRANGLER_SEND_METRICS: 'false' }, encoding: 'utf8',
    input, maxBuffer: 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe']
  });
  const expectingJSON = args.includes('--json') || (args[0] === 'secret' && args[1] === 'list');
  return { status: result.status ?? 1, stdout: kind === 'wrangler' && expectingJSON ? result.stdout : '' };
}

function checked(response, step) {
  if (response.status !== 0) throw Error(`${step} failed`);
  return response.stdout;
}
function parsed(response, step) {
  const output = checked(response, step);
  try { return JSON.parse(output); }
  catch { throw Error(`${step} returned invalid JSON`); }
}
function exactDatabase(list) {
  if (!Array.isArray(list)) throw Error('D1 list returned unexpected shape');
  const matches = list.filter(x => x.name === 'basehero-website');
  if (matches.length > 1) throw Error('Multiple databases with the exact website name');
  const id = matches[0]?.uuid;
  if (matches.length && (typeof id !== 'string' || !uuid.test(id))) throw Error('Website database ID invalid');
  return id;
}
function results(response, step) {
  const value = parsed(response, step);
  const entries = Array.isArray(value) ? value : value?.result;
  if (!Array.isArray(entries) || !entries.length || entries.some(x => x.success !== true)) throw Error(`${step} returned unsuccessful results`);
  return entries;
}

// Run only from the protected, manually dispatched setup workflow. Nothing sends mail or deploys.
export async function setup(env = process.env, run = runChild) {
  if (env.WEBSITE_LAUNCHED !== 'true' || env.SIGNUP_ENABLED !== 'false' || !env.CLOUDFLARE_ACCOUNT_ID || !env.CLOUDFLARE_API_TOKEN || !env.LETTERMINT_PROJECT_TOKEN) {
    throw Error('Setup held: launched website, disabled signup and approved account credentials required');
  }
  if (env.D1_DATABASE_ID && !uuid.test(env.D1_DATABASE_ID)) throw Error('Configured D1 ID invalid');
  const call = async (kind, args, input, overrides = {}) => {
    try { return await run({ kind, args, input, env: { ...env, ...overrides } }); }
    catch { throw Error(`${kind} operation failed`); }
  };
  // Keep the list/create boundary explicit: never create when an ID is already configured.
  const listDB = async () => exactDatabase(parsed(await call('wrangler', ['d1', 'list', '--json']), 'D1 list'));
  let id = await listDB();
  if (env.D1_DATABASE_ID && id !== env.D1_DATABASE_ID) throw Error('Configured D1 ID does not match the exact-name database');
  if (!id) {
    checked(await call('wrangler', ['d1', 'create', 'basehero-website', '--no-update-config']), 'D1 create');
    id = await listDB();
    if (!id) throw Error('Created database not found in account list');
  }
  checked(await call('build', [], undefined, { SIGNUP_ENABLED: 'false', D1_DATABASE_ID: id }), 'Disabled website build');
  const args = ['d1', 'execute', 'basehero-website', '--remote', '--config', config, '--yes', '--json'];
  // Wrangler prints non-JSON progress before --file output outside a TTY.
  // Exit status plus the following PRAGMA column check establish schema readiness.
  checked(await call('wrangler', [...args, '--file', resolve(root, 'schema.sql')]), 'D1 schema');
  const rows = results(await call('wrangler', [...args, '--command', 'PRAGMA table_info(subscribers)']), 'D1 schema inspection').flatMap(x => x.results ?? []);
  if (!requiredColumns.every(name => rows.some(row => row.name === name))) throw Error('Website D1 schema columns missing');
  const secrets = [['LETTERMINT_PROJECT_TOKEN', env.LETTERMINT_PROJECT_TOKEN], ['MAIL_FROM', env.MAIL_FROM], ['LETTERMINT_WEBHOOK_SECRET', env.LETTERMINT_WEBHOOK_SECRET]].filter(([, value]) => value);
  for (const [name, value] of secrets) checked(await call('wrangler', ['secret', 'put', name, '--config', config], value), `Worker secret ${name}`);
  const names = parsed(await call('wrangler', ['secret', 'list', '--config', config, '--format', 'json']), 'Worker secret names');
  if (!Array.isArray(names) || !secrets.every(([name]) => names.some(x => x.name === name && x.type === 'secret_text'))) throw Error('Installed Worker secret names could not be verified');
  return { databaseId: id, schemaReady: true, secrets: secrets.map(([name]) => name) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await setup();
    // Only public identifiers/names; never print child responses or a secret value.
    const summary = `Website D1 ID: ${result.databaseId}\nSchema checked: yes\nWorker secret names checked: ${result.secrets.join(', ')}\nSignup remains disabled; deploy separately after setting website-production D1_DATABASE_ID.\n`;
    if (process.env.GITHUB_STEP_SUMMARY) {
      const { appendFileSync } = await import('node:fs');
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
    } else console.log(summary);
  } catch (error) {
    console.error(`Signup setup failed: ${error.message}. No mail sent; site code not deployed; Worker secrets may have changed.`);
    process.exitCode = 1;
  }
}
