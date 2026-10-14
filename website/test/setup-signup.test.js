import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setup } from '../scripts/setup-signup.mjs';

const ID = '00000000-0000-4000-8000-000000000001';
const OTHER = '00000000-0000-4000-8000-000000000002';
const base = { WEBSITE_LAUNCHED: 'true', SIGNUP_ENABLED: 'false', CLOUDFLARE_ACCOUNT_ID: 'fake-account', CLOUDFLARE_API_TOKEN: 'fake-cf', LETTERMINT_PROJECT_TOKEN: 'fake-website-token' };
const db = (uuid = ID) => ({ name: 'basehero-website', uuid });
const columns = ['email', 'status', 'requested_at', 'consent_source', 'confirmed_at', 'stopped_at', 'confirmation_hash', 'confirmation_expires_at', 'last_sent_at'];

function runner(initial = []) {
  const calls = [];
  let databases = initial;
  return {
    calls,
    run: async ({ kind, args, input, env }) => {
      calls.push({ kind, args, input, env });
      if (kind === 'build') return { status: 0, stdout: '' };
      if (args[0] === 'd1' && args[1] === 'list') return { status: 0, stdout: JSON.stringify(databases) };
      if (args[0] === 'd1' && args[1] === 'create') { databases = [db()]; return { status: 0, stdout: '' }; }
      if (args[0] === 'd1' && args[1] === 'execute' && args.includes('--file')) return { status: 0, stdout: '├ Checking if file needs uploading\n├ 🌀 Uploading schema.sql\n' + JSON.stringify([{ success: true }]) };
      if (args[0] === 'd1' && args[1] === 'execute' && args.includes('--command')) return { status: 0, stdout: JSON.stringify([{ success: true, results: columns.map(name => ({ name })) }]) };
      if (args[0] === 'secret' && args[1] === 'put') return { status: 0, stdout: 'SECRET SHOULD NOT BE REPORTED' };
      if (args[0] === 'secret' && args[1] === 'list') return { status: 0, stdout: JSON.stringify([{ name: 'LETTERMINT_PROJECT_TOKEN', type: 'secret_text' }, { name: 'MAIL_FROM', type: 'secret_text' }, { name: 'LETTERMINT_WEBHOOK_SECRET', type: 'secret_text' }]) };
      throw Error(`Unexpected command: ${args}`);
    }
  };
}

for (const env of [
  { ...base, SIGNUP_ENABLED: 'true' }, { ...base, SIGNUP_ENABLED: undefined },
  { ...base, WEBSITE_LAUNCHED: undefined }, { ...base, CLOUDFLARE_ACCOUNT_ID: undefined },
  { ...base, CLOUDFLARE_API_TOKEN: undefined }, { ...base, LETTERMINT_PROJECT_TOKEN: undefined }
]) {
  test('setup refuses missing or unsafe production prerequisites before child calls', async () => {
    const f = runner();
    await assert.rejects(setup(env, f.run));
    assert.equal(f.calls.length, 0);
  });
}

test('reuses only exact-name DB; applies idempotent schema; installs Website token by stdin', async () => {
  const f = runner([{ name: 'basehero-website-old', uuid: OTHER }, db()]);
  const result = await setup({ ...base, D1_DATABASE_ID: ID }, f.run);
  assert.equal(result.databaseId, ID);
  assert.deepEqual(result.secrets, ['LETTERMINT_PROJECT_TOKEN']);
  assert.equal(f.calls.some(c => c.args?.includes('create')), false);
  const schema = f.calls.find(c => c.args?.includes('--file'));
  assert(schema.args.includes('--remote') && schema.args.includes('--yes'));
  assert.match(schema.args.join(' '), /schema\.sql/);
  assert(f.calls.some(c => c.kind === 'build' && c.env.D1_DATABASE_ID === ID && c.env.SIGNUP_ENABLED === 'false'));
  const puts = f.calls.filter(c => c.args?.[0] === 'secret' && c.args[1] === 'put');
  assert.equal(puts.length, 1);
  assert.equal(puts[0].input, base.LETTERMINT_PROJECT_TOKEN);
  assert.equal(puts[0].args[2], 'LETTERMINT_PROJECT_TOKEN');
  assert.equal(f.calls.some(c => /deploy|send/.test(c.args?.join(' ') ?? '')), false);
  assert.doesNotMatch(JSON.stringify(result), /fake-|SECRET SHOULD NOT BE REPORTED/);
});

test('creates once without config rewrite, re-lists and can safely retry', async () => {
  const f = runner();
  assert.equal((await setup(base, f.run)).databaseId, ID);
  assert.equal((await setup(base, f.run)).databaseId, ID);
  assert.equal(f.calls.filter(c => c.args?.[1] === 'create').length, 1);
  assert.equal(f.calls.filter(c => c.args?.includes('--file')).length, 2);
  assert(f.calls.find(c => c.args?.[1] === 'create').args.includes('--no-update-config'));
});

test('refuses duplicate or mismatched IDs before build/schema/secret mutation', async () => {
  for (const [initial, env] of [ [[db(), db(OTHER)], base], [[db(OTHER)], { ...base, D1_DATABASE_ID: ID }], [[], { ...base, D1_DATABASE_ID: ID }] ]) {
    const f = runner(initial);
    await assert.rejects(setup(env, f.run));
    assert(f.calls.every(c => c.args?.[1] === 'list'));
  }
});

test('optional verified secrets use stdin only, fail closed on CLI errors', async () => {
  const f = runner([db()]);
  const env = { ...base, MAIL_FROM: 'Fake Sender <sender@example.invalid>', LETTERMINT_WEBHOOK_SECRET: 'fake-webhook' };
  const result = await setup(env, f.run);
  assert.deepEqual(result.secrets, ['LETTERMINT_PROJECT_TOKEN', 'MAIL_FROM', 'LETTERMINT_WEBHOOK_SECRET']);
  for (const c of f.calls.filter(c => c.args?.[1] === 'put')) {
    assert.equal(c.input, env[c.args[2]]);
    assert.doesNotMatch(c.args.join(' '), /fake-|sender@example/);
  }
  const failure = runner([db()]);
  await assert.rejects(setup(env, async request => {
    const response = await failure.run(request);
    if (request.args?.[1] === 'put') return { status: 1, stdout: 'fake-website-token', stderr: 'fake-webhook' };
    return response;
  }), e => { assert.doesNotMatch(e.message, /fake-|sender@example/); return true; });
  await assert.rejects(setup(base, async request => {
    if (request.args?.[1] === 'list' && request.args?.[0] === 'd1') throw Error('fake-cf secret in child error');
    return failure.run(request);
  }), e => { assert.doesNotMatch(e.message, /fake-cf/); return true; });
  const brokenSchema = runner([db()]);
  await assert.rejects(setup(base, async request => {
    if (request.args?.includes('--file')) return { status: 1, stdout: 'fake-website-token', stderr: 'fake-webhook' };
    return brokenSchema.run(request);
  }), e => { assert.match(e.message, /D1 schema failed/); assert.doesNotMatch(e.message, /fake-/); return true; });
  assert.equal(brokenSchema.calls.some(c => c.args?.[1] === 'put'), false);
});

test('CLI failure reports stage without leaking child output or claiming no Worker mutation', t => {
  const dir = mkdtempSync(join(tmpdir(), 'website-setup-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const preload = join(dir, 'fake-child.mjs');
  writeFileSync(preload, `import child from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
child.spawnSync = (_, args) => {
  const cmd = args.slice(1);
  if (args[0].endsWith('build.mjs')) return { status: 0, stdout: '' };
  if (cmd[0] === 'd1' && cmd[1] === 'list') return { status: 0, stdout: JSON.stringify([{ name: 'basehero-website', uuid: '${ID}' }]) };
  if (cmd[1] === 'execute' && cmd.includes('--file')) return { status: 0, stdout: '├ Checking if file needs uploading\\n' + JSON.stringify([{ success: true }]) };
  if (cmd[1] === 'execute' && cmd.includes('--command')) return { status: 0, stdout: JSON.stringify([{ success: true, results: ${JSON.stringify(columns)}.map(name => ({ name })) }]) };
  if (cmd[0] === 'secret' && cmd[1] === 'put') return { status: 1, stdout: 'fake-website-token', stderr: 'fake-webhook' };
  throw Error('unexpected test command');
};
syncBuiltinESMExports();`);
  const child = spawnSync(process.execPath, ['--import', preload, new URL('../scripts/setup-signup.mjs', import.meta.url).pathname], {
    encoding: 'utf8', env: { PATH: process.env.PATH, ...base }
  });
  assert.equal(child.status, 1);
  assert.match(child.stderr, /Worker secret LETTERMINT_PROJECT_TOKEN failed/);
  assert.match(child.stderr, /No mail sent; site code not deployed; Worker secrets may have changed/);
  assert.doesNotMatch(child.stdout + child.stderr, /fake-website-token|fake-webhook|fake-cf/);
});

test('missing PRAGMA column refuses before secrets; missing installed name refuses completion', async () => {
  const missingColumn = runner([db()]);
  await assert.rejects(setup(base, async request => {
    if (request.args?.includes('--command')) return { status: 0, stdout: JSON.stringify([{ success: true, results: columns.filter(name => name !== 'confirmed_at').map(name => ({ name })) }]) };
    return missingColumn.run(request);
  }), /Website D1 schema columns missing/);
  assert.equal(missingColumn.calls.some(c => c.args?.[1] === 'put'), false);

  const missingName = runner([db()]);
  await assert.rejects(setup(base, async request => {
    if (request.args?.[0] === 'secret' && request.args[1] === 'list') return { status: 0, stdout: JSON.stringify([{ name: 'MAIL_FROM', type: 'secret_text' }]) };
    return missingName.run(request);
  }), /Installed Worker secret names could not be verified/);
  assert.equal(missingName.calls.filter(c => c.args?.[1] === 'put').length, 1);
});
