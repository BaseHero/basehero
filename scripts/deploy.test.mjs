import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, symlinkSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// A copy with fake tools guarantees failures never touch real credentials or Workers.
const source = resolve(dirname(fileURLToPath(import.meta.url)), 'deploy.sh');
function runWithFailedList(apiStatus, inActions = true, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'bh-deploy-test-'));
  try {
    const scripts = join(dir, 'scripts');
    const bin = join(dir, 'server/node_modules/.bin');
    const tools = join(dir, 'bin');
    const home = join(dir, 'home');
    for (const path of [scripts, bin, tools, home]) mkdirSync(path, { recursive: true });
    copyFileSync(source, join(scripts, 'deploy.sh'));
    symlinkSync(process.execPath, join(tools, 'node'));
    writeFileSync(join(bin, 'wrangler'), `#!${process.execPath}
const fs = require('fs');
const args = process.argv.slice(2).join(' ');
fs.appendFileSync(process.env.TEST_LOG, args + '\\n');
if (args.startsWith('secret list ')) process.exit(1);
`, { mode: 0o700 });
    writeFileSync(join(tools, 'curl'), `#!${process.execPath}
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.TEST_LOG, 'curl ' + args.join(' ') + '\\n');
if (args.includes('--write-out')) {
  fs.writeFileSync(args[args.indexOf('--output') + 1],
    process.env.TEST_API_STATUS === '404' ? '{"errors":[{"code":10007}]}' : '{}');
  process.stdout.write(process.env.TEST_API_STATUS);
} else if (process.env.TEST_DOH_FAILS === '1' && args.includes('--doh-url')) {
  process.stderr.write('curl: (6) Could not resolve host: dev-api.basehero.com\\n');
  process.exit(6);
} else { process.stdout.write(process.env.TEST_HEALTH_RESPONSE || '{"ok":true,"protocol":2}'); }
`, { mode: 0o700 });
    writeFileSync(join(tools, 'openssl'), `#!${process.execPath}\nrequire('fs').appendFileSync(process.env.TEST_LOG, 'openssl\\n');\nconsole.log('dummy');\n`, { mode: 0o700 });
    // A failing health response must not wait through the production retry window.
    writeFileSync(join(tools, 'sleep'), `#!${process.execPath}\nrequire('fs').appendFileSync(process.env.TEST_LOG, 'sleep\\n');\nprocess.exit(99);\n`, { mode: 0o700 });
    const log = join(dir, 'calls');
    const env = { PATH: `${tools}:${process.env.PATH}`, HOME: home, XDG_CONFIG_HOME: join(home, '.config'),
      CLOUDFLARE_ACCOUNT_ID: 'test-account', CLOUDFLARE_API_TOKEN: 'test-token',
      GH_CONFIG_DIR: join(home, 'gh'), GITHUB_ACTIONS: inActions ? 'true' : 'false',
      TEST_API_STATUS: apiStatus, TEST_LOG: log, ...extraEnv };
    const check = spawnSync('bash', ['--noprofile', '--norc', '-c',
      'test "$(command -v node)" = "$TEST_NODE" && test "$(command -v curl)" = "$TEST_CURL" && test "$(command -v openssl)" = "$TEST_OPENSSL" && test "$(command -v sleep)" = "$TEST_SLEEP" && test -x "$TEST_WRANGLER"'], {
      encoding: 'utf8',
      env: { ...env, TEST_NODE: join(tools, 'node'), TEST_CURL: join(tools, 'curl'),
        TEST_OPENSSL: join(tools, 'openssl'), TEST_SLEEP: join(tools, 'sleep'), TEST_WRANGLER: join(bin, 'wrangler') },
    });
    assert.ifError(check.error);
    assert.equal(check.status, 0, `fake tools did not resolve: ${check.stderr}`);
    const result = spawnSync('bash', ['--noprofile', '--norc', join(scripts, 'deploy.sh'), 'dev'], {
      encoding: 'utf8', env, timeout: 30000,
    });
    assert.ifError(result.error);
    return { result, calls: existsSync(log) ? readFileSync(log, 'utf8') : '' };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('outside GitHub Actions refuses to deploy before calling any tool', () => {
  const { result, calls } = runWithFailedList('404', false);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /production deploys on every push to main/i);
  assert.match(result.stderr, /gh workflow run deploy-dev\.yml --ref <branch>/);
  assert.equal(calls, '');
});

test('production Worker config does not enable test bypass or clock override', () => {
  const wrangler = readFileSync(resolve(dirname(source), '../server/wrangler.toml'), 'utf8');
  const production = wrangler.split(/^\[env\.production\]\s*$/m)[1]?.split(/^\[env\.(?!production\b)/m)[0];
  assert.ok(production, 'missing production environment');
  assert.doesNotMatch(production, /^\s*(?:ALLOW_TEST_BYPASS|GATEWAY_NOW_MS)\s*=/m);
});

test('no deployed Worker connects to a test model upstream', () => {
  const wrangler = readFileSync(resolve(dirname(source), '../server/wrangler.toml'), 'utf8');
  assert.doesNotMatch(wrangler, /TINFOIL_CONNECT/);
});

for (const status of ['200', '503']) {
  test(`secret lookup failure with Worker API status ${status} changes nothing`, () => {
    const { result, calls } = runWithFailedList(status);
    assert.notEqual(result.status, 0);
    assert.match(calls, /secret list --env dev/);
    assert.doesNotMatch(calls, /secret put|deploy/);
    assert.match(result.stderr, /secret lookup failed/i);
  });
}
test('protocol 2 health succeeds after DNS over HTTPS falls back to the host resolver', () => {
  const { result, calls } = runWithFailedList('404', true, { TEST_DOH_FAILS: '1',
    TEST_HEALTH_RESPONSE: '{"ok":true,"protocol":2}' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Health OK: https:\/\/dev-api\.basehero\.com\/v1\/health/);
  assert.match(result.stdout, /Through the host resolver/);
  assert.match(calls, /curl .*--doh-url .* -H BH-Protocol: 1 /);
  assert.match(calls, /curl --fail .* -H BH-Protocol: 1 /);
});
test('an older protocol 1 server does not pass the health check', () => {
  const { result, calls } = runWithFailedList('404', true, {
    TEST_HEALTH_RESPONSE: '{"ok":true,"protocol":1}' });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /Health OK/);
  assert.match(calls, /deploy --env dev/);
  assert.match(calls, /sleep/);
});
test('confirmed missing Worker permits initial creation of each secret', () => {
  const { result, calls } = runWithFailedList('404');
  assert.equal(result.status, 0, result.stderr);
  assert.match(calls, /secret put OPERATOR_TOKEN --env dev/);
  assert.match(calls, /secret put PEPPER --env dev/);
  assert.match(calls, /deploy --env dev/);
});
