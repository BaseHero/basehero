import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, symlinkSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// A copy with fake tools guarantees failures never touch real credentials or Workers.
const source = resolve(dirname(fileURLToPath(import.meta.url)), 'deploy.sh');
function runWithFailedList(apiStatus) {
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
if (args.includes('--write-out')) {
  fs.writeFileSync(args[args.indexOf('--output') + 1],
    process.env.TEST_API_STATUS === '404' ? '{"errors":[{"code":10007}]}' : '{}');
  process.stdout.write(process.env.TEST_API_STATUS);
} else { process.stdout.write('{"ok":true,"protocol":1}'); }
`, { mode: 0o700 });
    writeFileSync(join(tools, 'openssl'), `#!${process.execPath}\nconsole.log('dummy');\n`, { mode: 0o700 });
    const log = join(dir, 'calls');
    const result = spawnSync('bash', ['--noprofile', '--norc', join(scripts, 'deploy.sh'), 'dev'], {
      encoding: 'utf8',
      env: { PATH: `${tools}:${process.env.PATH}`, HOME: home, XDG_CONFIG_HOME: join(home, '.config'),
        CLOUDFLARE_ACCOUNT_ID: 'test-account', CLOUDFLARE_API_TOKEN: 'test-token',
        TEST_API_STATUS: apiStatus, TEST_LOG: log },
    });
    assert.ifError(result.error);
    return { result, calls: readFileSync(log, 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('production Worker config does not enable test bypass or clock override', () => {
  const wrangler = readFileSync(resolve(dirname(source), '../server/wrangler.toml'), 'utf8');
  const production = wrangler.split(/^\[env\.production\]\s*$/m)[1]?.split(/^\[env\.(?!production\b)/m)[0];
  assert.ok(production, 'missing production environment');
  assert.doesNotMatch(production, /^\s*(?:ALLOW_TEST_BYPASS|GATEWAY_NOW_MS)\s*=/m);
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
test('confirmed missing Worker permits initial creation of each secret', () => {
  const { result, calls } = runWithFailedList('404');
  assert.equal(result.status, 0, result.stderr);
  assert.match(calls, /secret put OPERATOR_TOKEN --env dev/);
  assert.match(calls, /secret put PEPPER --env dev/);
  assert.match(calls, /deploy --env dev/);
});
