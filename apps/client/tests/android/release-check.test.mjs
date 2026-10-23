// The release marker check on synthetic APKs and bare libraries, both
// directions. Real release and fixture APKs are checked by
// scripts/android-unsigned.sh and run-fixture.sh, real arm64 libraries by
// `check.sh android`.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const basehero = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const script = path.join(basehero, 'scripts/android-release-check.sh');

function apk(dir, name, library) {
  const file = path.join(dir, name);
  const made = spawnSync('python3', ['-c', `
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED) as apk:
    apk.writestr('classes.dex', b'dex\\n')
    apk.writestr('lib/arm64-v8a/libbh_client_lib.so', sys.argv[2].encode())
`, file, library]);
  assert.equal(made.status, 0, String(made.stderr));
  return file;
}
const check = (file, ...args) => {
  const home = path.join(path.dirname(file), 'home');
  mkdirSync(home, { recursive: true });
  const { GH_TOKEN, GITHUB_TOKEN, ...env } = process.env;
  return spawnSync('bash', ['--noprofile', '--norc', script, file, ...args], {
    encoding: 'utf8', env: { ...env, HOME: home },
  });
};

test('release_apk_has_no_fixture_markers', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bh-release-check-'));
  try {
    const clean = apk(dir, 'clean.apk', 'BaseHero release library');
    const fixture = apk(dir, 'fixture.apk', 'x EMULATOR FIXTURE y Create emulator test account z Create test account and show kit TEST ONLY — Password: ');
    const partial = apk(dir, 'partial.apk', 'EMULATOR FIXTURE only');
    const synthetic = apk(dir, 'synthetic.apk', 'EMULATOR FIXTURE Create emulator test account synthetic-attestation');

    assert.equal(check(clean).status, 0, check(clean).stderr);
    const leaked = check(fixture);
    assert.equal(leaked.status, 1);
    assert.match(leaked.stderr, /EMULATOR FIXTURE in lib\/arm64-v8a\/libbh_client_lib\.so/);
    assert.match(check(synthetic).stderr, /synthetic-attestation/);

    // The positive control finds every fixture marker and still refuses synthetic attestation.
    assert.equal(check(fixture, '--expect-fixture').status, 0);
    assert.match(check(clean, '--expect-fixture').stderr, /fixture marker missing: EMULATOR FIXTURE/);
    assert.match(check(partial, '--expect-fixture').stderr, /fixture marker missing: Create emulator test account/);
    assert.equal(check(synthetic, '--expect-fixture').status, 1);
    assert.equal(check(clean, '--bogus').status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('release_library_has_no_fixture_markers', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bh-release-check-'));
  try {
    const library = (name, bytes) => {
      mkdirSync(path.join(dir, name));
      const file = path.join(dir, name, 'libbh_client_lib.so');
      writeFileSync(file, bytes);
      return file;
    };
    const clean = library('clean', '\x7fELF BaseHero release library');
    const fixture = library('fixture', '\x7fELF EMULATOR FIXTURE Create emulator test account Create test account and show kit TEST ONLY — Password: ');
    const newStringsOnly = library('new-strings-only', '\x7fELF Create test account and show kit TEST ONLY — Password: ');

    assert.equal(check(clean).status, 0, check(clean).stderr);
    const newLeak = check(newStringsOnly);
    assert.equal(newLeak.status, 1, newLeak.stderr);
    assert.match(newLeak.stderr, /Create test account and show kit in libbh_client_lib\.so/);
    assert.match(newLeak.stderr, /TEST ONLY — Password:  in libbh_client_lib\.so/);
    const leaked = check(fixture);
    assert.equal(leaked.status, 1);
    assert.match(leaked.stderr, /EMULATOR FIXTURE in libbh_client_lib\.so/);
    assert.equal(check(fixture, '--expect-fixture').status, 0, check(fixture, '--expect-fixture').stderr);
    assert.match(check(clean, '--expect-fixture').stderr, /fixture marker missing: EMULATOR FIXTURE/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
