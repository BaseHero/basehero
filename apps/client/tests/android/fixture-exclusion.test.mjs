// The release-input check for the emulator fixture feature, on the real tree
// and on temporary copies that name the feature where a release build reads it.
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { check, releaseInputs } from '../../../../scripts/android-fixture-exclusion.mjs';

const basehero = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const tauri = 'apps/client/src-tauri';
const android = `${tauri}/gen/android`;

// A temporary copy of the real release inputs and the allowed scripts.
function copy() {
  const root = mkdtempSync(path.join(tmpdir(), 'bh-fixture-exclusion-'));
  for (const rel of [...releaseInputs(basehero), 'scripts/check.sh', 'scripts/android-release-check.sh']) {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    cpSync(path.join(basehero, rel), path.join(root, rel));
  }
  return root;
}
function write(root, rel, text) {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  writeFileSync(path.join(root, rel), text);
}

test('the real release inputs do not name the fixture feature', () => {
  const inputs = releaseInputs(basehero);
  for (const rel of [`${tauri}/tauri.conf.json`, `${tauri}/Cargo.toml`, `${android}/app/build.gradle.kts`,
    `${android}/buildSrc/src/main/java/app/basehero/client/kotlin/BuildTask.kt`, 'scripts/android-unsigned.sh']) {
    assert.ok(inputs.includes(rel), `${rel} is scanned`);
  }
  assert.ok(!inputs.some((rel) => rel.includes('/.kotlin/') || rel.includes('/build/')), 'caches and outputs are not scanned');
  assert.deepEqual(check(basehero), []);
});

test('a copy of the inputs passes until a release input names the feature', () => {
  const root = copy();
  try {
    assert.deepEqual(check(root), [], 'copy passes: only the declaration and allowed scripts name it');

    const config = JSON.parse(readFileSync(path.join(root, tauri, 'tauri.conf.json'), 'utf8'));
    config.build.features = ['emulator-fixture'];
    write(root, `${tauri}/tauri.conf.json`, JSON.stringify(config, null, 2));
    assert.deepEqual(check(root).map((f) => f.split(':')[0]), [`${tauri}/tauri.conf.json`]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('each release route that names the feature fails', () => {
  const routes = [
    [`${tauri}/tauri.android.conf.json`, '{"build":{"runner":"cargo","beforeBuildCommand":"x --features emulator-fixture"}}'],
    [`${tauri}/Cargo.toml`, readFileSync(path.join(basehero, tauri, 'Cargo.toml'), 'utf8')
      .replace('default = ["custom-protocol"]', 'default = ["custom-protocol", "emulator-fixture"]')],
    [`${android}/app/build.gradle.kts`, 'val features = "emulator-fixture"\n'],
    [`${android}/gradle.properties`, 'tauri.features=emulator-fixture\n'],
    [`${android}/buildSrc/src/main/java/app/basehero/client/kotlin/BuildTask.kt`, 'listOf("--features", "emulator-fixture")\n'],
    [`${android}/buildSrc/src/main/jniLibs/fixture.gradle.kts`, 'val features = "emulator-fixture"\n'],
    ['.cargo/config.toml', '[build]\nrustflags = ["--cfg", \'feature="emulator-fixture"\']\n'],
    ['scripts/android-unsigned.sh', 'cargo tauri android build --features emulator-fixture\n'],
    ['scripts/android-release.sh', 'cargo tauri android build --features emulator-fixture\n'],
  ];
  for (const [rel, text] of routes) {
    const root = copy();
    try {
      write(root, rel, text);
      const failures = check(root);
      assert.ok(failures.length > 0 && failures.every((f) => f.startsWith(`${rel}:`)), `${rel}: ${failures}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('a dangling generated app JNI library is not a release text input', () => {
  const root = copy();
  try {
    const rel = `${android}/app/src/main/jniLibs/arm64-v8a/libbasehero_client.so`;
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    symlinkSync('missing-generated-library.so', path.join(root, rel));
    assert.ok(!releaseInputs(root).includes(rel));
    assert.deepEqual(check(root), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a dangling Gradle input still fails closed', () => {
  const root = copy();
  try {
    const rel = `${android}/app/missing.gradle.kts`;
    symlinkSync('missing-build-input.gradle.kts', path.join(root, rel));
    assert.throws(() => check(root), { code: 'ENOENT' });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Gradle caches, build outputs and the allowed check scripts are not release inputs', () => {
  const root = copy();
  try {
    write(root, `${android}/buildSrc/.kotlin/sessions/cache.properties`, 'emulator-fixture\n');
    write(root, `${android}/app/build/intermediates/out.properties`, 'emulator-fixture\n');
    write(root, 'scripts/check.sh', 'cargo build --features bh-client/emulator-fixture\n');
    assert.deepEqual(check(root), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
