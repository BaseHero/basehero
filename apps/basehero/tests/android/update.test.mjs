import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { adb, launch, webview, signUpOnDev, newNote, saved } from './lib.mjs';

const android = resolve(import.meta.dirname, '../../src-tauri/gen/android');
const properties = join(android, 'app/tauri.properties');
const apk = join(android, 'app/build/outputs/apk/universal/debug/app-universal-debug.apk');
function buildVersion(version, output) {
  const contents = readFileSync(properties, 'utf8');
  writeFileSync(properties, contents.replace(/^tauri\.android\.versionName=.*$/m, `tauri.android.versionName=${version}`)
    .replace(/^tauri\.android\.versionCode=.*$/m, `tauri.android.versionCode=${version === '0.0.1' ? 1 : 2}`));
  // Rust was built by android-dev.sh; only package the same native library
  // twice with different Android manifest versions and the same debug key.
  execFileSync('timeout', ['360s', './gradlew', ':app:assembleUniversalDebug',
    '-PabiList=x86_64', '-ParchList=x86_64', '-PtargetList=x86_64',
    '-x', ':app:rustBuildX86_64Debug'], {
    cwd: android, timeout: 370_000, stdio: ['ignore', 'pipe', 'pipe'], env: process.env,
  });
  copyFileSync(apk, output);
}

test('debug update 0.0.1 to 0.0.2 keeps the account and note', { timeout: 800_000 }, async () => {
  const original = readFileSync(properties, 'utf8');
  const dir = mkdtempSync(join(tmpdir(), 'bh-update-'));
  let page;
  try {
    const oldApk = join(dir, '0.0.1.apk');
    const newApk = join(dir, '0.0.2.apk');
    buildVersion('0.0.1', oldApk);
    buildVersion('0.0.2', newApk);
    adb('install', '-r', '-d', oldApk);
    assert.match(adb('shell', 'pm', 'clear', 'app.basehero'), /Success/);
    await launch(); page = await webview();
    await signUpOnDev(page);
    const edit = await newNote(page, 'Update check');
    await edit.fill('Ferry update survives');
    await saved(page);
    await page.context().browser()?.close(); page = undefined;
    adb('install', '-r', newApk);
    assert.match(adb('shell', 'dumpsys', 'package', 'app.basehero'), /versionName=0\.0\.2/);
    await launch(); page = await webview();
    await page.getByRole('link', { name: 'Personal' }).first().click();
    await page.getByTestId('tree-row').filter({ hasText: 'Ferry update survives' }).first().click();
    await page.locator('[aria-label="Note editor"] .ProseMirror').getByText('Ferry update survives').waitFor();
  } finally {
    await page?.context().browser()?.close();
    writeFileSync(properties, original);
    rmSync(dir, { recursive: true, force: true });
  }
});
