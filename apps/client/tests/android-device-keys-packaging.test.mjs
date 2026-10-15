import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const client = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => readFileSync(path.join(client, relative), 'utf8');

test('Android shell includes device-key library without copying or widening WebView access', () => {
  const settings = read('src-tauri/gen/android/settings.gradle');
  assert.match(settings, /include ':device-keys'/);
  assert.match(settings, /project\(':device-keys'\)\.projectDir = new File\(settingsDir, ['"]\.\.\/\.\.\/\.\.\/plugins\/device-keys\/android['"]\)/);
  assert.match(read('src-tauri/gen/android/app/build.gradle.kts'), /implementation\(project\(":device-keys"\)\)/);
  const root = read('../../Cargo.toml');
  assert.match(root, /bh-device-keys\s*=\s*\{ path = "apps\/client\/plugins\/device-keys" \}/);
  assert.match(read('src-tauri/Cargo.toml'), /\[target\.'cfg\(target_os = "android"\)'\.dependencies\]\s*bh-device-keys\.workspace = true/);
  const lib = read('src-tauri/src/lib.rs');
  assert.match(lib, /#\[cfg\(target_os = "android"\)\]\s*let builder = builder\.plugin\(bh_device_keys::init\(\)\);/);
  assert.doesNotMatch(lib, /AndroidKeyStore|AndroidPendingSetupProtector|invoke_handler/);
  assert.doesNotMatch(read('src-tauri/capabilities/shell.json'), /device-keys/);
});

test('only a resumed Activity is bound and pause detaches it before super', () => {
  const activity = read('src-tauri/gen/android/app/src/main/java/app/basehero/client/MainActivity.kt');
  assert.match(activity, /override fun onResume\(\)\s*\{\s*super\.onResume\(\)\s*DeviceKeysBridge\.attachActivity\(this\)\s*\}/);
  assert.match(activity, /override fun onPause\(\)\s*\{\s*DeviceKeysBridge\.detachActivity\(this\)\s*super\.onPause\(\)\s*\}/);
  const binding = read('plugins/device-keys/android/src/main/java/app/basehero/devicekeys/CurrentActivity.kt');
  assert.match(binding, /if \(current\.get\(\) === activity\) current = WeakReference\(null\)/);
});
