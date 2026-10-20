import test from "node:test";
import assert from "node:assert/strict";
import { readFile, access, readdir } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const config = JSON.parse(await readFile(new URL("src-tauri/tauri.conf.json", root), "utf8"));
const html = await readFile(new URL("ui/index.html", root), "utf8");
const js = await readFile(new URL("ui/theme.js", root), "utf8");

function capabilitiesIn(parsed) {
  if (Array.isArray(parsed)) return parsed;
  return parsed.capabilities ?? [parsed];
}

test("shell bundles its assets and grants only Android main-window camera scan, and core only to move its window", async () => {
  assert.equal(config.identifier, "app.basehero.client");
  assert.equal(config.build.frontendDist, "../ui");
  assert.equal(config.build.devUrl, undefined);
  assert.deepEqual(config.app.security.capabilities, ["basehero-client-notes", "basehero-client-setup", "basehero-client-pairing", "basehero-client-window", "basehero-client-camera-scan"]);

  // command-acl.test.mjs checks the exact app-command union. The only plugin
  // grant is the Android main window's request/scan/cancel trio. No remote
  // origins; on a Mac only the core window grants needed for its location bar.
  const capabilitiesDir = new URL("src-tauri/capabilities/", root);
  const entries = await readdir(capabilitiesDir, { recursive: true });
  const capabilityFiles = entries.filter((name) => /\.(json|toml|json5)$/.test(name));
  assert.deepEqual(capabilityFiles.sort(), ["pairing.json", "scan.json", "shell.json", "signup.json", "window.json"]);
  for (const name of capabilityFiles) {
    assert(name.endsWith(".json"), `capability ${name} must be JSON so the check can parse it`);
    const parsed = JSON.parse(await readFile(new URL(name, capabilitiesDir), "utf8"));
    for (const capability of capabilitiesIn(parsed)) {
      const prefixes = { "shell.json": ["allow-note-", "allow-update-", "allow-window-sidebar"],
        "signup.json": ["allow-account-", "allow-pairing-join"], "pairing.json": ["allow-pairing-", "allow-sync-status"],
        "scan.json": ["qr-scan:allow-request-permissions", "qr-scan:allow-scan", "qr-scan:allow-cancel"],
        "window.json": ["core:window:allow-start-dragging", "core:window:allow-internal-toggle-maximize"] }[name];
      if (name === "window.json") assert.deepEqual(capability.platforms, ["macOS"]);
      if (name === "scan.json") {
        assert.deepEqual(capability.platforms, ["android"]);
        assert.deepEqual(capability.windows, ["main"]);
        assert.deepEqual(capability.permissions, ["qr-scan:allow-request-permissions", "qr-scan:allow-scan", "qr-scan:allow-cancel"]);
      }
      for (const permission of capability.permissions) assert(prefixes.some((prefix) => permission.startsWith(prefix)), permission);
      assert.equal(capability.remote, undefined);
    }
  }

  for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    assert(!match[1].includes(":") && !match[1].startsWith("/"));
    await access(new URL("ui/" + match[1], root));
  }
});

test("Android QR scanning is the app's own algorithmic adapter: CameraX and ZXing only", async () => {
  // Source declarations only; scripts/android_no_models.py checks the resolved
  // Gradle graph and packaged APK for models and ML/Play Services components.
  const app = await readFile(new URL("src-tauri/gen/android/app/build.gradle.kts", root), "utf8");
  const plugin = await readFile(new URL("plugins/qr-scan/android/build.gradle.kts", root), "utf8");
  const manifest = await readFile(new URL("plugins/qr-scan/android/src/main/AndroidManifest.xml", root), "utf8");
  assert.match(app, /implementation\(project\(":qr-scan"\)\)/);
  assert.doesNotMatch(app, /mlkit|play-services|firebase|tensorflow/i);
  const deps = [...plugin.matchAll(/^\s*(?:implementation|api)\((.+)\)$/gm)].map(match => match[1]);
  assert.deepEqual(deps, ['"androidx.camera:camera-core:$camerax"', '"androidx.camera:camera-camera2:$camerax"',
    '"androidx.camera:camera-lifecycle:$camerax"', '"androidx.camera:camera-view:$camerax"',
    '"com.google.zxing:core:3.5.4"', '"androidx.appcompat:appcompat:1.7.1"', 'project(":tauri-android")']);
  assert.deepEqual([...manifest.matchAll(/uses-permission android:name="([^"]+)"/g)].map(match => match[1]), ["android.permission.CAMERA"]);
  assert.match(manifest, /android\.hardware\.camera\.any" android:required="false"/);
});

test("Android source has a stable release-only unsigned arm64 package", async () => {
  const properties = await readFile(new URL("src-tauri/gen/android/gradle.properties", root), "utf8");
  const build = await readFile(new URL("src-tauri/gen/android/app/build.gradle.kts", root), "utf8");
  assert.match(build, /applicationId\s*=\s*"app\.basehero\.client"/);
  assert(build.includes(`tauri.android.versionName", "${config.version}"`));
  assert.match(build, /tauri\.android\.versionCode", "1"/);
  assert(!/signingConfigs\.getByName\("debug"\)/.test(build));
  assert(!/signingConfig\s*=/.test(build));
  assert(!properties.includes("storePassword"));
});

test("CSP refuses remote content, inline script and dynamic execution", () => {
  const csp = config.app.security.csp;
  for (const required of ["default-src 'none'", "script-src 'self'", "object-src 'none'", "frame-src 'none'", "worker-src 'none'", "form-action 'none'"]) {
    assert(csp.split("; ").includes(required));
  }
  assert(!csp.includes("unsafe-inline"));
  assert(!csp.includes("unsafe-eval"));
  assert(!/https:|\*/.test(csp));
});

test("native-unavailable fallback grants no editing or account authority", () => {
  assert(!/<(?:input|textarea)|contenteditable/i.test(html));
  assert(!/localStorage|sessionStorage|indexedDB|fetch\s*\(|WebSocket/.test(js));
  assert(!/<script(?![^>]*\bsrc=)/i.test(html));
});
