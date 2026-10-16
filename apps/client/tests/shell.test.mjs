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

test("shell bundles its assets and grants no plugin or remote permissions, and core only to move its window", async () => {
  assert.equal(config.identifier, "app.basehero.client");
  assert.equal(config.build.frontendDist, "../ui");
  assert.equal(config.build.devUrl, undefined);
  assert.deepEqual(config.app.security.capabilities, ["basehero-client-notes", "basehero-client-setup", "basehero-client-window"]);

  // command-acl.test.mjs checks the exact command union. Here: only app-command
  // permissions, no plugin grants, no remote origins, and on a Mac only the two
  // core window grants its location bar needs to move and zoom the window.
  const capabilitiesDir = new URL("src-tauri/capabilities/", root);
  const entries = await readdir(capabilitiesDir, { recursive: true });
  const capabilityFiles = entries.filter((name) => /\.(json|toml|json5)$/.test(name));
  assert.deepEqual(capabilityFiles.sort(), ["shell.json", "signup.json", "window.json"]);
  for (const name of capabilityFiles) {
    assert(name.endsWith(".json"), `capability ${name} must be JSON so the check can parse it`);
    const parsed = JSON.parse(await readFile(new URL(name, capabilitiesDir), "utf8"));
    for (const capability of capabilitiesIn(parsed)) {
      const prefixes = { "shell.json": ["allow-note-", "allow-update-", "allow-window-sidebar"], "signup.json": ["allow-account-"],
        "window.json": ["core:window:allow-start-dragging", "core:window:allow-internal-toggle-maximize"] }[name];
      if (name === "window.json") assert.deepEqual(capability.platforms, ["macOS"]);
      for (const permission of capability.permissions) assert(prefixes.some((prefix) => permission.startsWith(prefix)), permission);
      assert.equal(capability.remote, undefined);
    }
  }

  for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    assert(!match[1].includes(":") && !match[1].startsWith("/"));
    await access(new URL("ui/" + match[1], root));
  }
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
