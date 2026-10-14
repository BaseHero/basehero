import test from "node:test";
import assert from "node:assert/strict";

import { check, pluginLines } from "./webdriver-exclusion.mjs";

const clean = ["bh-client v0.1.0 (/repo/apps/client/src-tauri)", "├── tauri v2.12.1", "└── serde v1.0.229"].join("\n");
const dirty = [
  "bh-client v0.1.0 (/repo/apps/client/src-tauri)",
  "└── tauri-plugin-webdriver v0.2.3 (https://github.com/Choochmeque/tauri-plugin-webdriver?rev=b94eb81#b94eb81)",
  "    └── axum feature \"default\"",
].join("\n");

test("pluginLines finds the plugin however it appears", () => {
  assert.deepEqual(pluginLines(clean), []);
  assert.equal(pluginLines(dirty).length, 1);
  assert.deepEqual(pluginLines("tauri_plugin_webdriver::server::start"), ["tauri_plugin_webdriver::server::start"]);
});

test("check rejects a default graph that contains the plugin", () => {
  const failures = check({ trees: (features) => (features ? dirty : dirty) });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /default features pull the plugin/);
});

test("check rejects a missing positive control", () => {
  const failures = check({ trees: (features) => (features ? clean : clean) });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /not meaningful/);
});

test("check passes the clean default graph and the feature-positive control", () => {
  assert.deepEqual(check({ trees: (features) => (features ? dirty : clean) }), []);
});

test("the real client graph excludes the plugin by default and includes it with the feature", () => {
  assert.deepEqual(check(), []);
});
