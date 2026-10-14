import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MARKERS, check, markersIn } from "./check-webdriver-markers.mjs";

const dir = mkdtempSync(join(tmpdir(), "bh-webdriver-markers-"));

function artifact(name, chunks) {
  const path = join(dir, name);
  writeFileSync(path, Buffer.concat(chunks.map((chunk) => Buffer.from(chunk, "latin1"))));
  return path;
}

const markerBytes = MARKERS.map((marker) => `\u0000${marker}\u0000`);

test("markersIn reports exactly the markers present", () => {
  assert.deepEqual(markersIn(Buffer.from("no driver here")), []);
  assert.deepEqual(markersIn(Buffer.from(markerBytes.join(""))), MARKERS);
  assert.deepEqual(markersIn(Buffer.from("x tauri_plugin_webdriver y")), ["tauri_plugin_webdriver"]);
});

test("a release artifact without the feature passes, and one with it is rejected", () => {
  const clean = artifact("clean.bin", ["ordinary binary bytes", "tauri", "axum"]);
  const dirty = artifact("dirty.bin", ["ordinary binary bytes", ...markerBytes]);
  assert.deepEqual(check(clean, "absent"), []);
  const failures = check(dirty, "absent");
  assert.equal(failures.length, 1);
  assert.match(failures[0], /tauri_plugin_webdriver/);
});

test("the positive control requires every marker", () => {
  const complete = artifact("complete.bin", markerBytes);
  const partial = artifact("partial.bin", markerBytes.slice(0, 2));
  assert.deepEqual(check(complete, "present"), []);
  const failures = check(partial, "present");
  assert.equal(failures.length, 1);
  assert.match(failures[0], /session\/\{session_id\}/);
});
