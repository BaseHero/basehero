import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";

const scripts = new URL("../../../scripts/", import.meta.url);
const browser = new URL("browser/", import.meta.url);

test("the UI check prepares the editor's packages before browser tests import them", async () => {
  const files = (await readdir(browser)).filter((name) => name.endsWith(".test.mjs"));
  const importers = [];
  for (const name of files) {
    if ((await readFile(new URL(name, browser), "utf8")).includes("../../editor/node_modules/")) importers.push(name);
  }
  // Without an importer the order below would be a guess, not a requirement.
  assert(importers.length > 0, "no browser test imports the editor's installed packages");

  const check = await readFile(new URL("check-client-ui.sh", scripts), "utf8");
  const install = check.indexOf("cd apps/client/editor\n  npm ci");
  const prepare = check.indexOf("node scripts/patch-yjs.mjs");
  const run = check.indexOf("cd apps/client/tests/browser");
  assert(install >= 0 && prepare > install, "check-client-ui.sh installs and patches the editor's packages");
  assert(run > prepare, `${importers.join(", ")} need the editor's packages installed and patched before the browser tests run`);
});
