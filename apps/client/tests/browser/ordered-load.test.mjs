// A note opens from its updates in the order native integrated them. A merged
// full state of the same updates can place concurrent text differently; this
// fixture shows the difference. IPC is a test host, not native evidence.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, test } from "node:test";
import { browserMatrix, launchBrowser, startUiServer } from "./harness.mjs";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

const fixture = JSON.parse(await readFile(new URL("../../../../libs/core/tests/fixtures/k2.json", import.meta.url), "utf8"));
// The native title after integrating fixture.updates in order (bh-core).
const nativeTitle = "helloH worldabcdL";
// The native Note::state() of that note: one merged update, reopened by client ID.
const mergedState = [4, 1, 107, 0, 132, 2, 6, 6, 32, 119, 111, 114, 108, 100, 1, 50, 0, 196, 2, 4, 1, 1, 4, 97, 98, 99, 100, 4, 2, 0, 7, 1, 7, 100, 101, 102, 97, 117, 108, 116, 3, 9, 112, 97, 114, 97, 103, 114, 97, 112, 104, 7, 0, 2, 0, 6, 4, 0, 2, 1, 3, 104, 101, 108, 132, 2, 4, 2, 108, 111, 2, 1, 0, 132, 2, 6, 1, 72, 132, 1, 0, 1, 76, 0];

function host(updates) {
  window.__bhIpc.handle("note_binding", () => ({ note: Array(32).fill(3), surface: "42" }));
  window.__bhIpc.handle("note_open", () => ({ clientId: 2002468231004600, writerToken: Array(32).fill(9), updates, generation: 7, sequence: 5 }));
  window.__bhIpc.handle("note_commit", (args) => ({ requestId: args.requestId }));
  window.__bhIpc.handle("note_close", () => null);
}

async function opened(browser, origin, updates) {
  const page = await browser.newPage();
  await page.addInitScript(tauriIpcStub);
  await page.addInitScript(host, updates);
  await page.goto(`${origin}/`, { waitUntil: "load" });
  await page.waitForFunction(() => document.querySelector(".ProseMirror")?.getAttribute("contenteditable") === "true");
  const text = await page.locator(".ProseMirror").textContent();
  await page.close();
  return text;
}

for (const browserName of browserMatrix) {
  describe(`ordered note load in ${browserName}`, () => {
    test("browser_ordered_load_matches_native", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        assert.equal(await opened(browser, server.origin, fixture.updates), nativeTitle);
        // The same note from one merged state differs, as it does natively.
        assert.equal(await opened(browser, server.origin, [mergedState]), "helloHabcdL world");
      } finally { await browser.close(); await server.close(); }
    });
  });
}
