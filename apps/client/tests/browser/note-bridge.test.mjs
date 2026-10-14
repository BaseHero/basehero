// Bound bridge checks use the actual bundled EditorView under the shell CSP.
// IPC is a test-only host, not an account session or native-device evidence.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { browserMatrix, launchBrowser, openPage, startUiServer } from "./harness.mjs";

function senderHost() {
  window.__bhIpc.handle("note_binding", () => Array(32).fill(3));
  window.__bhIpc.handle("note_open", () => ({ state: [0, 0], generation: 7, sequence: 5 }));
  window.__bhIpc.handle("note_commit", (args) => new Promise((resolve) => {
    (window.__bhPendingAcks ??= []).push({ args, resolve });
  }));
  window.__bhIpc.handle("note_close", () => null);
}

function receiverHost() {
  window.__bhIpc.handle("note_binding", () => Array(32).fill(3));
  window.__bhIpc.handle("note_open", () => new Promise((resolve) => {
    window.__bhFinishOpen = () => resolve({ state: [0, 0], generation: 7, sequence: 5 });
  }));
  window.__bhIpc.handle("note_commit", (args) => ({ requestId: args.requestId }));
  window.__bhIpc.handle("note_close", () => null);
}

async function dispatch(page, generation, sequence, update) {
  await page.evaluate(({ generation, sequence, update }) => {
    window.dispatchEvent(new CustomEvent("bh-note-update", { detail: { generation, sequence, update } }));
  }, { generation, sequence, update });
}

for (const browserName of browserMatrix) {
  describe(`bound note bridge in ${browserName}`, () => {
    test("mounts only with a binding, buffers and fences updates, and saves only matching commits", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const unbound = await openPage(browser, server.origin, {
          extraInit: [() => window.__bhIpc.handle("note_binding", () => null)],
        });
        assert.equal(await unbound.locator("header strong").textContent(), "SETUP");
        assert.equal(await unbound.locator(".ProseMirror").count(), 0);
        assert.deepEqual(await unbound.evaluate(() => window.__bhIpc.calls.map(c => c.command)), ["note_binding"]);
        assert.equal(await unbound.evaluate(() => window.__bhStorageReads), 0);
        await unbound.close();

        const sender = await openPage(browser, server.origin, { extraInit: [senderHost] });
        await sender.locator(".ProseMirror").waitFor();
        assert.equal(await sender.locator("header strong").textContent(), "NOTE");
        assert.equal(await sender.locator(".note-content").count(), 1);
        assert.equal(await sender.evaluate(() => window.__bhStorageReads), 0);
        await sender.locator(".ProseMirror").click();
        await sender.keyboard.insertText("hello");
        await sender.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        const first = await sender.evaluate(() => window.__bhPendingAcks[0].args);
        assert.equal(first.generation, 7);
        assert.equal(typeof first.requestId, "string");
        assert.ok(first.update.length > 0);
        assert.notEqual(await sender.locator('[role="status"]').textContent(), "Saved on this device");
        await sender.evaluate(() => window.__bhPendingAcks[0].resolve({ requestId: "wrong-id" }));
        await sender.getByRole("button", { name: "Retry save" }).waitFor({ state: "visible" });
        assert.notEqual(await sender.locator('[role="status"]').textContent(), "Saved on this device");
        await sender.getByRole("button", { name: "Retry save" }).click();
        await sender.waitForFunction(() => window.__bhPendingAcks.length === 2);
        const retry = await sender.evaluate(() => window.__bhPendingAcks[1].args);
        assert.deepEqual(retry, first, "retry preserves the same request and update");
        await sender.evaluate(() => window.__bhPendingAcks[1].resolve({ requestId: window.__bhPendingAcks[1].args.requestId }));
        await sender.waitForFunction(() => document.querySelector('[role="status"]').textContent === "Saved on this device");
        await sender.keyboard.insertText("!");
        await sender.waitForFunction(() => window.__bhPendingAcks.length === 3);
        const later = await sender.evaluate(() => window.__bhPendingAcks[2].args);
        assert.equal(later.generation, 7);
        await sender.evaluate(() => window.__bhPendingAcks[2].resolve({ requestId: window.__bhPendingAcks[2].args.requestId }));
        await sender.waitForFunction(() => document.querySelector('[role="status"]').textContent === "Saved on this device");

        const receiver = await openPage(browser, server.origin, { extraInit: [receiverHost] });
        await receiver.waitForFunction(() => typeof window.__bhFinishOpen === "function");
        // These arrive during note_open, before the snapshot and generation are known.
        await dispatch(receiver, 8, 100, later.update);
        await dispatch(receiver, 7, 6, first.update);
        assert.equal(await receiver.locator(".ProseMirror").count(), 0);
        await receiver.evaluate(() => window.__bhFinishOpen());
        await receiver.locator(".ProseMirror").waitFor();
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent.trim() === "hello");
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello");
        await dispatch(receiver, 7, 6, later.update); // equal sequence, distinct content
        await dispatch(receiver, 7, 5, later.update); // older than snapshot
        await dispatch(receiver, 8, 101, later.update); // wrong generation
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello");
        await dispatch(receiver, 7, 7, later.update);
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello!");
        assert.equal(await receiver.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_commit").length), 0,
          "incoming updates never echo as local commits");
        await receiver.locator(".ProseMirror").click();
        await receiver.keyboard.press("End");
        await receiver.keyboard.insertText(" world");
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello! world");
        await receiver.getByRole("button", { name: "Undo" }).click();
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello!");
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello!",
          "local Undo leaves incoming content intact");
        assert.equal(await receiver.evaluate(() => window.__bhStorageReads), 0);
        await receiver.evaluate(() => window.dispatchEvent(new Event("pagehide")));
        assert.deepEqual(await receiver.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_close").map(c => c.args)),
          [{ generation: 7 }]);
        await sender.evaluate(() => window.dispatchEvent(new Event("pagehide")));
        assert.deepEqual(await sender.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_close").map(c => c.args)),
          [{ generation: 7 }]);
        assert.equal(await sender.evaluate(() => window.__bhStorageReads), 0);
        await receiver.close();
        await sender.close();
      } finally {
        await browser.close();
        await server.close();
      }
    });
  });
}
