// The shipped bridge's part of the native close/Quit/update barrier: native
// posts __bhDrain to one page token with a fence; the page finishes and saves
// its writing, replies, and resumes only when native (or a refused reply)
// says so. IPC is a test host; native fences and sheets are tested in Rust.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { browserMatrix, launchBrowser, startUiServer } from "./harness.mjs";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

// Like harness openPage, also taking [script, argument] init entries.
async function openPage(browser, origin, { extraInit = [] } = {}) {
  const page = await browser.newPage();
  await page.addInitScript(tauriIpcStub);
  for (const init of extraInit) {
    if (Array.isArray(init)) await page.addInitScript(...init);
    else await page.addInitScript(init);
  }
  await page.goto(`${origin}/`, { waitUntil: "load" });
  return page;
}

function heldHost() {
  const ipc = window.__bhIpc;
  window.__bhAcks = [];
  window.__bhView = null;
  window.__bhDrainedReply = true;
  ipc.handle("note_binding", () => ({ note: Array(32).fill(3), surface: "41", view: window.__bhView }));
  ipc.handle("note_selection", () => []);
  ipc.handle("note_list", () => []);
  ipc.handle("note_open", () => ({ clientId: 2002468231004600, writerToken: Array(32).fill(9), updates: [[0, 0]], generation: 7, sequence: 0 }));
  ipc.handle("note_commit", (args) => new Promise((resolve, reject) => window.__bhAcks.push({ args, resolve, reject })));
  ipc.handle("note_close", () => null);
  ipc.handle("note_drained", () => window.__bhDrainedReply);
  ipc.handle("note_drain_failed", () => true);
}
const calls = (page, command) => page.evaluate((name) =>
  window.__bhIpc.calls.filter((call) => call.command === name).map((call) => call.args), command);
const editable = (page) => page.locator(".ProseMirror").getAttribute("contenteditable");
const ack = (page) => page.evaluate(() => { const job = window.__bhAcks.shift(); job.resolve({ requestId: job.args.requestId }); });
const drain = (page, fence, extra = {}) => page.evaluate(([fence, extra]) =>
  window.__bhDrain({ page: "41", fence, timeoutMs: 5000, reason: "close", ...extra }), [fence, extra]);

for (const browserName of browserMatrix) {
  describe(`native save barrier bridge in ${browserName}`, () => {
    test("a native drain saves held writing, replies with its view and resumes only on its fence", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost] });
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("held");
        await page.waitForFunction(() => window.__bhAcks.length === 1);
        assert.equal(await drain(page, "f1"), "accepted");
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "false");
        assert.equal((await calls(page, "note_drained")).length, 0, "not drained while a save is in flight");
        await ack(page);
        await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_drained"));
        const [reply] = await calls(page, "note_drained");
        assert.equal(reply.surface, "41"); assert.equal(reply.fence, "f1");
        assert.equal(reply.view.version, 1);
        assert.ok(Array.isArray(reply.view.anchor) && Array.isArray(reply.view.head));
        assert.equal(await editable(page), "false", "held until native resumes");
        assert.equal(await page.evaluate(() => window.__bhResumeEditing("f0")), "accepted");
        assert.equal(await editable(page), "false", "another fence cannot resume it");
        await page.evaluate(() => window.__bhResumeEditing("f1"));
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "true");
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a refused drained reply resumes the page's own editing", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost, () => { window.__bhDrainedReply = false; }] });
        await page.locator(".ProseMirror").waitFor();
        await drain(page, "late");
        await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_drained"));
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "true");
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a save that fails twice reports the failed drain and stays held for the sheet", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost] });
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("unsaved");
        await page.waitForFunction(() => window.__bhAcks.length === 1);
        const first = await page.evaluate(() => window.__bhAcks[0].args.requestId);
        await drain(page, "f2");
        await page.evaluate(() => window.__bhAcks.shift().reject("note commit failed"));
        await page.waitForFunction(() => window.__bhAcks.length === 1);
        assert.equal(await page.evaluate(() => window.__bhAcks[0].args.requestId), first, "one unchanged retry");
        await page.evaluate(() => window.__bhAcks.shift().reject("note commit failed"));
        await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_drain_failed"));
        assert.deepEqual(await calls(page, "note_drain_failed"), [{ surface: "41", fence: "f2" }]);
        assert.equal((await calls(page, "note_drained")).length, 0);
        assert.equal(await editable(page), "false");
        assert.match(await page.locator(".ProseMirror").textContent(), /unsaved/);
        await page.evaluate(() => window.__bhResumeEditing("f2"));
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "true");
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a drain posted for another page token is refused without holding", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost] });
        await page.locator(".ProseMirror").waitFor();
        assert.equal(await drain(page, "f3", { page: "40" }), "stale");
        assert.equal(await editable(page), "true");
        assert.equal((await calls(page, "note_drained")).length, 0);
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("an editor that loads after its page drained empty stays held until that drain resumes it", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost, () => {
          // Native's open was already under way when the drain arrived.
          window.__bhIpc.handle("note_open", () => new Promise((resolve) => {
            window.__bhOpenGate = () => resolve({ clientId: 2002468231004600, writerToken: Array(32).fill(9), updates: [[0, 0]], generation: 7, sequence: 0 });
          }));
        }] });
        await page.waitForFunction(() => !!window.__bhOpenGate);
        assert.equal(await drain(page, "f5", { reason: "update" }), "accepted");
        await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_drained"));
        assert.equal((await calls(page, "note_drained"))[0].view, null, "nothing to save yet");
        await page.evaluate(() => window.__bhOpenGate());
        await page.locator(".ProseMirror").waitFor();
        assert.equal(await editable(page), "false");
        assert.equal(await page.locator("[data-status]").textContent(), "Saving before update…");
        await page.locator(".ProseMirror").click();
        await page.keyboard.type("tail");
        await page.locator(".ProseMirror").evaluate((el) => el.editor.view.pasteText("pasted"));
        await page.keyboard.press("ControlOrMeta+a");
        await page.keyboard.press("ControlOrMeta+b");
        await page.keyboard.press("ControlOrMeta+z");
        assert.equal(await page.getByRole("toolbar", { name: "Format" }).isVisible(), false, "no formatting while held");
        await page.waitForTimeout(100);
        assert.equal((await calls(page, "note_commit")).length, 0, "nothing accepted between drained and exit");
        assert.doesNotMatch(await page.locator(".ProseMirror").textContent(), /tail|pasted/);
        await page.evaluate(() => window.__bhResumeEditing("f0"));
        assert.equal(await editable(page), "false", "another fence cannot resume it");
        await page.evaluate(() => window.__bhResumeEditing("f5"));
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "true");
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("after");
        await page.waitForFunction(() => window.__bhAcks.length === 1);
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a refused empty drain resumes the editor that loaded while native replied", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost, () => {
          window.__bhIpc.handle("note_open", () => new Promise((resolve) => {
            window.__bhOpenGate = () => resolve({ clientId: 2002468231004600, writerToken: Array(32).fill(9), updates: [[0, 0]], generation: 7, sequence: 0 });
          }));
          window.__bhIpc.handle("note_drained", () => new Promise((resolve) => {
            window.__bhRefuseDrain = () => resolve(false);
          }));
        }] });
        await page.waitForFunction(() => !!window.__bhOpenGate);
        assert.equal(await drain(page, "late"), "accepted");
        await page.waitForFunction(() => !!window.__bhRefuseDrain);
        assert.equal((await calls(page, "note_drained"))[0].view, null);
        await page.evaluate(() => window.__bhOpenGate());
        await page.locator(".ProseMirror").waitFor();
        assert.equal(await editable(page), "false", "late editor is held before the refused reply");
        await page.evaluate(() => window.__bhRefuseDrain());
        await page.waitForFunction(() => document.querySelector(".ProseMirror").getAttribute("contenteditable") === "true");
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a new window held at its first binding offers to try again, never setup", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost, () => {
          // Native refuses the binding while a drain holds every window.
          let held = true;
          window.__bhEndHold = () => { held = false; };
          window.__bhIpc.handle("note_binding", () => {
            if (held) throw new Error("note busy");
            return { note: Array(32).fill(3), surface: "41", view: null };
          });
        }] });
        const retry = page.getByRole("button", { name: "Retry opening note" });
        await retry.waitFor();
        assert.equal((await calls(page, "account_screen")).length, 0, "no setup screen");
        assert.equal((await calls(page, "note_open")).length, 0, "no note data while held");
        await retry.click();
        await page.waitForFunction(() => (window.__bhIpc.calls.filter((c) => c.command === "note_binding").length === 2));
        await page.waitForFunction(() => [...document.querySelectorAll("button")]
          .some((b) => b.textContent === "Retry opening note" && !b.disabled), null, { timeout: 5000 });
        assert.equal((await calls(page, "note_open")).length, 0, "still held");
        await page.evaluate(() => window.__bhEndHold());
        await retry.click();
        await page.waitForFunction(() => document.querySelector(".ProseMirror")?.getAttribute("contenteditable") === "true");
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a restored window's binding puts back the drained selection", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, { extraInit: [heldHost] });
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("restore here");
        await page.waitForFunction(() => window.__bhAcks.length === 1);
        await ack(page);
        await page.locator(".ProseMirror").evaluate((el) => el.editor.commands.setTextSelection({ from: 9, to: 13 }));
        await drain(page, "f4", { reason: "update" });
        await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_drained"));
        assert.equal(await page.locator("[data-status]").textContent(), "Saving before update…");
        const [{ view }] = await calls(page, "note_drained");
        const committed = await page.evaluate(() => window.__bhIpc.calls.filter((c) => c.command === "note_commit").map((c) => c.args.update));
        await page.close();
        // The restarted app: the committed note, and native's restart hint.
        const restarted = await openPage(browser, server.origin, { extraInit: [heldHost, [([view, committed]) => {
          window.__bhView = view;
          window.__bhIpc.handle("note_open", async () => ({ clientId: 2002468231004601, writerToken: Array(32).fill(8),
            updates: [committed[0]], generation: 9, sequence: 0 }));
        }, [view, committed]]] });
        await restarted.waitForFunction(() => {
          const s = document.querySelector(".ProseMirror")?.editor?.state.selection;
          return s && s.from === 9 && s.to === 13;
        });
        await restarted.close();
      } finally { await browser.close(); await server.close(); }
    });
  });
}
