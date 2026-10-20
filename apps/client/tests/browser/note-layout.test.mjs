// The note window's layout: one bar that is also the title bar, a notes
// sidebar that can be hidden, the page, one status line, formatting on a
// selection and a small update card. The IPC host is a page-side test model,
// not an account, a native Mac window or its menu.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { browserMatrix, launchBrowser, openPage, startUiServer } from "./harness.mjs";

function layoutHost() {
  const ipc = window.__bhIpc;
  const id = (n) => Array(32).fill(n);
  let current = id(1), surface = 0;
  window.__bhSidebar ??= true;
  ipc.handle("note_binding", () => ({ note: current, surface: String(++surface) }));
  ipc.handle("note_open", () => ({ clientId: 2002468231004600, writerToken: id(9), updates: [[0, 0]], generation: 7, sequence: 0 }));
  ipc.handle("note_commit", ({ requestId }) => ({ requestId }));
  ipc.handle("note_close", () => null);
  ipc.handle("note_selection", () => []);
  ipc.handle("note_list", () => [
    { note: id(1), title: "Kitchen renovation: what we decided", touched: 3 },
    { note: id(2), title: "Questions for Dr. Okafor", touched: 2 },
    { note: id(3), title: "", touched: 1 },
  ]);
  ipc.handle("note_show", ({ note }) => { current = note; return null; });
  ipc.handle("note_create", () => id(4));
  // A local-only build: its notes stay on this device.
  ipc.handle("sync_status", () => ({ revision: 1, state: "saved-local", pending: 0, network: "off", home: null, account: "active", confirm: false }));
  ipc.handle("note_new_window", () => null);
  ipc.handle("window_sidebar", ({ shown }) => {
    if (typeof shown === "boolean") window.__bhSidebar = shown;
    return window.__bhSidebar;
  });
}
const hidden = () => { window.__bhSidebar = false; };
const sidebarWrites = (page) => page.evaluate(() =>
  window.__bhIpc.calls.filter((c) => c.command === "window_sidebar" && typeof c.args.shown === "boolean").map((c) => c.args.shown));
const visible = (locator) => locator.isVisible();

async function bound(browser, origin, options = {}) {
  const page = await openPage(browser, origin, { extraInit: [layoutHost, ...(options.extraInit ?? [])], viewport: options.viewport ?? { width: 1000, height: 760 } });
  await page.locator(".ProseMirror").waitFor();
  await page.locator(".note-list button").first().waitFor({ state: "attached" });
  return page;
}
async function typeAndSelect(page, text, word) {
  await page.locator(".ProseMirror").click();
  await page.keyboard.insertText(text);
  await page.locator(".ProseMirror").evaluate((element, word) => {
    const at = element.editor.state.doc.textContent.indexOf(word) + 1;
    element.editor.commands.setTextSelection({ from: at, to: at + word.length });
  }, word);
}

for (const engine of browserMatrix) {
  describe(`note window layout in ${engine}`, () => {
    let server, browser;
    before(async () => { server = await startUiServer(); browser = await launchBrowser(engine); });
    after(async () => { await browser?.close(); await server?.close(); });

    test("one bar names the open note; the list, the page and one status line fill the window", async () => {
      const page = await bound(browser, server.origin);
      const bar = page.locator("header");
      await page.waitForFunction(() => document.querySelector("header strong")?.textContent === "Kitchen renovation: what we decided");
      for (const name of ["Show or hide notes", "New note", "New window"]) {
        const button = bar.getByRole("button", { name, exact: true });
        assert.equal(await button.count(), 1, name);
        assert.match(await button.getAttribute("title"), new RegExp(name.split(" ")[0], "i"), `${name} has a tooltip`);
        assert.equal((await button.textContent()).trim(), "", `${name} is an icon button`);
      }
      const box = await bar.boundingBox();
      assert.ok(box.height <= 40, `the bar is slim, got ${box.height}`);
      const side = page.getByRole("complementary", { name: "Notes" });
      assert.equal(await side.getByRole("navigation", { name: "Notes" }).count(), 1);
      // The status line is the window's one footer: local state and cloud.
      const footer = page.locator("footer");
      assert.equal(await footer.locator("[data-status]").textContent(), "Saved on this Mac");
      assert.equal(await footer.getByText("Cloud sync not connected").count(), 1);
      assert.equal(await page.getByText("Cloud sync not connected").count(), 1);
      assert.ok((await footer.boundingBox()).height <= 30, "the status line is slim");
      // No always-visible toolbar, link field or Undo button above the writing.
      assert.equal(await page.getByRole("textbox", { name: "Link URL" }).count(), 0);
      assert.equal(await page.getByRole("button", { name: "Undo" }).count(), 0);
      assert.equal(await page.getByRole("toolbar", { name: "Format" }).isVisible().catch(() => false), false);
      const fill = await page.evaluate(() => {
        const pane = document.querySelector(".note-pane").getBoundingClientRect();
        return { bottom: pane.bottom, footer: document.querySelector("footer").getBoundingClientRect().top, width: pane.width };
      });
      assert.ok(Math.abs(fill.bottom - fill.footer) <= 1, "the page reaches the status line");
      assert.ok(fill.width >= 700, `the page gets the window, got ${fill.width}`);
      await page.close();
    });

    test("the bar's toggle and Control-Command-S hide and show the notes and remember it natively", async () => {
      const page = await bound(browser, server.origin);
      const side = page.getByRole("complementary", { name: "Notes" });
      const toggle = page.getByRole("button", { name: "Show or hide notes" });
      assert.equal(await toggle.getAttribute("aria-expanded"), "true");
      await toggle.click();
      assert.equal(await visible(side), false);
      assert.equal(await toggle.getAttribute("aria-expanded"), "false");
      const width = await page.evaluate(() => document.querySelector(".note-pane").getBoundingClientRect().width);
      assert.ok(width >= 990, `the page takes the whole width, got ${width}`);
      await page.locator(".ProseMirror").click();
      await page.keyboard.press("Control+Meta+s");
      assert.equal(await visible(side), true);
      // The View menu reaches the same toggle.
      await page.evaluate(() => window.__bhMenu("sidebar"));
      assert.equal(await visible(side), false);
      assert.deepEqual(await sidebarWrites(page), [false, true, false]);
      await page.close();

      const next = await bound(browser, server.origin, { extraInit: [hidden] });
      assert.equal(await visible(next.getByRole("complementary", { name: "Notes" })), false, "a new window follows the remembered choice");
      assert.deepEqual(await sidebarWrites(next), []);
      await next.close();
    });

    test("without a native answer the notes stay shown", async () => {
      const page = await bound(browser, server.origin, { extraInit: [() => window.__bhIpc.handle("window_sidebar", () => { throw "unavailable"; })] });
      assert.equal(await visible(page.getByRole("complementary", { name: "Notes" })), true);
      await page.getByRole("button", { name: "Show or hide notes" }).click();
      assert.equal(await visible(page.getByRole("complementary", { name: "Notes" })), false, "the window still toggles");
      await page.close();
    });

    test("a narrow window opens the notes over the page and closes them after a choice", async () => {
      const page = await bound(browser, server.origin, { viewport: { width: 480, height: 600 } });
      const side = page.getByRole("complementary", { name: "Notes" });
      assert.equal(await visible(side), false, "a narrow window starts on the page");
      await page.getByRole("button", { name: "Show or hide notes" }).click();
      assert.equal(await visible(side), true);
      const over = await page.evaluate(() => getComputedStyle(document.querySelector("aside")).position);
      assert.equal(over, "absolute", "it lies over the page instead of squeezing it");
      await side.getByRole("button", { name: "Questions for Dr. Okafor" }).click();
      await page.waitForFunction(() => document.querySelector("header strong")?.textContent === "Questions for Dr. Okafor");
      assert.equal(await visible(side), false);
      assert.deepEqual(await sidebarWrites(page), [], "opening the overlay is not the remembered choice");
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.close();
    });

    test("a selection shows the formatting bubble, whose buttons and shortcuts format it", async () => {
      const page = await bound(browser, server.origin);
      const bubble = page.getByRole("toolbar", { name: "Format" });
      await page.locator(".ProseMirror").click();
      await page.keyboard.insertText("flat white fronts");
      assert.equal(await visible(bubble), false, "no bubble without a selection");
      await typeAndSelect(page, "", "white");
      await bubble.waitFor();
      for (const name of ["Bold", "Italic", "Code", "Link", "Heading", "List", "Checklist"]) {
        const button = bubble.getByRole("button", { name, exact: true });
        assert.equal(await button.count(), 1, name);
        assert.ok((await button.getAttribute("title")).length > name.length, `${name} shows its shortcut`);
      }
      const near = await page.evaluate(() => {
        const b = document.querySelector('[role="toolbar"]').getBoundingClientRect();
        const s = getSelection().getRangeAt(0).getBoundingClientRect();
        return { above: b.bottom <= s.top + 1, gap: s.top - b.bottom, overlaps: b.left < s.right && b.right > s.left };
      });
      assert.ok(near.above && near.gap < 24 && near.overlaps, `the bubble sits just above the selection: ${JSON.stringify(near)}`);
      await bubble.getByRole("button", { name: "Bold" }).click();
      assert.equal(await page.locator(".ProseMirror strong").textContent(), "white");
      assert.equal(await bubble.getByRole("button", { name: "Bold" }).getAttribute("aria-pressed"), "true");
      await page.keyboard.press("ControlOrMeta+i");
      assert.equal(await page.locator(".ProseMirror em").textContent(), "white");
      await page.keyboard.press("ControlOrMeta+e");
      assert.equal(await page.locator(".ProseMirror code").textContent(), "white");
      await bubble.getByRole("button", { name: "Heading" }).click();
      assert.equal(await page.locator(".ProseMirror h2").count(), 1);
      await bubble.getByRole("button", { name: "Checklist" }).click();
      assert.equal(await page.locator('.ProseMirror ul[data-type="taskList"]').count(), 1);
      await bubble.getByRole("button", { name: "List", exact: true }).click();
      assert.equal(await page.locator(".ProseMirror ul:not([data-type])").count(), 1);
      await page.keyboard.press("ArrowRight");
      await bubble.waitFor({ state: "hidden", timeout: 2000 }); // a collapsed selection hides it
      await page.close();
    });

    test("Link opens a small link editor from the bubble or Command-K; unsafe addresses never become links", async () => {
      const page = await bound(browser, server.origin);
      await typeAndSelect(page, "the faucet we liked", "faucet");
      await page.keyboard.press("ControlOrMeta+k");
      const dialog = page.getByRole("dialog", { name: "Link" });
      const field = dialog.getByRole("textbox", { name: "Link URL" });
      await field.waitFor();
      assert.equal(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")), "Link URL");
      await field.fill("javascript:alert(1)");
      await field.press("Enter");
      assert.equal(await page.locator(".ProseMirror a").count(), 0);
      await field.fill("https://example.org/faucet");
      await dialog.getByRole("button", { name: "Done" }).click();
      assert.equal(await page.locator(".ProseMirror a").getAttribute("href"), "https://example.org/faucet");
      assert.equal(await visible(dialog), false);
      assert.equal(await page.evaluate(() => document.activeElement?.classList.contains("ProseMirror")), true, "Done returns to the writing");
      // Editing an existing link starts from its address; Remove takes it off.
      await page.locator(".ProseMirror").evaluate((element) => {
        const at = element.editor.state.doc.textContent.indexOf("faucet") + 3;
        element.editor.commands.setTextSelection(at);
      });
      await page.getByRole("toolbar", { name: "Format" }).waitFor({ state: "hidden", timeout: 2000 });
      await page.keyboard.press("ControlOrMeta+k");
      assert.equal(await field.inputValue(), "https://example.org/faucet");
      await dialog.getByRole("button", { name: "Remove" }).click();
      assert.equal(await page.locator(".ProseMirror a").count(), 0);
      // The bubble's Link button opens the same editor; Escape returns to the writing.
      await typeAndSelect(page, "", "liked");
      await page.getByRole("toolbar", { name: "Format" }).getByRole("button", { name: "Link" }).click();
      await field.waitFor();
      await field.press("Escape");
      assert.equal(await visible(dialog), false);
      assert.equal(await page.evaluate(() => document.activeElement?.classList.contains("ProseMirror")), true);
      assert.equal(await page.evaluate(() => window.__bhIpc.calls.filter((c) => c.command.startsWith("note_") && /open|navigate/.test(c.command)).length), 1);
      await page.close();
    });

    test("the Edit menu's Undo and Redo reach the note's own history", async () => {
      const page = await bound(browser, server.origin);
      await page.locator(".ProseMirror").click();
      await page.keyboard.insertText("kept");
      await page.waitForFunction(() => document.querySelector("[data-status]")?.textContent === "Saved on this Mac");
      const send = (inputType) => page.locator(".ProseMirror").evaluate((element, inputType) =>
        element.dispatchEvent(new InputEvent("beforeinput", { inputType, bubbles: true, cancelable: true })), inputType);
      assert.equal(await send("historyUndo"), false, "the page handles the menu's Undo");
      await page.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "");
      assert.equal(await send("historyRedo"), false);
      await page.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "kept");
      await page.close();
    });

    test("New note and New window answer the File menu and their shortcuts", async () => {
      const page = await bound(browser, server.origin);
      await page.locator(".ProseMirror").click();
      await page.keyboard.press("ControlOrMeta+Alt+n");
      await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_new_window"));
      await page.evaluate(() => window.__bhMenu("new-window"));
      await page.waitForFunction(() => window.__bhIpc.calls.filter((c) => c.command === "note_new_window").length === 2);
      await page.keyboard.press("ControlOrMeta+n");
      await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_create"));
      await page.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "note_show"));
      await page.close();
    });

    test("the update is a small card under the notes; with them hidden the bar's indicator opens them", async () => {
      const page = await bound(browser, server.origin, { extraInit: [() => {
        window.__bhIpc.handle("update_status", () => ({ phase: "available", version: 43, whatsNew: "Notes reopen where you left them.", message: null }));
      }] });
      const side = page.getByRole("complementary", { name: "Notes" });
      const card = side.locator("#update-banner");
      await card.getByText("BaseHero 43 is ready").waitFor();
      const height = (await card.boundingBox()).height;
      assert.ok(height <= 130, `the card is small, got ${height}`);
      assert.equal(await visible(card.getByText("Notes reopen")), false);
      await card.getByRole("button", { name: "What’s new" }).click();
      assert.equal(await visible(card.getByText("Notes reopen where you left them.")), true, "What’s new opens in the card");
      const indicator = page.locator("header").getByRole("button", { name: "BaseHero 43 is ready" });
      assert.equal(await visible(indicator), false, "no indicator while the card shows");
      await page.getByRole("button", { name: "Show or hide notes" }).click();
      assert.equal(await visible(indicator), true);
      await indicator.click();
      assert.equal(await visible(side), true);
      assert.equal(await visible(card.getByRole("button", { name: "Install update" })), true);
      await page.close();
    });

    test("a failed save shows Not saved and Retry in the status line at once", async () => {
      const page = await bound(browser, server.origin, { extraInit: [() => {
        window.__bhIpc.handle("note_commit", () => { throw "note commit failed"; });
      }] });
      await page.locator(".ProseMirror").click();
      await page.keyboard.insertText("x");
      const footer = page.locator("footer");
      await footer.getByRole("button", { name: "Retry save" }).waitFor();
      assert.equal(await footer.locator("[data-status]").textContent(), "Not saved");
      assert.equal((await footer.getByRole("button", { name: "Retry save" }).textContent()).trim(), "Retry");
      await page.close();
    });
  });
}
