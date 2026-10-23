// Pairing and sync status screens against a page-side model of the native
// pairing and sync hosts. The model is a test host: no relay, account,
// native prompt or camera runs here; those are native and device checks.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { browserMatrix, launchBrowser, startUiServer } from "./harness.mjs";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

const QR = "BH1:" + "Q".repeat(163);
// What native draws: one path. The page imports nothing else from it.
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 29 29"><path d="M4 4h1v1h-1zM6 4h1v1h-1z"/></svg>';

// A bound note window, as the native note host serves it.
function boundNote() {
  const ipc = window.__bhIpc;
  const note = Array(32).fill(7);
  const usable = { revision: 1, state: "synced", pending: 0, network: "on", home: "done", account: "active", confirm: false };
  const model = (window.__bhModel = { note, sync: usable, page: 0, hold: false, held: [], pairing: [], join: [] });
  // Native's status post: an eval naming the page native bound when it was
  // posted, which returns at once on any other page (note_host.rs).
  window.__bhPost = (view, page = String(model.page)) => {
    if (window.__bhNotePage !== page) return;
    window.dispatchEvent(new CustomEvent("sync://status", { detail: view }));
  };
  // A publication: the account's current view changes and is posted.
  window.__bhPublish = (view) => { model.sync = view; window.__bhPost(view); };
  // Every binding rotates the window's page.
  ipc.handle("note_binding", () => ({ note: model.note, surface: String(++model.page) }));
  // The current view, only for the window's current page. A held answer is
  // the view as it was when asked, delivered when the test releases it.
  ipc.handle("sync_status", ({ surface }) => {
    if (surface !== String(model.page)) throw "status unavailable";
    const answer = model.sync;
    return model.hold ? new Promise((resolve) => model.held.push(() => resolve(answer))) : answer;
  });
  ipc.handle("note_create", () => Array(32).fill(8));
  ipc.handle("note_show", ({ note: shown }) => { model.note = shown; return null; });
  ipc.handle("note_list", () => [{ note, title: "Weekend plans", touched: 1 }]);
  ipc.handle("note_open", () => ({ clientId: 2002468231004600, writerToken: Array(32).fill(9), updates: [[0, 0]], generation: 1, sequence: 0 }));
  ipc.handle("note_commit", ({ requestId }) => ({ requestId }));
  ipc.handle("note_close", () => null);
  ipc.handle("note_selection", () => []);
  ipc.handle("window_sidebar", () => true);
}

// The first-run window of a device with no account.
function firstRun() {
  const ipc = window.__bhIpc;
  window.__bhModel = { screen: { screen: "welcome" }, join: [], joined: 0 };
  ipc.handle("note_binding", () => null);
  ipc.handle("account_screen", () => window.__bhModel.screen);
  ipc.handle("account_suggest_password", () => ({ screen: "password", suggested: "acorn breeze copper dawn elm" }));
  ipc.handle("account_open_note", () => null);
}

async function page(browser, origin, init, { userAgent, viewport } = {}) {
  const view = await browser.newPage({ userAgent, viewport });
  await view.addInitScript(tauriIpcStub);
  for (const script of init) {
    if (Array.isArray(script)) await view.addInitScript(...script);
    else await view.addInitScript(script);
  }
  await view.goto(`${origin}/`, { waitUntil: "load" });
  return view;
}
const calls = (view, command) => view.evaluate((name) =>
  window.__bhIpc.calls.filter((call) => call.command === name).map((call) => call.args), command);
// Publish to the window's current page, as native does after a change.
const sync = (view, detail) => view.evaluate((d) => window.__bhPublish(d), detail);
let revision = 100;
const view = (state, extra = {}) => ({ revision: ++revision, state, pending: 0, network: "on", home: "done", account: "active", confirm: false, ...extra });
const cloudState = (v) => v.evaluate(() => document.querySelector("footer .cloud")?.dataset.sync);
// Let the page finish what a released answer started (one task turn).
const settle = (v) => v.evaluate(() => new Promise((resolve) => setTimeout(resolve, 0)));
const ANDROID = "Mozilla/5.0 (Linux; Android 16; Pixel 10 Pro Fold) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36";

for (const engine of browserMatrix) {
  describe(`pairing and sync status in ${engine}`, () => {
    test("the status line keeps local saving apart from every network state", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          window.__bhModel.sync = { revision: 1, state: "waiting-network", pending: 2, network: "on", home: "done", account: "active", confirm: false };
        }]);
        await v.locator(".ProseMirror").waitFor();
        const cloud = v.locator("footer .cloud");
        // A (re)bound page asks for the current status once it is installed.
        await v.waitForFunction(() => document.querySelector("footer .cloud")?.dataset.sync === "waiting-network");
        assert.match(await cloud.textContent(), /Waiting for network/);
        assert.equal(await v.locator("[data-status]").textContent(), "Saved on this Mac", "local save is separate");
        const seen = new Map();
        const states = [
          view("saved-local", { pending: 3 }), view("syncing", { pending: 2 }), view("synced"),
          view("waiting-network", { pending: 1 }), view("waiting-authorization"), view("history-missing"),
          view("unsupported"), view("stopped"), view("publishing-stopped"),
          view("not-accepted", { notes: 2 }), view("control-not-accepted"),
        ];
        for (const state of states) {
          await sync(v, state);
          const text = await cloud.textContent();
          assert.equal(await cloud.getAttribute("data-sync"), state.state);
          assert.ok(text.length > 0, state.state);
          seen.set(state.state, text);
        }
        assert.equal(new Set(seen.values()).size, states.length, "each state reads differently");
        assert.match(seen.get("synced"), /Synced/);
        assert.match(seen.get("syncing"), /^Syncing 2 notes/);
        await sync(v, view('syncing', { pending: 1 }));
        assert.equal(await v.locator('footer .cloud .sync-text').textContent(), 'Syncing 1 note');
        await sync(v, view('synced'));
        assert.equal(await v.locator('footer .cloud .sync-text').textContent(), 'Synced');
        assert.match(seen.get("saved-local"), /Saved on this device/);
        assert.doesNotMatch(seen.get("stopped"), /reset|discard/i);
        // No endpoint in this build: local only, never a cloud claim.
        await sync(v, view("saved-local", { pending: 1, network: "off", home: null }));
        assert.equal(await v.locator("footer .cloud .sync-text").textContent(), "Cloud sync not connected");
        assert.doesNotMatch(await cloud.textContent(), /Synced/);
        // Home setup is shown on its own; it never hides behind Synced.
        await sync(v, view("synced", { home: "retrying", homeReason: "unavailable" }));
        assert.match(await cloud.textContent(), /Synced/);
        assert.match(await v.locator("footer .home").textContent(), /not yet stored/i);
        await sync(v, view("synced", { home: "done" }));
        assert.equal(await v.locator("footer .home").isVisible(), false);
        // A copy that waits for the person offers one explicit confirmation.
        await v.evaluate(() => window.__bhIpc.handle("pairing_reconfirm", () => null));
        await sync(v, view("waiting-authorization", { confirm: true }));
        await v.getByRole("button", { name: "Confirm on this device" }).click();
        await v.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "pairing_reconfirm"));
        assert.equal((await calls(v, "pairing_reconfirm")).length, 1);
        assert.equal(await v.locator("[data-status]").textContent(), "Saved on this Mac");
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a status published while a page binds is the one a quiet account shows", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          const model = window.__bhModel;
          model.sync = { revision: 1, state: "syncing", pending: 2, network: "on", home: "done", account: "active", confirm: false };
          window.__bhIpc.handle("note_binding", () => {
            const surface = String(++model.page);
            // Native has bound the new page; this page has not installed it,
            // so the post for this publication returns without a status.
            window.__bhPublish({ ...model.sync, revision: 2, state: "synced", pending: 0 });
            return { note: model.note, surface };
          });
        }]);
        await v.locator(".ProseMirror").waitFor();
        // Nothing else is ever published: the page must have asked for it.
        await v.waitForFunction(() => document.querySelector("footer .cloud")?.dataset.sync === "synced", null, { timeout: 5000 });
        assert.equal(await v.locator("footer .cloud .sync-text").textContent(), "Synced");
        assert.deepEqual(await calls(v, "sync_status"), [{ surface: "1" }]);
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a status published just after native answers reaches the page", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          const model = window.__bhModel;
          model.sync = { revision: 1, state: "syncing", pending: 2, network: "on", home: "done", account: "active", confirm: false };
          window.__bhIpc.handle("sync_status", ({ surface }) => {
            if (surface !== String(model.page)) throw "status unavailable";
            const answer = model.sync;
            // Native read its view, then a publication posts to this page.
            window.__bhPublish({ ...model.sync, revision: 2, state: "synced", pending: 0 });
            return answer;
          });
        }]);
        await v.locator(".ProseMirror").waitFor();
        await v.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "sync_status"));
        await settle(v);
        assert.equal(await cloudState(v), "synced", "the post found its page, and the older answer stayed behind it");
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("an older status answer never replaces a newer pushed status", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          Object.assign(window.__bhModel, { hold: true,
            sync: { revision: 5, state: "syncing", pending: 2, network: "on", home: "done", account: "active", confirm: false } });
        }]);
        await v.locator(".ProseMirror").waitFor();
        await v.waitForFunction(() => window.__bhModel.held.length === 1);
        // A newer status reaches the page before its answer (revision 5) does.
        await sync(v, { revision: 6, state: "synced", pending: 0, network: "on", home: "done", account: "active", confirm: false });
        assert.equal(await cloudState(v), "synced");
        await v.evaluate(() => window.__bhModel.held.shift()());
        await settle(v);
        assert.equal(await cloudState(v), "synced");
        assert.equal(await v.locator("footer .cloud .sync-text").textContent(), "Synced");
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a previous page's status, pushed or answered late, never reaches the next page", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          Object.assign(window.__bhModel, { hold: true,
            sync: { revision: 8, state: "syncing", pending: 2, network: "on", home: "done", account: "active", confirm: false } });
        }]);
        await v.locator(".ProseMirror").waitFor();
        await v.waitForFunction(() => window.__bhModel.held.length === 1);
        await sync(v, { revision: 9, state: "waiting-network", pending: 2, network: "on", home: "done", account: "active", confirm: false });
        assert.equal(await cloudState(v), "waiting-network");
        // The window moves to a new page whose current view has a lower
        // revision than the old page showed: it is still that page's own.
        await v.evaluate(() => Object.assign(window.__bhModel, { hold: false,
          sync: { revision: 3, state: "synced", pending: 0, network: "on", home: "done", account: "active", confirm: false } }));
        await v.getByRole("button", { name: "New note" }).click();
        await v.waitForFunction(() => document.querySelector("footer .cloud")?.dataset.sync === "synced", null, { timeout: 5000 });
        assert.deepEqual(await calls(v, "sync_status"), [{ surface: "1" }, { surface: "2" }]);
        // A post native made for page 1, and page 1's late answer (revision 8).
        await v.evaluate(() => window.__bhPost({ revision: 10, state: "stopped", pending: 0, network: "on", home: "done", account: "stopped", confirm: false }, "1"));
        await v.evaluate(() => window.__bhModel.held.shift()());
        await settle(v);
        assert.equal(await cloudState(v), "synced");
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("Add a device waits for a usable cloud account, and home setup says why it retries", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, () => {
          Object.assign(window.__bhModel, { hold: true,
            sync: { revision: 1, state: "saved-local", pending: 0, network: "off", home: null, account: "active", confirm: false } });
        }]);
        await v.locator(".ProseMirror").waitFor();
        const add = v.getByRole("button", { name: "Add a device" });
        const text = v.locator("footer .cloud .sync-text");
        // Before the first status nothing is claimed either way.
        await v.waitForFunction(() => window.__bhModel.held.length === 1);
        assert.equal(await add.isVisible(), false);
        assert.doesNotMatch(await text.textContent(), /not connected|Synced/);
        assert.ok((await text.textContent()).length > 0);
        await v.evaluate(() => window.__bhModel.held.shift()());
        await v.waitForFunction(() => document.querySelector("footer .cloud")?.dataset.sync === "saved-local");
        assert.equal(await text.textContent(), "Cloud sync not connected");
        assert.equal(await add.isVisible(), false, "a local-only build cannot add a device");
        await sync(v, view("synced"));
        assert.equal(await add.isVisible(), true);
        await sync(v, view("unsupported", { network: "unsupported", home: null }));
        assert.equal(await add.isVisible(), false);
        await sync(v, view("stopped", { account: "stopped" }));
        assert.equal(await add.isVisible(), false);
        // Each fixed reason reads on screen, apart from the network line.
        const home = v.locator("footer .home");
        const reasons = new Set();
        for (const homeReason of ["unavailable", "refused", "setup-not-ready", "other"]) {
          await sync(v, view("synced", { home: "retrying", homeReason }));
          assert.equal(await home.isVisible(), true);
          assert.match(await home.textContent(), /not yet stored/);
          reasons.add(await home.textContent());
        }
        assert.equal(reasons.size, 4, "each reason reads differently");
        assert.equal(await text.textContent(), "Synced");
        assert.equal(await add.isVisible(), true);
        // One note is one note, also when native names no count.
        await sync(v, view("not-accepted", { notes: 1 }));
        assert.match(await text.textContent(), /^1 note not accepted/);
        await sync(v, view("not-accepted"));
        assert.match(await text.textContent(), /^1 note not accepted/);
        await sync(v, view("not-accepted", { notes: 3 }));
        assert.match(await text.textContent(), /^3 notes not accepted/);
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a note window shows a code, its candidate's plain-text name and approves once", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, [([qr, svg]) => {
          const ipc = window.__bhIpc;
          window.__bhModel.status = { state: "waiting" };
          ipc.handle("pairing_show", () => ({ session: "s1", qrText: qr, qrSvg: svg }));
          ipc.handle("pairing_status", () => window.__bhModel.status);
          ipc.handle("pairing_approve", () => (window.__bhModel.status = { ...window.__bhModel.status, state: "approving" }));
          ipc.handle("pairing_cancel", () => (window.__bhModel.status = { state: "cancelled" }));
        }, [QR, SVG]]]);
        await v.locator(".ProseMirror").waitFor();
        const add = v.getByRole("button", { name: "Add a device" });
        await add.click();
        const dialog = v.getByRole("dialog", { name: "Add a device" });
        await dialog.waitFor();
        // The code: one imported path, no script, no foreign markup.
        assert.equal(await dialog.locator("svg path").count(), 1);
        assert.equal(await dialog.locator("svg script, svg foreignObject, svg [onload]").count(), 0);
        assert.match(await dialog.textContent(), /Keep this screen open/);
        await v.evaluate(() => { window.__bhModel.status = { state: "candidate", label: "<img src=x onerror=window.__bhPwned=1>Pixel" }; });
        const approve = dialog.getByRole("button", { name: /Approve/ });
        await approve.waitFor();
        assert.match(await dialog.textContent(), /Add <img src=x onerror=window.__bhPwned=1>Pixel\?/);
        assert.equal(await dialog.locator("img").count(), 0, "a name is text, never markup");
        assert.equal(await v.evaluate(() => window.__bhPwned), undefined);
        // A double activation still approves once.
        await approve.dblclick();
        await dialog.getByText(/Confirm on this/).waitFor();
        assert.equal((await calls(v, "pairing_approve")).length, 1, "one approval");
        await dialog.getByText(/Confirm on this/).waitFor();
        await v.evaluate(() => { window.__bhModel.status = { state: "ordered", label: "Pixel" }; });
        await dialog.getByText(/Pixel was added/).waitFor();
        assert.deepEqual((await calls(v, "pairing_status")).at(-1), { session: "s1" });
        await dialog.getByRole("button", { name: "Done" }).click();
        await dialog.waitFor({ state: "hidden" });
        assert.equal(await v.evaluate(() => document.activeElement?.getAttribute("aria-label")), "Add a device", "focus returns");
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a late approval shows the code expired, and closing cancels the session", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [boundNote, [([qr, svg]) => {
          const ipc = window.__bhIpc;
          window.__bhModel.status = { state: "candidate", label: "Pixel" };
          ipc.handle("pairing_show", () => ({ session: "s2", qrText: qr, qrSvg: svg }));
          ipc.handle("pairing_status", () => window.__bhModel.status);
          ipc.handle("pairing_approve", () => ({ state: "approving", label: "Pixel" }));
          ipc.handle("pairing_cancel", () => ({ state: "cancelled" }));
        }, [QR, SVG]]]);
        await v.locator(".ProseMirror").waitFor();
        await v.getByRole("button", { name: "Add a device" }).click();
        const dialog = v.getByRole("dialog", { name: "Add a device" });
        await dialog.getByRole("button", { name: /Approve/ }).click();
        await v.evaluate(() => { window.__bhModel.status = { state: "failed", label: "Pixel", reason: "expired" }; });
        await dialog.getByText(/This code expired/).waitFor();
        assert.doesNotMatch(await dialog.textContent(), /Pixel was added/);
        await dialog.getByRole("button", { name: "Show a new code" }).waitFor();
        await v.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden" });
        assert.deepEqual((await calls(v, "pairing_cancel")).at(-1), { session: "s2" });
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("desktop first run keeps both choices; a pasted code joins and shows progress to ready", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [firstRun, () => {
          const ipc = window.__bhIpc;
          window.__bhModel.joinStatus = { state: "waiting-approval" };
          ipc.handle("pairing_join", ({ qrText }) => {
            if (!qrText.startsWith("BH1:")) throw "pairing code invalid";
            window.__bhModel.joined++;
            return { ticket: "t1" };
          });
          ipc.handle("pairing_join_status", () => window.__bhModel.joinStatus);
        }]);
        await v.getByRole("button", { name: "Create my account" }).waitFor();
        await v.getByRole("button", { name: "I already have an account" }).click();
        await v.getByRole("button", { name: "Use my other device" }).click();
        await v.getByRole("heading", { name: /Join your account/ }).waitFor();
        assert.equal(await v.locator("#pair-scan").count(), 1, "the scan slot");
        // Joining makes no claim about this device's cloud sync.
        assert.equal(await v.locator("footer").textContent(), "");
        const input = v.getByLabel("Pairing code");
        await input.fill("not a code");
        await v.getByRole("button", { name: "Join" }).click();
        await v.getByRole("alert").filter({ hasText: /isn.t a BaseHero pairing code/ }).waitFor();
        await input.fill(QR);
        await input.press("Enter");
        await v.getByText(/Approve this device on your other device/).waitFor();
        assert.equal(await v.evaluate(() => window.__bhModel.joined), 1, "one submission");
        assert.deepEqual((await calls(v, "pairing_join")).at(-1), { qrText: QR });
        await v.evaluate(() => { window.__bhModel.joinStatus = { state: "bootstrapping", done: 3, total: 10 }; });
        await v.getByText("Downloading your notes: 3 of 10").waitFor();
        assert.equal(await v.locator("footer").textContent(), "");
        await v.evaluate(() => {
          window.__bhModel.joinStatus = { state: "ready", done: 10, total: 10 };
          window.__bhModel.screen = { screen: "ready" };
        });
        await v.waitForFunction(() => window.__bhIpc.calls.some((c) => c.command === "account_open_note"));
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("Android's first run offers joining and a scan joins the same way", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [firstRun, () => {
          window.__bhIpc.handle("pairing_join", () => ({ ticket: "t2" }));
          window.__bhIpc.handle("pairing_join_status", () => ({ state: "waiting-approval" }));
        }], { userAgent: ANDROID, viewport: { width: 412, height: 915 } });
        await v.getByRole("heading", { name: "Welcome back" }).waitFor();
        await v.getByRole("button", { name: "Use my other device" }).click();
        await v.getByRole("heading", { name: /Join your account/ }).waitFor();
        assert.equal(await v.locator("main .label").first().textContent(), "WELCOME");
        assert.equal(await v.locator("footer").textContent(), "");
        assert.equal(await v.getByRole("button", { name: "Create my account" }).count(), 0);
        assert.equal(await v.getByRole("button", { name: "Back" }).count(), 1);
        // The camera seam: a scanner fills #pair-scan and hands over the text.
        await v.evaluate((code) => document.getElementById("pair-scan")
          .dispatchEvent(new CustomEvent("bh-pair-code", { detail: { code } })), QR);
        await v.getByText(/Approve this device on your other device/).waitFor();
        assert.deepEqual((await calls(v, "pairing_join")).at(-1), { qrText: QR });
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("refusal, expiry and a lost connection are shown with their way forward", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [firstRun, () => {
          window.__bhModel.joinStatus = { state: "refused", reason: "refused" };
          window.__bhIpc.handle("pairing_join", () => ({ ticket: "t3" }));
          window.__bhIpc.handle("pairing_join_status", () => window.__bhModel.joinStatus);
        }]);
        await v.getByRole("button", { name: "I already have an account" }).click();
        await v.getByRole("button", { name: "Use my other device" }).click();
        await v.getByLabel("Pairing code").fill(QR);
        await v.getByRole("button", { name: "Join" }).click();
        await v.getByText(/was not added/).waitFor();
        await v.getByRole("button", { name: "Scan again" }).click();
        await v.getByLabel("Pairing code").waitFor();
        await v.evaluate(() => { window.__bhModel.joinStatus = { state: "failed", reason: "expired" }; });
        await v.getByLabel("Pairing code").fill(QR);
        await v.getByRole("button", { name: "Join" }).click();
        await v.getByText(/code expired/).waitFor();
        // A lost connection after admission keeps the progress: retry resumes.
        await v.evaluate(() => {
          window.__bhModel.joinStatus = { state: "failed", reason: "network" };
          window.__bhModel.screen = { screen: "joining", ticket: "t3" };
        });
        await v.getByRole("button", { name: "Scan again" }).click();
        await v.getByLabel("Pairing code").fill(QR);
        await v.getByRole("button", { name: "Join" }).click();
        await v.getByText(/Couldn.t reach BaseHero/).waitFor();
        await v.evaluate(() => { window.__bhModel.joinStatus = { state: "bootstrapping", done: 1, total: 4 }; });
        await v.getByRole("button", { name: "Try again" }).click();
        await v.getByText("Downloading your notes: 1 of 4").waitFor();
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a stopped account says so and offers no reset", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(engine);
      try {
        const v = await page(browser, server.origin, [firstRun, () => {
          window.__bhModel.screen = { screen: "stopped" };
        }]);
        await v.getByRole("heading", { name: "Sync stopped" }).waitFor();
        assert.match(await v.locator("main").textContent(), /still on this device/);
        assert.equal(await v.getByRole("button").filter({ hasText: /reset|discard|delete/i }).count(), 0);
        await v.close();
      } finally { await browser.close(); await server.close(); }
    });
  });
}
