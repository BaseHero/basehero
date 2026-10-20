// Shared real-app WebDriver spec: one browser session against a running
// BaseHero client over the plugin's W3C endpoint. Used by every platform
// runner (Linux/Xvfb, macOS, Android emulator).
//
//   node spec.mjs [screenshot.png]
//
// It asserts the real first-run welcome screen DOM text and a valid non-empty PNG, and ends
// the session. It is not a browser stub: the client must already be running.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { remote } from "webdriverio";
import { startPeer } from "./presence-peer.mjs";

const shotPath = process.argv[2] ?? "session-screenshot.png";
const port = 4445;
const marks = [];
const t0 = performance.now();
const mark = (name) => {
  const ms = Math.round(performance.now() - t0);
  marks.push([name, ms]);
  console.log("  " + name + ": " + ms + " ms");
};

const browser = await remote({
  hostname: "127.0.0.1",
  port,
  path: "/",
  logLevel: "error",
  capabilities: { browserName: "chrome" },
  connectionRetryCount: 2,
  connectionRetryTimeout: 30000,
});
mark("create session");
const sessionId = browser.sessionId;

const failures = [];
const presence = process.env.WEBDRIVER_PRESENCE === "1";
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(action, label, timeout = 60_000) {
  let last;
  for (const end = Date.now() + timeout; Date.now() < end; await sleep(250)) {
    last = await action();
    if (last) return last;
  }
  throw Error(`timeout: ${label}; last=${JSON.stringify(last)}`);
}
// Where the remote caret is drawn: the paragraph text position whose caret
// box its 2 px line stands on. Not a hit test: the format bubble may cover it.
const remoteCaret = () => browser.execute(() => {
  const widget = document.querySelector(".bh-remote-cursor");
  if (!widget) return null;
  const view = document.querySelector(".ProseMirror").editor.view;
  const box = widget.getBoundingClientRect();
  let at = null;
  view.state.doc.forEach((paragraph, start) => {
    for (let offset = 0; !at && offset <= paragraph.content.size; offset++) {
      const caret = view.coordsAtPos(start + 1 + offset, -1);
      if (Math.abs(caret.left - box.left) < 1.5 && Math.abs(caret.bottom - box.bottom) < 1.5)
        at = { offset, text: paragraph.textContent };
    }
  });
  if (!at) return null;
  const label = widget.querySelector(".bh-remote-label")?.textContent ?? null;
  return { label: widget.dataset.label ?? null, drawn: label, offset: at.offset,
    collapsed: widget.hasAttribute("data-collapsed"), text: at.text };
});
try {
  if (presence) {
    await waitFor(async () => (await browser.execute(
      () => document.querySelector("main .label")?.textContent === "WELCOME")), "welcome screen", 60_000);
  }
  const h1 = await browser.$("h1");
  mark("find h1");
  const heading = await h1.getText();
  mark("h1 getText");
  const title = await browser.getTitle();
  mark("get title");
  const url = await browser.getUrl();
  mark("get url");
  const pageSource = await browser.getPageSource();
  mark("get page source");

  const shell = await browser.execute(() => {
    const q = (s) => document.querySelector(s)?.textContent?.trim() ?? null;
    return {
      label: q(".label"),
      heading: q("h1"),
      paragraph: q("main p:not(.label)"),
      footer: q("footer"),
      actions: [...document.querySelectorAll("main button")]
        .filter((node) => !node.hidden && node.offsetParent !== null)
        .map((node) => node.textContent.trim()),
    };
  });
  mark("execute/sync read shell");

  // Exercise the click endpoint on a static element and prove nothing navigated.
  await h1.click();
  mark("click h1");
  const urlAfterClick = await browser.getUrl();

  // The driver evaluates JS through the native WebView API, so the page's strict
  // CSP must not block it; a script the page injects itself must still be blocked.
  const inline = await browser.execute(() => {
    const script = document.createElement("script");
    script.textContent = "window.__bh_inline = 1";
    document.body.appendChild(script);
    return window.__bh_inline === 1;
  });
  mark("execute/sync inline-script probe");
  const arithmetic = await browser.execute("return 6 * 7;");
  mark("execute/sync arithmetic");

  const png = Buffer.from(await browser.takeScreenshot(), "base64");
  mark("screenshot");
  writeFileSync(shotPath, png);
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const isPng = png.subarray(0, 8).equals(signature);
  const width = isPng ? png.readUInt32BE(16) : 0;
  const height = isPng ? png.readUInt32BE(20) : 0;

  const expected = {
    heading: "A place for your thoughts.",
    label: "WELCOME",
    paragraph: "Keep notes in your own space. You do not need an email to create an account.",
    footer: "Cloud sync not connected",
  };
  for (const [key, want] of Object.entries(expected)) {
    if (shell[key] !== want) failures.push(`${key}: got ${JSON.stringify(shell[key])}, want ${JSON.stringify(want)}`);
  }
  if (heading !== expected.heading) failures.push("h1.getText(): got " + JSON.stringify(heading));
  if (!title.includes("BaseHero")) failures.push("title: got " + JSON.stringify(title));
  if (!pageSource.includes("You do not need an email to create an account.")) failures.push("page source lacks the welcome sentence");
  const actions = JSON.stringify(shell.actions);
  if (actions !== JSON.stringify(["Create my account", "I already have an account"])) failures.push("welcome actions: got " + actions);
  if (!isPng) failures.push("screenshot is not a PNG");
  if (png.length === 0) failures.push("screenshot is empty");
  if (arithmetic !== 42) failures.push("execute/sync arithmetic: got " + JSON.stringify(arithmetic));
  if (inline) failures.push("the page's own inline script ran despite the CSP");
  if (urlAfterClick !== url) failures.push("click changed the url: " + JSON.stringify(urlAfterClick));

  if (presence) {
    const root = process.env.SYNC_RUN;
    const shots = process.env.PRESENCE_SHOTS;
    if (!root || !shots) throw Error("presence run needs SYNC_RUN and PRESENCE_SHOTS");
    mkdirSync(shots, { recursive: true });
    const peer = await startPeer({ root, endpoint: process.env.SYNC_HOST_ENDPOINT,
      bin: process.env.SYNC_PEER_BIN });
    try {
      await peer.call("signup", { password: "ripple amber horizon nectar willow" });
      const identity = await peer.call("open");
      await peer.call("save", { window: "main", note: identity.home, text: "Existing peer note" });
      await peer.until(async () => (await peer.call("status")).view?.state === "synced",
        "peer note accepted");
      const shown = await peer.call("show");

      // The desktop joins the peer's account through its own paste flow.
      await browser.execute(() => {
        const button = [...document.querySelectorAll("main button")]
          .find(node => node.textContent.trim() === "I already have an account");
        if (!button) throw new Error("no join button");
        button.click();
      });
      await waitFor(async () => browser.execute(() => !!document.querySelector("#pair-code")),
        "pairing code field");
      await browser.execute(qr => {
        const field = document.querySelector("#pair-code");
        field.value = qr;
        field.dispatchEvent(new Event("input", { bubbles: true }));
        const button = [...document.querySelectorAll("main button")]
          .find(node => node.textContent.trim() === "Join");
        if (!button) throw new Error("no join action");
        button.click();
      }, shown.qr);
      await peer.until(async () => (await peer.call("pair-status", { session: shown.session })).state
        === "candidate", "desktop candidate");
      await peer.call("approve", { session: shown.session });
      await peer.until(async () => (await peer.call("pair-status", { session: shown.session })).state
        === "ordered", "desktop added");
      await waitFor(async () => browser.execute(() => {
        const editor = document.querySelector(".ProseMirror");
        return editor?.textContent.includes("Existing peer note") ?? false;
      }), "note after joining", 120_000);

      const first = await peer.call("relative", { window: "main", note: identity.home,
        paragraph: 0, offset: 2 });
      await peer.call("select", { window: "main", note: identity.home,
        anchor: first.hex, head: first.hex, label: "Mac" });
      const atFirst = await waitFor(async () => {
        const caret = await remoteCaret();
        return caret?.label === "Mac" && caret.offset === 2 ? caret : null;
      }, "remote Mac caret");
      if (atFirst.drawn !== "Mac" || atFirst.collapsed) failures.push(
        `remote label: got ${JSON.stringify({ drawn: atFirst.drawn, collapsed: atFirst.collapsed })}`);
      writeFileSync(path.join(shots, "desktop-presence-caret.png"),
        Buffer.from(await browser.takeScreenshot(), "base64"));

      const second = await peer.call("relative", { window: "main", note: identity.home,
        paragraph: 0, offset: 12 });
      await peer.call("select", { window: "main", note: identity.home,
        anchor: second.hex, head: second.hex, label: "Mac" });
      const atSecond = await waitFor(async () => {
        const caret = await remoteCaret();
        return caret?.offset === 12 ? caret : null;
      }, "remote Mac caret moved");
      if (atSecond.drawn !== "Mac" || atSecond.collapsed) failures.push(
        `remote label after move: got ${JSON.stringify({ drawn: atSecond.drawn, collapsed: atSecond.collapsed })}`);
      writeFileSync(path.join(shots, "desktop-presence-moved.png"),
        Buffer.from(await browser.takeScreenshot(), "base64"));

      await peer.call("clear");
      await waitFor(async () => (await remoteCaret()) === null, "remote Mac caret cleared");
      writeFileSync(path.join(shots, "desktop-presence-cleared.png"),
        Buffer.from(await browser.takeScreenshot(), "base64"));
      marks.push(["presence caret at", atFirst.offset], ["presence caret moved to", atSecond.offset]);
    } finally {
      await peer.quit();
    }
  }
  console.log(JSON.stringify({
    sessionId, url, title, heading, shell,
    inlineScriptBlocked: !inline,
    screenshot: { path: shotPath, bytes: png.length, width, height, isPng },
    marks, failures,
  }, null, 2));
} catch (error) {
  failures.push("probe error: " + error);
} finally {
  try {
    await browser.deleteSession();
    mark("delete session");
  } catch (error) {
    failures.push("delete session failed: " + error);
  }
}

if (failures.length > 0) {
  console.error(`FAIL (${failures.length}):`);
  for (const failure of failures) console.error("- " + failure);
  process.exit(1);
}
console.log("PASS: real welcome-screen DOM, click, execute/sync, valid non-empty PNG, session ended");
