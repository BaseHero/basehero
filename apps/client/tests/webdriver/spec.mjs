// Shared real-app WebDriver spec: one browser session against a running
// BaseHero client over the plugin's W3C endpoint. Used by every platform
// runner (Linux/Xvfb, macOS, Android emulator).
//
//   node spec.mjs [screenshot.png]
//
// It asserts the real first-run welcome screen DOM text and a valid non-empty PNG, and ends
// the session. It is not a browser stub: the client must already be running.
import { writeFileSync } from "node:fs";
import { remote } from "webdriverio";

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
try {
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
