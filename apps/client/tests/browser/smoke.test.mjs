// Browser UI checks for the real bundled client shell. Each case runs in
// Chromium and WebKit so engine differences surface here rather than on a
// device. Chromium approximates an Android WebView and WebKit the macOS
// WKWebView; neither is real-device acceptance.
//
// Today the shell is a static setup screen. Navigation, editing, drafts and
// their error states need the real app UI; those cases belong here once it
// exists, and the setup-screen cases below are replaced rather than kept.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { browserMatrix, launchBrowser, openPage, shellCsp, startUiServer } from "./harness.mjs";

for (const browserName of browserMatrix) {
  describe(`client shell in ${browserName}`, () => {
    let server;
    let browser;

    before(async () => {
      server = await startUiServer();
      browser = await launchBrowser(browserName);
    });

    after(async () => {
      await browser?.close();
      await server?.close();
    });

    test("serves the real setup screen with the pre-app shell globals", async () => {
      const page = await openPage(browser, server.origin);
      assert.equal(await page.title(), "BaseHero");
      assert.equal(await page.locator("header span").textContent(), "BASEHERO");
      assert.equal(await page.locator("header strong").textContent(), "SETUP");
      assert.equal(await page.locator(".label").textContent(), "CLIENT FOUNDATION");
      assert.equal(await page.locator("h1").textContent(), "Your workspace starts here.");
      assert.match(await page.locator("main p").last().textContent(), /not available yet/);
      assert.match(await page.locator("footer").textContent(), /NO ACCOUNT OPEN/);
      // The stub stands in for the Tauri shell, installed before app code.
      assert.equal(await page.evaluate(() => typeof window.__TAURI_INTERNALS__?.invoke), "function");
      assert.equal(await page.evaluate(() => window.__bhStorageGuarded), true);
      assert.equal(await page.evaluate(() => window.__bhStorageReads), 0);
      assert.ok(Array.isArray(await page.evaluate(() => window.__bhIpc.calls)));
      await page.close();
    });

    test("follows the system colour scheme and switches it live", async () => {
      const dark = await openPage(browser, server.origin, { colorScheme: "dark" });
      assert.equal(await dark.evaluate(() => document.documentElement.dataset.mode), "dark");
      // Tokens: dark panel #131518, light panel #ffffff.
      assert.equal(await dark.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(19, 21, 24)");
      await dark.emulateMedia({ colorScheme: "light" });
      await dark.waitForFunction(() => document.documentElement.dataset.mode === "light");
      assert.equal(await dark.evaluate(() => getComputedStyle(document.body).backgroundColor), "rgb(255, 255, 255)");
      await dark.close();

      const light = await openPage(browser, server.origin, { colorScheme: "light" });
      assert.equal(await light.evaluate(() => document.documentElement.dataset.mode), "light");
      await light.emulateMedia({ colorScheme: "dark" });
      await light.waitForFunction(() => document.documentElement.dataset.mode === "dark");
      await light.close();
    });

    test("fits phone and desktop viewports without horizontal overflow", async () => {
      for (const viewport of [
        { name: "phone", width: 390, height: 844 },
        { name: "desktop", width: 1280, height: 800 },
      ]) {
        const page = await openPage(browser, server.origin, { viewport });
        const metrics = await page.evaluate(() => {
          const main = document.querySelector("main").getBoundingClientRect();
          const header = document.querySelector("header").getBoundingClientRect();
          return {
            scrollWidth: document.documentElement.scrollWidth,
            innerWidth: window.innerWidth,
            mainWidth: main.width,
            mainLeft: main.left,
            headerHeight: header.height,
            footerVisible: document.querySelector("footer").getBoundingClientRect().bottom <= window.innerHeight + 1,
          };
        });
        assert.ok(metrics.scrollWidth <= metrics.innerWidth + 1, `${viewport.name}: no horizontal scroll, got ${metrics.scrollWidth} > ${metrics.innerWidth}`);
        assert.ok(metrics.mainLeft >= 0, `${viewport.name}: content starts on screen`);
        assert.ok(metrics.mainWidth <= metrics.innerWidth + 1, `${viewport.name}: main fits, got ${metrics.mainWidth}`);
        assert.ok(metrics.headerHeight >= 56, `${viewport.name}: header keeps its bar height`);
        assert.ok(metrics.footerVisible, `${viewport.name}: footer is within the viewport`);
        if (viewport.name === "desktop") assert.ok(metrics.mainWidth <= 801, `desktop: main is capped, got ${metrics.mainWidth}`);
        await page.close();
      }
    });

    test("loads only bundled assets from the shell itself", async () => {
      const requests = [];
      const page = await browser.newPage();
      page.on("request", (request) => requests.push(request.url()));
      const response = await page.goto(`${server.origin}/`, { waitUntil: "load" });
      assert.equal(response.status(), 200);
      assert.equal(response.headers()["content-security-policy"], await shellCsp());
      assert.ok(requests.length > 0);
      for (const url of requests) {
        assert.ok(url.startsWith(`${server.origin}/`), `request stays on the shell origin: ${url}`);
      }
      assert.ok(requests.some((url) => url.endsWith("/tokens.css")));
      assert.ok(requests.some((url) => url.endsWith("/theme.js")));
      await page.close();
    });

    test("refuses inline script under the shell content security policy", async () => {
      const page = await openPage(browser, server.origin, {
        path: "__harness/probe.html",
        extraInit: [
          () => {
            window.__bhCsp = [];
            document.addEventListener("securitypolicyviolation", (event) => window.__bhCsp.push(event.violatedDirective));
          },
        ],
      });
      assert.equal((await page.evaluate(() => window.__bhProbe)).inlineRan, undefined);
      assert.ok(
        (await page.evaluate(() => window.__bhCsp)).some((directive) => directive.startsWith("script-src")),
        "the blocked inline script is reported as a script-src violation",
      );
      await page.close();
    });

    test("installs the IPC stub before the first page script", async () => {
      const withStub = await openPage(browser, server.origin, { path: "__harness/probe.html" });
      const probe = await withStub.evaluate(() => window.__bhProbe);
      assert.equal(probe.internalsAtModuleEval, "object");
      assert.equal(probe.invokeAtModuleEval, "function");
      assert.equal(probe.storageGuarded, true);
      await withStub.close();

      // Negative control: without the stub the probe sees nothing, so the
      // assertion above is evidence the stub (not the page) supplies it.
      const withoutStub = await openPage(browser, server.origin, { path: "__harness/probe.html", stub: false });
      assert.equal((await withoutStub.evaluate(() => window.__bhProbe)).internalsAtModuleEval, "undefined");
      await withoutStub.close();
    });

    test("answers a registered command and rejects unhandled ones", async () => {
      const page = await openPage(browser, server.origin, { path: "__harness/ipc.html" });
      await page.evaluate(() => window.__bhIpc.handle("bh_test_echo", (args) => ({ echoed: args.value + 1 })));
      assert.deepEqual(
        await page.evaluate(() => window.__bhIpcFixture.call("bh_test_echo", { value: 41 })),
        { ok: true, value: { echoed: 42 } },
      );

      // The shell's event plugin is not modelled: until a test registers it, it
      // rejects like any other command rather than pretending to work.
      assert.deepEqual(await page.evaluate(() => window.__bhIpcFixture.call("plugin:event|listen", { event: "bh:test" })), {
        ok: false,
        error: "no stub IPC handler for plugin:event|listen",
      });
      assert.deepEqual(await page.evaluate(() => window.__bhIpcFixture.call("bh_missing_command")), {
        ok: false,
        error: "no stub IPC handler for bh_missing_command",
      });
      assert.deepEqual(await page.evaluate(() => window.__bhIpc.calls.map((call) => call.command)), [
        "bh_test_echo",
        "plugin:event|listen",
        "bh_missing_command",
      ]);
      await page.close();
    });
  });
}
