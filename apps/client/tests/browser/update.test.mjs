// The Mac update banner in the real shell: native owns discovery, trust and
// installation; the page only shows signed text and asks for Install update.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { browserMatrix, launchBrowser, openPage, startUiServer } from "./harness.mjs";

const installs = (page) => page.evaluate(() => window.__bhIpc.calls.filter((c) => c.command === "update_install").length);
const status = (page, next) => page.evaluate((next) => { window.__release = next; }, next);

for (const engine of browserMatrix) {
  describe(`Mac update banner in ${engine}`, () => {
    let server, browser;
    before(async () => { server = await startUiServer(); browser = await launchBrowser(engine); });
    after(async () => { await browser?.close(); await server?.close(); });
    const available = () => {
      window.__release = { phase: "available", version: 43, whatsNew: "Safer notes <img src=x onerror=alert(1)>", message: null };
      window.__bhIpc.handle("update_status", () => window.__release);
      window.__bhIpc.handle("update_install", () => { window.__release = { phase: "downloading", version: 43 }; });
      window.__bhIpc.handle("update_not_now", () => { window.__release = { ...window.__release, phase: "dismissed" }; });
    };

    test("signed notes are text and only Install update starts the download", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [available] });
      await page.getByText("BaseHero 43 is ready").waitFor();
      assert.equal(await installs(page), 0);
      await page.getByRole("button", { name: "What’s new" }).click();
      assert.match(await page.locator("#update-notes").textContent(), /Safer notes <img/);
      assert.equal(await page.locator("#update-notes img").count(), 0);
      await page.getByRole("button", { name: "Install update" }).click();
      await page.getByText("Downloading BaseHero 43").waitFor();
      await page.getByRole("progressbar", { name: "Downloading update" }).waitFor();
      assert.equal(await installs(page), 1);
      assert.equal(await page.getByRole("heading", { level: 1 }).count(), 1, "the page stays usable");
      await page.close();
    });

    test("a refused save offers Try again and never a discard", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [available] });
      await page.getByText("BaseHero 43 is ready").waitFor();
      await status(page, { phase: "retry", version: 43, message: "Some writing couldn't be saved, so BaseHero didn't restart. Your writing is still here." });
      await page.getByText(/Your writing is still here/).waitFor();
      assert.equal(await page.getByRole("button", { name: /discard|without saving/i }).count(), 0);
      await page.getByRole("button", { name: "Try again" }).click();
      assert.equal(await installs(page), 1);
      await page.getByText("Downloading BaseHero 43").waitFor();
      await page.close();
    });

    test("errors and an installed-but-not-restarted update explain and dismiss", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [available] });
      await page.getByText("BaseHero 43 is ready").waitFor();
      await status(page, { phase: "saving", version: 43 });
      await page.getByText("Saving your writing before BaseHero restarts…").waitFor();
      assert.equal(await page.getByRole("button", { name: "Install update" }).isVisible(), false);
      await status(page, { phase: "restart", version: 43, message: "BaseHero 43 is installed, but couldn't restart. Quit and reopen BaseHero to finish." });
      await page.getByText(/installed, but couldn't restart/).waitFor();
      await page.getByRole("button", { name: "Dismiss" }).click();
      await page.getByText(/installed, but couldn't restart/).waitFor({ state: "hidden" });
      assert.equal(await installs(page), 0);
      await page.close();
    });

    test("Not now dismisses without downloading", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [available] });
      await page.getByText("BaseHero 43 is ready").waitFor();
      await page.getByRole("button", { name: "Not now" }).click();
      await page.getByText("BaseHero 43 is ready").waitFor({ state: "hidden" });
      assert.equal(await installs(page), 0);
      await page.close();
    });

    test("a transient status rejection does not stop polling", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [() => {
        let calls = 0;
        window.__bhIpc.handle("update_status", () => {
          if (++calls === 1) throw new Error("temporary IPC failure");
          return { phase: "available", version: 43, whatsNew: "Safer notes", message: null };
        });
      }] });
      await page.getByText("BaseHero 43 is ready").waitFor({ timeout: 5000 });
      assert.ok(await page.evaluate(() => window.__bhIpc.calls.filter((c) => c.command === "update_status").length) >= 2);
      await page.close();
    });

    test("a disabled updater hides the banner and stops asking", async () => {
      const page = await openPage(browser, server.origin, { extraInit: [() => {
        window.__bhIpc.handle("update_status", () => ({ phase: "disabled" }));
      }] });
      await page.waitForTimeout(1800);
      assert.equal(await page.evaluate(() => window.__bhIpc.calls.filter((c) => c.command === "update_status").length), 1);
      assert.equal(await page.locator("#update-banner").isHidden(), true);
      await page.close();
    });
  });
}
