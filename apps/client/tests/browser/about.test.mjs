import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';

for (const engine of browserMatrix) {
  describe(`About BaseHero in ${engine}`, () => {
    let server, browser;
    before(async () => { server = await startUiServer(); browser = await launchBrowser(engine); });
    after(async () => { await browser?.close(); await server?.close(); });
    const open = async (about) => {
      const page = await openPage(browser, server.origin, {});
      // Init scripts cannot capture local variables; register the reply in the page.
      await page.evaluate(data => window.__bhIpc.handle('app_about', () => data), about);
      await page.waitForFunction(() => typeof window.__bhAbout === 'function');
      await page.evaluate(() => window.__bhAbout());
      return page;
    };
    test('shows version, build and source commit', async () => {
      const page = await open({ version: '1.2.3', build: '42', commit: 'abc123', test_settings: [] });
      const dialog = page.getByRole('dialog', { name: 'About BaseHero' });
      await dialog.waitFor();
      for (const value of ['1.2.3', '42', 'abc123']) assert.match(await dialog.textContent(), new RegExp(value));
      await dialog.getByRole('button', { name: 'Close' }).click();
      assert.equal(await dialog.count(), 0);
      await page.close();
    });
    test('lists Test settings only when non-default', async () => {
      const base = { version: '1.2.3', build: '42', commit: 'abc123' };
      const page = await open({ ...base, test_settings: [{ name: 'removal wait', value: '5 minutes' }] });
      assert.match(await page.getByRole('dialog', { name: 'About BaseHero' }).textContent(), /Test settings[\s\S]*removal wait: 5 minutes/);
      await page.close();
      const normal = await open({ ...base, test_settings: [] });
      assert.equal(await normal.getByRole('dialog', { name: 'About BaseHero' }).getByText('Test settings').count(), 0);
      await normal.close();
    });
  });
}
