import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { adb, bh, launch, signUpOnDev, webview } from './lib.mjs';

test('the emulator removes a second full device with both answers', { timeout: 240_000 }, async () => {
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  const page = await webview();
  try {
    const credentials = await signUpOnDev(page);
    let kit = credentials.kit;
    for (const lost of [false, true]) {
      const home = mkdtempSync(join(tmpdir(), 'bh-removal-'));
      let signed;
      try {
        signed = bh(['signin', '--server', 'https://dev-api.basehero.com', '--email', credentials.email,
          '--name', lost ? 'Lost device' : 'Kept device', '--kit', kit], { home, password: credentials.password });
      } finally { rmSync(home, { recursive: true, force: true }); }
      await page.getByRole('link', { name: 'Personal' }).click();
      await page.getByRole('link', { name: 'Devices' }).click();
      const device = page.locator(`[data-device-id="${signed.deviceId}"]`);
      await device.getByRole('button', { name: 'Remove' }).click();
      await page.getByText('Do you still have this device?').waitFor();
      await page.getByLabel('Password').fill(credentials.password);
      await page.getByRole('button', { name: lost ? "It's lost or stolen" : 'I still have it' }).click();
      if (lost) {
        await page.getByRole('heading', { name: 'Your recovery kit' }).waitFor();
        kit = (await page.getByTestId('kit').textContent()).trim();
        assert.notEqual(kit, credentials.kit);
        await page.screenshot({ path: '/tmp/bh-removal-lost-android.png', mask: [page.getByTestId('kit')] });
        await page.getByRole('button', { name: 'Later' }).click();
      } else {
        await device.waitFor({ state: 'detached' });
        assert.equal(kit, credentials.kit);
        await page.screenshot({ path: '/tmp/bh-removal-kept-android.png' });
      }
    }
  } finally {
    await page.context().browser()?.close();
  }
});
