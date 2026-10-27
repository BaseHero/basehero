import { test, expect } from '@playwright/test';

test('non-Mac platforms do not show an update even when available', async ({ page }) => {
  await page.goto('/?update=0.1.1&platform=android');
  await expect(page.getByText('BaseHero 0.1.1 is ready')).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.some(c => c === 'updateCheck'))).toBe(false);
});

test('an update installs only when asked', async ({ page }) => {
  await page.goto('/?update=0.1.1');
  await expect(page.getByText('BaseHero 0.1.1 is ready')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'updateInstall').length)).toBe(0);
  await page.getByRole('button', { name: 'Restart to update' }).click();
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'updateInstall').length)).toBe(1);
});
