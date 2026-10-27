import { test, expect } from '@playwright/test';

test('an unreachable device key shows the key error, not Welcome', async ({ page }) => {
  await page.goto('/?keyError');                           // the fake's accounts() fails with KeyUnavailable
  await expect(page.getByRole('heading', { name: "BaseHero can't reach its key on this device." })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'BaseHero', exact: true })).toHaveCount(0);
  const details = page.locator('details');
  await expect(details).not.toHaveAttribute('open');
  await expect(details).toContainText('KeyUnavailable: Keychain status -25308');
  await details.getByText('Technical details').click();
  await expect(details).toHaveAttribute('open');
  await expect(details.getByText('KeyUnavailable: Keychain status -25308')).toBeVisible();
});

test('reset asks once, cancellation preserves the key error, confirmation returns to welcome', async ({ page }) => {
  await page.goto('/?keyError');
  const reset = page.getByRole('button', { name: 'Reset this device' });
  await expect(reset).toBeVisible();
  await reset.click();
  await expect(page.getByText(/Unsynced changes/)).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: "BaseHero can't reach its key on this device." })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call === 'resetDevice'))).toEqual([]);
  await reset.click();
  await page.getByRole('button', { name: 'Erase and reset' }).click();
  await expect(page.getByRole('heading', { name: 'BaseHero', exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call === 'resetDevice'))).toEqual(['resetDevice']);
});
