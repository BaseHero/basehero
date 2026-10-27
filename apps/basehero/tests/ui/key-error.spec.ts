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
