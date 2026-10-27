import { test, expect } from '@playwright/test';

test('the welcome screen shows the version and follows the system mode', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeVisible();
  await expect(page.getByText(/^Version \d+\.\d+\.\d+$/)).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-mode', 'dark');
});
