import { test, expect, type Page } from '@playwright/test';

const month = new Date().toISOString().slice(0, 7);
const previous = new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)) - 2, 1)).toISOString().slice(0, 7);
const day = `${month}-01`;
const hiddenId = '11111111111111111111111111111111';
const removedId = '22222222222222222222222222222222';

type Row = { period: string; service: string; base: string | null; device: string | null; requests: number; unreported: number; promptTokens: number; completionTokens: number; costMicroUsd: number; priceMicroUsd: number; storedBytes: number };
function row(period: string, base: string | null, device: string | null, priceMicroUsd: number, requests = 1, service = 'model', unreported = 0): Row {
  return { period, service, base, device, requests, unreported, promptTokens: 0, completionTokens: 0, costMicroUsd: Math.round(priceMicroUsd / 1.5), priceMicroUsd, storedBytes: 0 };
}
async function signedIn(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'Later' }).click();
  const account = await page.evaluate(() => window.__fake.accounts().then(accounts => accounts[0].id));
  await page.evaluate(({ account, month, previous, day, hiddenId, removedId }) => {
    const r = (period: string, base: string | null, device: string | null, priceMicroUsd: number, requests = 1, service = 'model', unreported = 0) =>
      ({ period, service, base, device, requests, unreported, promptTokens: 0, completionTokens: 0, costMicroUsd: Math.round(priceMicroUsd / 1.5), priceMicroUsd, storedBytes: 0 });
    window.__fake.seedUsage(account, {
      months: [r(month, 'personal', 'app', 340000, 2), { ...r(month, 'work', null, 1250000, 0, 'storage'), storedBytes: 5_242_880 }, r(month, hiddenId, removedId, 20000, 1, 'model', 1), { ...r(month, hiddenId, null, 10000, 0, 'storage'), storedBytes: 1000 }, r(month, null, 'phone', 10000), r(previous, 'personal', 'app', 70000)],
      days: [r(day, 'personal', 'app', 340000, 2), r(day, hiddenId, removedId, 20000, 1, 'model', 1), r(day, null, 'phone', 10000)],
      baseNames: { personal: 'Personal', work: 'Work' }, deviceNames: { app: 'Writer app', phone: 'My phone' },
    });
  }, { account, month, previous, day, hiddenId, removedId });
  await page.getByRole('link', { name: 'Usage' }).click();
  await expect(page.getByRole('heading', { name: 'Usage' })).toBeVisible();
  return account;
}

test('shows this month and sorts service, base and app totals by price', async ({ page }) => {
  await signedIn(page);
  await expect(page.getByText('This month: $1.63')).toBeVisible();
  await expect(page.locator('[data-usage-group="service"] li')).toContainText(['storage', 'model']);
  await expect(page.locator('[data-usage-group="base"] li')).toContainText(['Work', 'Personal', 'Other']);
  await expect(page.locator('[data-usage-group="app"] li')).toContainText(['Writer app', 'a removed device', 'My phone']);
  await expect(page.locator('[data-usage-group="app"]')).not.toContainText('not broken down');
  await expect(page.locator('[data-usage-group="base"]')).toContainText('5 MiB stored');
  await expect(page.locator('[data-usage-group="base"]')).toContainText('1000 bytes stored');
  await expect(page.locator('section.history').last()).not.toContainText('storage');
  await expect(page.getByText('Calls with no reported cost: 1')).toBeVisible();
  await expect(page.getByText('Days and months are UTC.')).toBeVisible();
  await expect(page.getByText("Storage is a month at today's size.")).toBeVisible();
});

test('choosing a prior month loads its days and updates the headline', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(({ account, previous, priorDay }) => window.__fake.seedUsageDays(account, previous, [priorDay]), { account, previous, priorDay: row(previous + '-02', 'personal', 'app', 70000) });
  await page.getByRole('button', { name: previous }).click();
  await expect(page.getByText(`${previous}: $0.07`)).toBeVisible();
  await expect(page.getByText("Storage is a month at today's size.")).toHaveCount(0);
  await expect(page.getByRole('row', { name: new RegExp(`${previous}-02.*1.*\\$0\\.0467.*\\$0\\.07`) })).toBeVisible();
  await expect(page.locator('table').first()).toContainText('Our cost');
  await expect(page.locator('table').first()).toContainText('Price');
  await expect.poll(() => page.evaluate(previous => window.__fake.calls.some(c => c === `usage ${previous}`), previous)).toBe(true);
});

test('unnamed base usage is folded with no-base usage under Other without leaking IDs', async ({ page }) => {
  await signedIn(page);
  const other = page.locator('[data-usage-group="base"] li').filter({ hasText: 'Other' });
  await expect(other).toContainText('$0.04');
  await expect(other).toContainText('2 calls');
  await expect(page.locator('main')).not.toContainText(hiddenId);
  await expect(page.locator('main')).not.toContainText(removedId);
  await expect(page.getByText('a base you no longer have')).toHaveCount(0);
});

test('empty account shows no use and small amounts retain four decimals', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.seedUsage(account, { months: [], days: [], baseNames: {}, deviceNames: {} }), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.getByRole('link', { name: 'Usage' }).click();
  await expect(page.getByText('No use yet.')).toBeVisible();
  await page.evaluate(({ account, small }) => window.__fake.seedUsage(account, { months: [small], days: [], baseNames: {}, deviceNames: {} }), { account, small: row(month, null, null, 1234) });
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.getByRole('link', { name: 'Usage' }).click();
  await expect(page.getByText('This month: $0.0012')).toBeVisible();
});

test('Usage has no horizontal overflow at Fold and desktop sizes', async ({ page }) => {
  await signedIn(page);
  for (const [width, height] of [[412, 915], [1280, 800]]) {
    await page.setViewportSize({ width, height });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (test.info().project.name === 'chromium') await page.screenshot({ path: `/tmp/bh-usage-${width}x${height}.png` });
  }
});
