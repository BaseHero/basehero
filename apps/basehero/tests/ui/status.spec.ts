import { test, expect, type Page } from '@playwright/test';

async function signedIn(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'Later' }).click();
  const r = await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    const base = await window.__fake.createBase(account, 'Personal');
    return { account, base: base.id };
  });
  await page.getByRole('link', { name: 'Personal' }).click();
  return r;
}

test('the status bar shows offline and waiting changes, then synced', async ({ page }) => {
  const r = await signedIn(page);
  await page.evaluate(r => window.__fake.setSync(r, { online: false, pending: 3, lastSyncedAt: null }), r);
  await expect(page.getByRole('status')).toContainText('OFFLINE');
  await expect(page.getByRole('status')).toContainText('3 CHANGES WAITING');
  await page.evaluate(r => window.__fake.setSync(r, { online: true, pending: 0, lastSyncedAt: new Date(2026, 9, 27, 12, 4).getTime() }), r);
  await expect(page.getByRole('status')).toContainText('ONLINE');
  await expect(page.getByRole('status')).toContainText('SYNCED 12:04');
});

test('a sync that needs an update says so', async ({ page }) => {
  const r = await signedIn(page);
  await page.evaluate(r => window.__fake.emit({ kind: 'base', account: r.account, base: r.base, event: 'needsUpdate' }), r);
  await expect(page.getByRole('alert')).toHaveText('This version of BaseHero is too old to sync. Update it.');
});

test('on Mac an update banner offers Restart to update', async ({ page }) => {
  const r = await signedIn(page);
  await page.evaluate(() => window.__fake.setPlatform('macos'));
  await page.evaluate(() => window.__bhRestart?.());
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.evaluate(r => window.__fake.emit({ kind: 'base', account: r.account, base: r.base, event: 'NeedsUpdate' }), r);
  await page.getByRole('button', { name: 'Restart to update' }).click();
  expect(await page.evaluate(() => window.__fake.calls.includes('updateInstall'))).toBe(true);
});

test('on phones the status dot opens the same text', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const r = await signedIn(page);
  await page.evaluate(r => window.__fake.setSync(r, { online: false, pending: 2, lastSyncedAt: null }), r);
  await page.getByRole('button', { name: 'Sync status' }).click();
  await expect(page.getByRole('status')).toContainText('OFFLINE');
  await expect(page.getByRole('status')).toContainText('2 CHANGES WAITING');
  const dot = page.getByRole('button', { name: 'Sync status' });
  const offlineColor = await dot.evaluate(el => getComputedStyle(el).color);
  await page.evaluate(r => window.__fake.setSync(r, { online: true, pending: 0, lastSyncedAt: null }), r);
  await expect(page.getByRole('status')).toContainText('ONLINE');
  const onlineColor = await dot.evaluate(el => getComputedStyle(el).color);
  expect(offlineColor).not.toBe(onlineColor);
});
