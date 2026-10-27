import { test, expect, type Page } from '@playwright/test';

async function signedIn(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  return page.evaluate(() => window.__fake.accounts().then(accounts => accounts[0].id));
}

test('devices lists this device first and removes another after confirming', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'other', name: 'Other phone', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200 },
    { id: 'mine', name: 'This Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300 },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const rows = page.locator('[data-device-id]');
  await expect(rows.nth(0)).toHaveAttribute('data-device-id', 'mine');
  await expect(rows.nth(0)).toContainText('This device');
  await expect(rows.nth(0)).toContainText('Mac');
  await expect(rows.nth(0)).toContainText('Last seen');
  await expect(rows.nth(1)).toHaveAttribute('data-device-id', 'other');
  page.once('dialog', dialog => void dialog.dismiss());
  await rows.nth(1).getByRole('button', { name: 'Remove' }).click();
  await expect(rows).toHaveCount(2);
  page.once('dialog', dialog => void dialog.accept());
  await rows.nth(1).getByRole('button', { name: 'Remove' }).click();
  await expect(rows).toHaveCount(1);
  expect(await page.evaluate(() => window.__fake.calls.some(call => call === 'removeDevice other'))).toBe(true);
});

test('removing this device confirms, erases it and shows Removed', async ({ page }) => {
  await signedIn(page);
  await page.getByRole('link', { name: 'Devices' }).click();
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.accounts().then(accounts => accounts.length))).toBe(0);
});

test('removal clears an unsaved recovery kit warning', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    window.__fake.emit({ kind: 'account', account, event: 'Removed' });
  });
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  expect(await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event.defaultPrevented;
  })).toBe(false);
});

test('when this device is removed the app says its data was erased', async ({ page }) => {
  const account = await signedIn(page);
  const r = await page.evaluate(async account => {
    const base = await window.__fake.createBase(account, 'Personal');
    const note = await window.__fake.createObject({ account, base: base.id }, { kind: 'note', parent: null, after: null, name: 'My note' });
    return { account, base: base.id, note };
  }, account);
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.getByRole('searchbox', { name: 'Search' }).fill('My note');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await page.getByRole('link', { name: 'My note' }).click();
  await expect(page.locator('.ProseMirror')).toBeVisible();
  const savedHash = new URL(page.url()).hash;
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
  await page.evaluate(r => window.__fake.emit({ kind: 'account', account: r.account, event: 'Removed' }), r);
  await expect(page.getByText('This device was removed from your account. Its notes and keys have been erased from it.')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(0);
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await page.evaluate(hash => { location.hash = hash; }, savedHash);
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  await expect(page).not.toHaveURL(savedHash);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible();
  await page.evaluate(hash => { location.hash = hash; }, savedHash);
  await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible();
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await expect(page).not.toHaveURL(savedHash);
});
