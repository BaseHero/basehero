import { test, expect, type Page } from '@playwright/test';

async function signedIn(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'Later' }).click();
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

test('Devices shows an app cap, changes it and disconnects', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, capMicroUsd: null },
    { id: 'sample', name: 'Dan - Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, capMicroUsd: 1000000 },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="sample"]');
  await expect(row).toContainText('Cap $1.00 a month');
  await row.getByRole('button', { name: 'Change cap' }).click();
  await row.getByLabel('Monthly cap (USD)').fill('0.50');
  await row.getByRole('button', { name: 'Save' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.includes('setAppCap sample 500000'))).toBe(true);
  await expect(row).toContainText('Cap $0.50 a month');
  page.once('dialog', async dialog => { expect(dialog.message()).toBe('Disconnect Dan - Sample? It erases its copy of your data.'); await dialog.accept(); });
  await row.getByRole('button', { name: 'Disconnect' }).click();
  await expect(row).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.includes('removeDevice sample'))).toBe(true);
});

test('Devices adds and removes an app folder', async ({ page }) => {
  const account = await signedIn(page);
  const { personal, health, device } = await page.evaluate(async account => {
    const personal = (await window.__fake.createBase(account, 'Personal')).id;
    const health = await window.__fake.createObject({ account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' });
    window.__fake.setAppOffer('request', { name: 'Sample', appId: 'sample', deviceName: 'Dan - Sample', bases: [], capMicroUsd: 1000000, old: null, removeOld: false });
    const [device] = await window.__fake.connectApprove(account, 'request', { bases: [{ base: personal, mode: 'readWrite' }], capMicroUsd: 1000000, replaces: null });
    window.__fake.setDevices(account, [
      { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, capMicroUsd: null },
      { id: device, name: 'Dan - Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, capMicroUsd: 1000000 },
    ]);
    return { personal, health, device };
  }, account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator(`[data-device-id="${device}"]`);
  await expect(row).toContainText('Personal');
  await row.getByRole('button', { name: 'Add a base or folder' }).click();
  await row.getByRole('radio', { name: 'Health' }).check();
  await row.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(row).toContainText('Health in Personal');
  await page.screenshot({ path: '/tmp/bh-folder-devices.png' });
  const mounted = await page.evaluate(({ account, device }) => window.__fake.apps(account).then(list => list.find(app => app.deviceId === device)!.bases[1].base), { account, device });
  expect(await page.evaluate(({ account, personal, health }) => window.__fake.bases(account).then(list => list.find(base => base.mount?.folder === health)?.mount?.parent === personal), { account, personal, health })).toBe(true);
  page.once('dialog', async dialog => { expect(dialog.message()).toBe("Remove Sample's access to Health in Personal? The app erases its copy of it."); await dialog.accept(); });
  await row.getByRole('button', { name: 'Remove Health in Personal' }).click();
  await expect(row).not.toContainText('Health in Personal');
  expect(await page.evaluate(({ account, device, mounted }) => window.__fake.apps(account).then(list => !list.find(app => app.deviceId === device)!.bases.some(grant => grant.base === mounted)), { account, device, mounted })).toBe(true);
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('appGrantRemove')))).toBe(true);
});

test('removing this device confirms, erases it and shows Removed', async ({ page }) => {
  await signedIn(page);
  await page.getByRole('link', { name: 'Devices' }).click();
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.accounts().then(accounts => accounts.length))).toBe(0);
});

test('a server sign-out keeps the notes and leaves erasing to the person', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.emit({ kind: 'account', account, event: 'SignedOutByServer' }), account);
  const alert = page.getByRole('alert').filter({ hasText: 'The server signed this device out' });
  await expect(alert).toHaveText(/none of your devices removed it\. Its notes stay here and won't sync\./);
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.accounts().then(accounts => accounts.length))).toBe(1);
  page.once('dialog', async dialog => {
    expect(dialog.message()).toBe("Erase BaseHero's notes and keys on this device? Changes that haven't synced are lost.");
    await dialog.accept();
  });
  await alert.getByRole('button', { name: 'Erase this device' }).click();
  await expect(page.getByRole('heading', { name: 'Device removed' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.accounts().then(accounts => accounts.length))).toBe(0);
});

test('a server sign-out of an account not on screen shows when it opens', async ({ page }) => {
  await signedIn(page);
  const other = await page.evaluate(async () => {
    const result = await window.__fake.signUp({ invite: 'WELCOME', email: 'two@example.com', password: 'correct horse battery staple', deviceName: 'Mac' });
    window.__fake.emit({ kind: 'account', account: result.account.id, event: 'SignedOutByServer' });
    return result.account.id;
  });
  await expect(page.getByRole('alert').filter({ hasText: 'The server signed this device out' })).toHaveCount(0);
  await page.evaluate(id => { location.hash = `#/a/${id}`; }, other);
  await expect(page.getByRole('link', { name: 'Devices' })).toHaveAttribute('href', `#/a/${other}/devices`);
  await expect(page.getByRole('alert').filter({ hasText: 'The server signed this device out' })).toBeVisible();
});

test('a window opened after a server sign-out shows it', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      fake.accounts = async () => [{ id: 'known', email: 'known@example.com', kind: 'full', signedOutByServer: true }];
    } });
  });
  await page.goto('/');
  await expect(page.getByRole('alert').filter({ hasText: 'The server signed this device out' })).toBeVisible();
});

test('removal clears kit state without a leave warning', async ({ page }) => {
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
