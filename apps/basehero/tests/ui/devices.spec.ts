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

test('removing a device asks for the password and whether you still have it', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'other', name: 'Other phone', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
    { id: 'mine', name: 'This Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const rows = page.locator('[data-device-id]');
  await expect(rows.nth(0)).toHaveAttribute('data-device-id', 'mine');
  await expect(rows.nth(0)).toContainText('This device');
  await expect(rows.nth(0)).toContainText('Mac');
  await expect(rows.nth(0)).toContainText('Last seen');
  await expect(rows.nth(1)).toHaveAttribute('data-device-id', 'other');
  await rows.nth(1).getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByText('Do you still have this device?')).toBeVisible();
  const removalPassword = rows.nth(1).getByLabel('Password');
  await expect(removalPassword).toBeFocused();
  await page.screenshot({ path: '/tmp/bh-removal-question.png' });
  await removalPassword.fill('wrong');
  await page.getByRole('button', { name: 'I still have it' }).click();
  await expect(page.getByRole('alert')).toContainText('Email or password is wrong.');
  await expect(removalPassword).toHaveValue('');
  await expect(removalPassword).toBeFocused();
  await expect(rows).toHaveCount(2);
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'I still have it' }).click();
  await expect(rows).toHaveCount(1);
  expect(await page.evaluate(() => window.__fake.calls.includes('removeDevice other kept'))).toBe(true);
});

test('a full device removal stays visibly busy until the backend returns', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => {
    const fake = window.__fake;
    fake.setDevices(account, [
      { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
      { id: 'other', name: 'Fold', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
    ]);
    const original = fake.removeDevice.bind(fake);
    fake.removeDevice = async (...args) => {
      fake.calls.push('removeDevice held');
      await new Promise<void>(resolve => { Object.assign(fake, { releaseRemoval: resolve }); });
      return original(...args);
    };
  }, account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="other"]');
  await row.getByRole('button', { name: 'Remove' }).click();
  await row.getByLabel('Password').fill('correct horse battery staple');
  await row.getByRole('button', { name: 'I still have it' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(call => call === 'removeDevice held').length)).toBe(1);
  await expect(row.getByRole('status')).toHaveText('Removing…');
  await expect(row.getByRole('button', { name: 'I still have it' })).toBeDisabled();
  await expect(row.getByRole('button', { name: "It's lost or stolen" })).toBeDisabled();
  await row.getByRole('button', { name: 'I still have it' }).click({ force: true });
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call === 'removeDevice held').length)).toBe(1);
  await page.evaluate(() => (window.__fake as typeof window.__fake & { releaseRemoval: () => void }).releaseRemoval());
  await expect(row).toHaveCount(0);
});

test('the removal question stays beneath the device row on the Fold', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
    { id: 'other', name: 'Fold', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="other"]');
  const button = row.getByRole('button', { name: 'Remove' });
  await button.click();
  const form = row.locator('form');
  const buttonBox = (await button.boundingBox())!;
  const formBox = (await form.boundingBox())!;
  expect(formBox.y).toBeGreaterThanOrEqual(buttonBox.y + buttonBox.height);
  expect(formBox.x + formBox.width).toBeLessThanOrEqual(390);
  await expect(form.getByRole('button', { name: "It's lost or stolen" })).toBeVisible();
  await page.screenshot({ path: '/tmp/bh-removal-question-fold.png', fullPage: true });
});

test('a lost device shows the new recovery kit', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
    { id: 'other', name: 'Fold', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.locator('[data-device-id="other"]').getByRole('button', { name: 'Remove' }).click();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: "It's lost or stolen" }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
  await page.screenshot({ path: '/tmp/bh-removal-new-kit.png' });
  await expect(page.getByTestId('kit')).not.toContainText('7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC');
  expect(await page.evaluate(() => window.__fake.calls.includes('removeDevice other lost'))).toBe(true);
});

test('a new kit is shown even while re-keying is pending', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => {
    window.__fake.setDevices(account, [
      { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
      { id: 'other', name: 'Fold', kind: 'Android', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
    ]);
    window.__fake.setNextRemovalPending(true);
  }, account);
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.locator('[data-device-id="other"]').getByRole('button', { name: 'Remove' }).click();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: "It's lost or stolen" }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
  await expect(page.getByTestId('kit')).not.toContainText('7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC');
  await page.getByRole('button', { name: 'Later' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="other"]');
  await expect(row.getByRole('status')).toHaveText('Removing…');
  await expect(row.getByRole('button', { name: 'Remove' })).toBeDisabled();
});

test('Devices shows an app cap, changes it and disconnects', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false, capMicroUsd: null },
    { id: 'sample', name: 'Dan - Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false, capMicroUsd: 1000000 },
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
  await expect(row).toContainText('Removing…');
  await expect(row.getByRole('button', { name: 'Disconnect' })).toBeDisabled();
  await page.evaluate(({ account }) => window.__fake.finishRemoval(account, 'sample'), { account });
  await expect(row).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.includes('removeDevice sample'))).toBe(true);
});

test('a newly pending app cannot save its already-open cap form', async ({ page }) => {
  const account = await signedIn(page);
  const mine = { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active' as const, thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false };
  const app = { id: 'sample', name: 'Sample', kind: 'App', status: 'active' as const, thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false, capMicroUsd: 1_000_000 };
  await page.evaluate(({ account, mine, app }) => window.__fake.setDevices(account, [mine, app]), { account, mine, app });
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="sample"]');
  await row.getByRole('button', { name: 'Change cap' }).click();
  await row.getByLabel('Monthly cap (USD)').fill('0.50');
  await page.evaluate(({ account, mine, app }) => {
    window.__fake.setDevices(account, [mine, { ...app, pendingRemoval: true }]);
    window.__fake.emit({ kind: 'account', account, event: 'DevicesChanged' });
  }, { account, mine, app });
  await expect(row.getByRole('status')).toHaveText('Removing…');
  await expect(row.getByRole('button', { name: 'Save' })).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('setAppCap')))).toBe(false);
});

test('a newly pending app cannot use its already-open grant picker', async ({ page }) => {
  const account = await signedIn(page);
  const mine = { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active' as const, thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false };
  const app = { id: 'sample', name: 'Sample', kind: 'App', status: 'active' as const, thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false };
  await page.evaluate(({ account, mine, app }) => window.__fake.setDevices(account, [mine, app]), { account, mine, app });
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="sample"]');
  await row.getByRole('button', { name: 'Add a base or folder' }).click();
  await expect(row.locator('.grant-picker')).toBeVisible();
  await page.evaluate(({ account, mine, app }) => {
    window.__fake.setDevices(account, [mine, { ...app, pendingRemoval: true }]);
    window.__fake.emit({ kind: 'account', account, event: 'DevicesChanged' });
  }, { account, mine, app });
  await expect(row.getByRole('status')).toHaveText('Removing…');
  await expect(row.locator('.grant-picker')).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('appGrantAdd')))).toBe(false);
});

test('Devices adds and removes an app folder', async ({ page }) => {
  const account = await signedIn(page);
  const { personal, health, device } = await page.evaluate(async account => {
    const personal = (await window.__fake.createBase(account, 'Personal')).id;
    const health = await window.__fake.createObject({ account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' });
    window.__fake.setAppOffer('request', { name: 'Sample', appId: 'sample', deviceName: 'Dan - Sample', bases: [], capMicroUsd: 1000000, old: null, removeOld: false });
    const [device] = await window.__fake.connectApprove(account, 'request', { bases: [{ base: personal, mode: 'readWrite' }], capMicroUsd: 1000000, replaces: null });
    window.__fake.setDevices(account, [
      { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false, capMicroUsd: null },
      { id: device, name: 'Dan - Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false, capMicroUsd: 1000000 },
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

test('pending folder removal remains visible until DevicesChanged and disables app actions', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
    { id: 'sample', name: 'Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: true },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="sample"]');
  await expect(row).toContainText('Removing…');
  await page.screenshot({ path: '/tmp/bh-removal-pending.png' });
  await expect(row.getByRole('button', { name: 'Disconnect' })).toBeDisabled();
  await expect(row.getByRole('button', { name: 'Add a base or folder' })).toBeDisabled();
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  await expect(row).toContainText('Removing…');
  await page.evaluate(account => {
    window.__fake.setDevices(account, [
      { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
      { id: 'sample', name: 'Sample', kind: 'App', status: 'active', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: false },
    ]);
    window.__fake.emit({ kind: 'account', account, event: 'DevicesChanged' });
  }, account);
  await expect(row).not.toContainText('Removing…');
  await expect(row.getByRole('button', { name: 'Disconnect' })).toBeEnabled();
});

test('a pending full device removal remains visible until re-keying finishes', async ({ page }) => {
  const account = await signedIn(page);
  await page.evaluate(account => window.__fake.setDevices(account, [
    { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
    { id: 'other', name: 'Fold', kind: 'Android', status: 'revoked', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: true },
  ]), account);
  await page.getByRole('link', { name: 'Devices' }).click();
  const row = page.locator('[data-device-id="other"]');
  await expect(row.getByRole('status')).toHaveText('Removing…');
  await expect(row.getByRole('button', { name: 'Remove' })).toBeDisabled();
  await page.evaluate(account => window.__fake.finishRemoval(account, 'other'), account);
  await expect(row).toHaveCount(0);
});

test('a pending app removal is restored when Devices first loads after a restart', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      fake.accounts = async () => [{ id: 'known', email: 'known@example.com', kind: 'full', signedOutByServer: false }];
      fake.setDevices('known', [
        { id: 'mine', name: 'Mac', kind: 'Mac', status: 'active', thisDevice: true, createdAt: 100, lastSeenAt: 300, pendingRemoval: false },
        { id: 'sample', name: 'Sample', kind: 'App', status: 'revoked', thisDevice: false, createdAt: 100, lastSeenAt: 200, pendingRemoval: true },
      ]);
    } });
  });
  await page.goto('/#/a/known/devices');
  const row = page.locator('[data-device-id="sample"]');
  await expect(row).toContainText('Removing…');
  await expect(row.getByRole('button', { name: 'Disconnect' })).toBeDisabled();
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
