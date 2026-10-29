import { test, expect, type Page } from '@playwright/test';

async function signed(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'Later' }).click();
  const account = await page.evaluate(() => window.__fake.accounts().then(accounts => accounts[0].id));
  const base = await page.evaluate(account => window.__fake.createBase(account, 'Personal'), account);
  return { account, personal: base.id };
}

async function request(page: Page, account: string, personal: string, old: boolean) {
  await page.evaluate(({ account, personal, old }) => {
    const entry = { id: '11111111111111111111111111111111', deviceId: '22222222222222222222222222222222', createdAt: 0, expiresAt: 120000, kind: 'App' as const };
    window.__fake.addAppRequest(account, entry);
    window.__fake.setAppOffer(entry.id, {
      name: 'Sample', appId: 'app.basehero.sample', deviceName: 'Dan - Sample',
      bases: [{ base: personal, mode: 'readWrite' }], capMicroUsd: 1000000,
      old: old ? { deviceId: 'previous', name: 'Dan - Sample', lastSeenAt: 1700000000000 } : null,
      removeOld: old,
    });
    window.__fake.emit({ kind: 'account', account, event: { ApprovalRequested: entry } });
  }, { account, personal, old });
  await expect(page.getByText('An app wants to connect.')).toBeVisible();
  await expect(page.getByText('Sample')).toHaveCount(0);
  await page.getByRole('button', { name: 'Open request' }).click();
  await expect(page.getByText("Type the six digits the app shows. Approve only an app you're setting up right now.")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(call => call.startsWith('connectOpen')))).toBe(true);
  await page.getByLabel('Digits shown in the app').fill('482913');
  await page.getByRole('button', { name: 'Check digits' }).click();
  await expect(page.getByText('Not verified')).toBeVisible();
  await expect(page.getByText("Approve only an app you're setting up right now.")).toBeVisible();
}

test('an app request is opened, checked and connected', async ({ page }) => {
  const { account, personal } = await signed(page);
  await request(page, account, personal, false);
  await expect(page.getByText('Joins your account as Dan - Sample.')).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Personal access' })).toHaveValue('readWrite');
  await expect(page.getByLabel('Monthly cap (USD)')).toHaveValue('1.00');
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ base: personal, mode: 'readWrite' }], capMicroUsd: 1000000, replaces: null,
    },
  }]);
  await expect(page.getByText('Connected Dan - Sample.')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('connectCheck')))).toHaveLength(1);
});

test('an empty base choice cannot consume the request', async ({ page }) => {
  const { account, personal } = await signed(page);
  await request(page, account, personal, false);
  const connect = page.getByRole('button', { name: 'Connect app' });
  await page.getByRole('button', { name: 'Remove Personal' }).click();
  await expect(connect).toBeDisabled();
  expect(await page.evaluate(() => window.__fake.appChoices)).toHaveLength(0);
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('combobox', { name: 'Base', exact: true }).selectOption({ label: 'New base' });
  await page.getByLabel('New base name').fill('Readings');
  await page.locator('.grant-picker').getByRole('button', { name: 'Create base' }).click();
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(connect).toBeEnabled();
  await connect.click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ base: expect.any(String), mode: 'readWrite' }], capMicroUsd: 1000000, replaces: null,
    },
  }]);
});

test('approving starts with your own base and can grant one folder instead', async ({ page }) => {
  const { account, personal } = await signed(page);
  const health = await page.evaluate(({ account, personal }) => window.__fake.createObject(
    { account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' },
  ), { account, personal });
  await request(page, account, personal, false);
  await page.getByRole('button', { name: 'Remove Personal' }).click();
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('radio', { name: 'Health' }).check();
  await page.getByRole('combobox', { name: 'Access' }).selectOption('readOnly');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.getByRole('combobox', { name: 'Health in Personal access' })).toHaveValue('readOnly');
  await page.screenshot({ path: '/tmp/bh-folder-approval.png', fullPage: true });
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ base: personal, folder: health, mode: 'readOnly' }], capMicroUsd: 1000000, replaces: null,
    },
  }]);
});

test('the picker creates a base and a folder in it', async ({ page }) => {
  const { account, personal } = await signed(page);
  await request(page, account, personal, false);
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('combobox', { name: 'Base', exact: true }).selectOption({ label: 'New base' });
  await page.getByLabel('New base name').fill('Trips');
  await page.locator('.grant-picker').getByRole('button', { name: 'Create base' }).click();
  await page.getByLabel('New folder name').fill('2027');
  await page.getByRole('button', { name: 'Create folder' }).click();
  await expect(page.getByRole('radio', { name: '2027' })).toBeChecked();
  await page.screenshot({ path: '/tmp/bh-folder-picker.png', fullPage: true });
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.getByRole('combobox', { name: '2027 in Trips access' })).toBeVisible();
  const trips = await page.evaluate(account => window.__fake.bases(account).then(list => list.find(base => base.name === 'Trips')!.id), account);
  const folder = await page.evaluate(({ account, trips }) => window.__fake.treeChildren({ account, base: trips }, null).then(list => list[0].id), { account, trips });
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices[0]?.choice.bases)).toEqual([
    { base: personal, mode: 'readWrite' }, { base: trips, folder, mode: 'readWrite' },
  ]);
});

test('the picker includes projects and folders inside granted folders', async ({ page }) => {
  const { account, personal } = await signed(page);
  const { mounted, project } = await page.evaluate(async ({ account, personal }) => {
    const health = await window.__fake.createObject({ account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' });
    const mounted = await window.__fake.grantFolder(account, personal, health, 'Other app');
    const project = await window.__fake.createObject({ account, base: mounted }, { kind: 'project', parent: null, after: null, name: 'Visits' });
    return { mounted, project };
  }, { account, personal });
  await request(page, account, personal, false);
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await expect(page.getByRole('combobox', { name: 'Base', exact: true }).locator('option')).toHaveText(['Personal', 'New base']);
  await expect(page.getByRole('radio', { name: 'Visits' })).toBeVisible();
  await page.getByRole('radio', { name: 'Health' }).check();
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('radio', { name: 'Visits' }).check();
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices[0]?.choice.bases)).toEqual([
    { base: personal, mode: 'readWrite' }, { base: mounted, mode: 'readWrite' }, { base: mounted, folder: project, mode: 'readWrite' },
  ]);
});

test('creating beneath a folder in a mounted base grants only that new folder', async ({ page }) => {
  const { account, personal } = await signed(page);
  const { mounted, visits } = await page.evaluate(async ({ account, personal }) => {
    const health = await window.__fake.createObject({ account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' });
    const mounted = await window.__fake.grantFolder(account, personal, health, 'Other app');
    const visits = await window.__fake.createObject({ account, base: mounted }, { kind: 'folder', parent: null, after: null, name: 'Visits' });
    return { mounted, visits };
  }, { account, personal });
  await request(page, account, personal, false);
  await page.getByRole('button', { name: 'Remove Personal' }).click();
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('radio', { name: 'Visits' }).check();
  await page.getByLabel('New folder name').fill('October');
  await page.getByRole('button', { name: 'Create folder' }).click();
  const october = await page.evaluate(async ({ account, mounted, visits }) => {
    const children = await window.__fake.treeChildren({ account, base: mounted }, visits);
    return children.find(item => item.title === 'October')?.id;
  }, { account, mounted, visits });
  expect(october).toBeTruthy();
  await expect(page.getByRole('radio', { name: 'October' })).toBeChecked();
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices[0]?.choice.bases)).toEqual([
    { base: mounted, folder: october, mode: 'readWrite' },
  ]);
});

test('a failed old removal still reports the new app connected', async ({ page }) => {
  const { account, personal } = await signed(page);
  await request(page, account, personal, true);
  await page.evaluate(() => window.__fake.failNextAppRemoval());
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect(page.getByText('Connected Dan - Sample.')).toBeVisible();
  await expect(page.getByText("The old connection couldn't be removed; disconnect it in Devices.")).toBeVisible();
});

test('hidden bases stay out of the offer and an old app can be replaced with read-only access', async ({ page }) => {
  const { account, personal } = await signed(page);
  await page.evaluate(account => window.__fake.createHiddenBase(account, 'Private', 'a long extra password'), account);
  await request(page, account, personal, true);
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await expect(page.getByRole('combobox', { name: 'Base', exact: true }).locator('option')).toHaveText(['Personal', 'New base']);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('checkbox', { name: /Remove the old connection/ })).toBeChecked();
  await page.getByRole('combobox', { name: 'Personal access' }).selectOption('readOnly');
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111',
    choice: { bases: [{ base: personal, mode: 'readOnly' }], capMicroUsd: 1000000, replaces: 'previous' },
  }]);
});

test('the offer can add a new base, change the cap and keep the old connection', async ({ page }) => {
  const { account, personal } = await signed(page);
  await request(page, account, personal, true);
  await page.getByRole('checkbox', { name: /Remove the old connection/ }).uncheck();
  await page.getByRole('button', { name: 'Add a base or folder' }).click();
  await page.getByRole('combobox', { name: 'Base', exact: true }).selectOption({ label: 'New base' });
  await page.getByLabel('New base name').fill('Readings');
  await page.locator('.grant-picker').getByRole('button', { name: 'Create base' }).click();
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByLabel('Monthly cap (USD)').fill('2.5');
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ base: personal, mode: 'readWrite' }, { base: expect.any(String), mode: 'readWrite' }],
      capMicroUsd: 2500000, replaces: null,
    },
  }]);
});
