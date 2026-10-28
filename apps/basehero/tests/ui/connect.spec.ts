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
  await expect(page.getByRole('checkbox', { name: 'Personal' })).toBeChecked();
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
  await page.getByRole('checkbox', { name: 'Personal' }).uncheck();
  await expect(connect).toBeDisabled();
  await page.getByLabel('New base').fill('   ');
  await expect(connect).toBeDisabled();
  expect(await page.evaluate(() => window.__fake.appChoices)).toHaveLength(0);
  await page.getByLabel('New base').fill('Readings');
  await expect(connect).toBeEnabled();
  await connect.click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ newName: 'Readings', mode: 'readWrite' }], capMicroUsd: 1000000, replaces: null,
    },
  }]);
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
  await expect(page.getByRole('checkbox', { name: 'Private' })).toHaveCount(0);
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
  await page.getByLabel('New base').fill('Readings');
  await page.getByLabel('Monthly cap (USD)').fill('2.5');
  await page.getByRole('button', { name: 'Connect app' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.appChoices)).toEqual([{
    account, id: '11111111111111111111111111111111', choice: {
      bases: [{ base: personal, mode: 'readWrite' }, { newName: 'Readings', mode: 'readWrite' }],
      capMicroUsd: 2500000, replaces: null,
    },
  }]);
});
