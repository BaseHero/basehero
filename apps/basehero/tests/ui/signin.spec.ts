import { test, expect, type Page } from '@playwright/test';

const kit = '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC';

async function signUp(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByLabel('Device name').fill('My Mac');
  await page.getByRole('button', { name: 'Create account' }).click();
}

async function pendingSignIn(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Continue' }).click();
}

test('sign-in with the kit reaches the account', async ({ page }) => {
  await pendingSignIn(page);
  await expect(page.getByText('Approval in the app')).toBeVisible();
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Use kit' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
});

test('a wrong kit says so and keeps what was typed', async ({ page }) => {
  await pendingSignIn(page);
  await page.getByLabel('Recovery kit').fill('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA');
  await page.getByRole('button', { name: 'Use kit' }).click();
  await expect(page.getByText("That kit doesn't match this account.")).toBeVisible();
  await expect(page.getByLabel('Recovery kit')).toHaveValue('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA');
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Use kit' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  const calls = await page.evaluate(() => window.__fake.calls);
  expect(calls.filter(call => call.startsWith('signInStart'))).toHaveLength(1);
});

test('sign-in never stores the password or the kit', async ({ page }) => {
  await pendingSignIn(page);
  await page.getByLabel('Recovery kit').fill(kit);
  await page.getByRole('button', { name: 'Use kit' }).click();
  const stored = await page.evaluate(async () => {
    const data: unknown[] = [Object.entries(localStorage), Object.entries(sessionStorage)];
    for (const database of await indexedDB.databases()) {
      if (!database.name) continue;
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(database.name);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      for (const name of db.objectStoreNames) {
        const values = await new Promise<unknown[]>((resolve, reject) => {
          const tx = db.transaction(name, 'readonly');
          const request = tx.objectStore(name).getAll();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
        data.push(values);
      }
      db.close();
    }
    return JSON.stringify(data);
  });
  expect(stored).not.toContain('correct horse battery staple');
  expect(stored).not.toContain(kit);
  const historyAndCalls = await page.evaluate(() => JSON.stringify({ state: history.state, calls: window.__fake.calls }));
  expect(historyAndCalls).not.toContain('correct horse battery staple');
  expect(historyAndCalls).not.toContain(kit);
  expect(page.url()).not.toContain(kit);
});

test('browser and Android Back leave the kit without prompting', async ({ page }) => {
  await signUp(page);
  let dialogs = 0;
  page.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
  await page.evaluate(() => window.__bhBack?.());
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  expect(dialogs).toBe(0);
});

test('kit print stays black on white in dark mode', async ({ page }) => {
  await signUp(page);
  await page.emulateMedia({ colorScheme: 'dark', media: 'print' });
  const colors = await page.getByTestId('kit').evaluate(node => {
    const style = getComputedStyle(node);
    return { ink: style.color, paper: style.backgroundColor };
  });
  expect(colors).toEqual({ ink: 'rgb(0, 0, 0)', paper: 'rgb(255, 255, 255)' });
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toHaveCSS('color', 'rgb(0, 0, 0)');
});

test('screen changes focus the heading, then Tab reaches the first field', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeFocused();
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Create account' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Invite code')).toBeFocused();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeFocused();
  await page.getByRole('button', { name: 'Later' }).click();
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeFocused();
});

test('cancelling a pending sign-in cancels the backend request', async ({ page }) => {
  await pendingSignIn(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('signInCancel')))).toBe(true);
});
