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

test('sign-up shows the kit once and continues only once it is saved', async ({ page }) => {
  await signUp(page);
  await expect(page.getByTestId('kit')).toHaveText(/^([0-9A-Z]{4}-){6}[0-9A-Z]{2}$/);
  await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled();
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId('kit')).toHaveCount(0);
});

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

test('the UI never stores the password or the kit', async ({ page }) => {
  await signUp(page);
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
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

test('browser and Android Back ask before losing an unacknowledged kit', async ({ page }) => {
  await signUp(page);
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); expect(dialog.message()).toContain("You haven't saved your recovery kit"); void dialog.dismiss(); });
  await page.goBack();
  await expect(page.getByTestId('kit')).toBeVisible();
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); void dialog.accept(); });
  await page.evaluate(() => window.__bhBack?.());
  await expect(page.getByRole('button', { name: 'Make a new recovery kit' })).toBeVisible();
  await expect(page.getByTestId('kit')).toHaveCount(0);
  expect(await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event.defaultPrevented;
  })).toBe(true);
});

test('unacknowledged kit warns on reload and window close', async ({ page, context }) => {
  await signUp(page);
  const reloadWarning = page.waitForEvent('dialog');
  void page.evaluate(() => { location.reload(); }).catch(() => {});
  const dialog = await reloadWarning;
  expect(dialog.type()).toBe('beforeunload');
  await dialog.dismiss();
  await expect(page.getByTestId('kit')).toBeVisible();
  const closeWarning = page.waitForEvent('dialog');
  await page.close({ runBeforeUnload: true });
  const closeDialog = await closeWarning;
  expect(closeDialog.type()).toBe('beforeunload');
  await closeDialog.dismiss();
  expect(context.pages()).toContain(page);
});

test('an unsaved account can make a fresh kit after Back, then clear the reminder', async ({ page }) => {
  await signUp(page);
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Back' }).click();
  await page.evaluate(() => window.__bhRestart?.());
  await expect(page.getByRole('button', { name: 'Make a new recovery kit' })).toBeVisible();
  await page.getByRole('button', { name: 'Make a new recovery kit' }).click();
  await page.getByLabel('Password').fill('wrong');
  await page.getByRole('button', { name: 'Make kit' }).click();
  await expect(page.getByText('Email or password is wrong.')).toBeVisible();
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Make kit' }).click();
  const fresh = await page.getByTestId('kit').textContent();
  expect(fresh).toMatch(/^([0-9A-Z]{4}-){6}[0-9A-Z]{2}$/);
  expect(fresh).not.toBe(kit);
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('button', { name: 'Make a new recovery kit' })).toHaveCount(0);
  const logAndHistory = await page.evaluate(() => JSON.stringify({ calls: window.__fake.calls, state: history.state }));
  expect(logAndHistory).not.toContain('correct horse battery staple');
  expect(logAndHistory).not.toContain(fresh!);
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('newKit ')))).toHaveLength(2);
});

test('kit print stays black on white in dark mode', async ({ page }) => {
  await signUp(page);
  await page.emulateMedia({ colorScheme: 'dark', media: 'print' });
  const colors = await page.getByTestId('kit').evaluate(node => {
    const style = getComputedStyle(node);
    return { ink: style.color, paper: style.backgroundColor };
  });
  expect(colors).toEqual({ ink: 'rgb(0, 0, 0)', paper: 'rgb(255, 255, 255)' });
  await expect(page.getByRole('heading', { name: 'Save your recovery kit' })).toHaveCSS('color', 'rgb(0, 0, 0)');
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
  await expect(page.getByRole('heading', { name: 'Save your recovery kit' })).toBeFocused();
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeFocused();
});

test('cancelling a pending sign-in cancels the backend request', async ({ page }) => {
  await pendingSignIn(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.some(call => call.startsWith('signInCancel')))).toBe(true);
});
