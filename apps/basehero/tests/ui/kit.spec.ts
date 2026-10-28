import { test, expect, type Page } from '@playwright/test';

const originalKit = '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC';
const password = 'correct horse battery staple';
const reminder = "Save your recovery kit. You'll need it to open your account if you lose your devices.";

async function signUp(page: Page, url = '/') {
  await page.goto(url);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Device name').fill('My Mac');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByTestId('kit')).toHaveText(originalKit);
}

async function storedData(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const data: unknown[] = [Object.entries(localStorage), Object.entries(sessionStorage)];
    for (const { name } of await indexedDB.databases()) {
      if (!name) continue;
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open(name);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      for (const store of db.objectStoreNames) {
        const values = await new Promise<unknown[]>((resolve, reject) => {
          const req = db.transaction(store, 'readonly').objectStore(store).getAll();
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        data.push(values);
      }
      db.close();
    }
    return JSON.stringify(data);
  });
}

test('sign-up offers Later without a gate, a leave guard or an immediate reminder', async ({ page }) => {
  await signUp(page, '/?platform=macos');
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
  await expect(page.getByText('Your password and this kit together open your account on a new device. Keep it somewhere safe, apart from your password.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Print' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy' })).toBeVisible();
  let dialogs = 0;
  page.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
  expect(await page.evaluate(() => { const event = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented; })).toBe(false);
  await page.getByRole('button', { name: 'Later' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  await expect(page.getByText(reminder)).toHaveCount(0);
  await expect(page.getByTestId('kit')).toHaveCount(0);
  expect(dialogs).toBe(0);
});

test('a day later Show kit returns the same kit; saving clears the reminder on restart', async ({ page }) => {
  await page.clock.install();
  await signUp(page, '/?platform=macos');
  await page.getByRole('button', { name: 'Later' }).click();
  await page.clock.fastForward(24 * 60 * 60 * 1000);
  await expect(page.getByText(reminder)).toBeVisible();
  await page.getByRole('button', { name: 'Show kit' }).click();
  await expect(page.getByTestId('kit')).toHaveText(originalKit);
  await page.getByRole('button', { name: "I've saved it" }).click();
  await expect(page.getByText(reminder)).toHaveCount(0);
  await page.evaluate(() => window.__bhRestart?.());
  await expect(page.getByRole('heading', { name: 'BaseHero' })).toBeVisible();
  await expect(page.getByText(reminder)).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.kitStatus(window.__fake.calls.find(c => c.startsWith('kitStatus '))!.split(' ')[1]))).toMatchObject({ saved: true });
});

test('the reminder shows the current kit before acknowledging it', async ({ page }) => {
  await page.clock.install();
  await signUp(page);
  await page.getByRole('button', { name: 'Later' }).click();
  await page.clock.fastForward(24 * 60 * 60 * 1000);
  await expect(page.getByText(reminder)).toBeVisible();
  await page.getByRole('button', { name: "I've saved it" }).click();
  await expect(page.getByTestId('kit')).toHaveText(originalKit);
  await page.getByRole('button', { name: "I've saved it" }).click();
  await expect(page.getByText(reminder)).toHaveCount(0);
  await expect(page.getByTestId('kit')).toHaveCount(0);
  await page.evaluate(() => window.__bhRestart?.());
  await expect(page.getByText(reminder)).toHaveCount(0);
});

test('a replaced kit refuses acknowledgement and shows the current one', async ({ page }) => {
  await signUp(page);
  const newer = await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0];
    return window.__fake.newKit(account.id, 'correct horse battery staple');
  });
  await page.getByRole('button', { name: "I've saved it" }).click();
  await expect(page.getByRole('alert')).toContainText('Your kit changed');
  await expect(page.getByTestId('kit')).toHaveText(newer);
  await expect(page.getByRole('heading', { name: 'Your recovery kit' })).toBeVisible();
  const account = await page.evaluate(() => window.__fake.accounts().then(accounts => accounts[0].id));
  expect(await page.evaluate(id => window.__fake.kitStatus(id), account)).toMatchObject({ saved: false });
  await page.getByRole('button', { name: "I've saved it" }).click();
  expect(await page.evaluate(id => window.__fake.kitStatus(id), account)).toMatchObject({ saved: true });
});

test('a kit whose credentials changed offers to make a new one', async ({ page }) => {
  await signUp(page);
  await page.evaluate(async () => window.__fake.seedOlderAccount((await window.__fake.accounts())[0].id));
  await page.getByRole('button', { name: "I've saved it" }).click();
  await expect(page.getByTestId('kit')).toHaveCount(0);
  await page.getByRole('link', { name: 'Devices' }).click();
  await expect(page.getByRole('button', { name: 'Make a new kit' })).toBeVisible();
});

test('Android offers a kit to save, without a Google copy', async ({ page }) => {
  await page.clock.install();
  await signUp(page, '/?platform=android');
  await expect(page.getByText('Google also keeps a copy on this phone to help you sign in again.')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Copy' })).toBeVisible();
  await expect(page.getByRole('button', { name: "I've saved it" })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Later' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Print' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Later' }).click();
  await page.clock.fastForward(24 * 60 * 60 * 1000);
  await expect(page.getByText(reminder)).toBeVisible();
});

test('Devices shows a known kit without making a new one', async ({ page }) => {
  await signUp(page);
  await page.getByRole('button', { name: 'Later' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  await expect(page.getByText('Recovery kit')).toBeVisible();
  await page.getByRole('button', { name: 'Show', exact: true }).click();
  await expect(page.getByTestId('kit')).toHaveText(originalKit);
  await page.getByRole('button', { name: 'Later' }).click();
  await expect(page.getByTestId('kit')).toHaveCount(0);
});

test('older accounts get a one-time offer and can make a new kit from Devices', async ({ page }) => {
  await signUp(page);
  await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0];
    window.__fake.seedOlderAccount(account.id);
    await window.__bhRestart?.();
  });
  await expect(page.getByText('BaseHero can now keep your recovery kit for you.')).toBeVisible();
  await page.evaluate(() => window.__bhRestart?.());
  await expect(page.getByText('BaseHero can now keep your recovery kit for you.')).toHaveCount(0);
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.getByRole('button', { name: 'Make a new kit' }).click();
  await expect(page.getByText('Your old kit stops working.')).toBeVisible();
  await page.getByLabel('Password').fill('wrong');
  await page.getByRole('button', { name: 'Make kit' }).click();
  await expect(page.getByText('Email or password is wrong.')).toBeVisible();
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Make kit' }).click();
  await expect(page.getByTestId('kit')).toBeVisible();
  expect(await page.getByTestId('kit').textContent()).not.toBe(originalKit);
});

test('an older account first opened on Devices gets its offer on the account screen', async ({ page }) => {
  await signUp(page);
  await page.getByRole('button', { name: 'Later' }).click();
  await page.getByRole('link', { name: 'Devices' }).click();
  await page.evaluate(async () => {
    window.__fake.seedOlderAccount((await window.__fake.accounts())[0].id);
    await window.__bhRestart?.();
  });
  await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible();
  await page.evaluate(() => window.__bhRestart?.());
  await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible();
  await page.getByRole('link', { name: 'BaseHero' }).click();
  await expect(page.getByText('BaseHero can now keep your recovery kit for you.')).toBeVisible();
});

test('kit never enters WebView storage, history or fake call logs across flows', async ({ page }) => {
  await signUp(page);
  for (const step of ['signup', 'show', 'new'] as const) {
    const code = await page.getByTestId('kit').textContent();
    expect(await storedData(page)).not.toContain(code!);
    expect(await page.evaluate(() => JSON.stringify({ state: history.state, calls: window.__fake.calls }))).not.toContain(code!);
    expect(page.url()).not.toContain(code!);
    await page.getByRole('button', { name: 'Later' }).click();
    expect(await storedData(page)).not.toContain(code!);
    if (step === 'signup') {
      await page.getByRole('link', { name: 'Devices' }).click();
      await page.getByRole('button', { name: 'Show', exact: true }).click();
    } else if (step === 'show') {
      await page.evaluate(async () => {
        window.__fake.seedOlderAccount((await window.__fake.accounts())[0].id);
        await window.__bhRestart?.();
      });
      await page.getByRole('link', { name: 'Devices' }).click();
      await page.getByRole('button', { name: 'Make a new kit' }).click();
      await page.getByLabel('Password').fill(password);
      await page.getByRole('button', { name: 'Make kit' }).click();
    }
  }
  expect(await storedData(page)).not.toContain(password);
});
