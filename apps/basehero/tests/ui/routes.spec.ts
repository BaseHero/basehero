import { test, expect, type Page } from '@playwright/test';

async function makeNoteRoute(page: Page) {
  return page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    const base = await window.__fake.createBase(account, 'Personal');
    const note = await window.__fake.createObject({ account, base: base.id }, { kind: 'note', name: 'Note', parent: null, after: null });
    return `#/a/${account}/b/${base.id}/n/${note}`;
  });
}

async function signUp(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByTestId('kit')).toBeVisible();
}

test('a removed account route on a fresh page opens the available account list', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      fake.accounts = async () => [{ id: 'known', email: 'known@example.com', kind: 'full' }];
    } });
  });
  await page.goto('/#/a/removed/b/old/n/old-note');
  await expect(page).toHaveURL(/#\/a\/known$/);
  await expect(page.getByRole('heading', { name: 'Bases' })).toBeVisible();
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
});

test('an account can enter a note route and Back waits for the editor drain', async ({ page }) => {
  await signUp(page);
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  const noteRoute = await makeNoteRoute(page);
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true })));
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Waiting for IME');
  await page.evaluate(() => window.__bhBack?.());
  await expect(page).toHaveURL(new RegExp(`${noteRoute}$`));
  await expect(page.locator('.ProseMirror')).toHaveText('Waiting for IME');
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true })));
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  await expect.poll(() => page.evaluate(route => window.__fake.noteText(route.split('/').at(-1)!), noteRoute)).toBe('Waiting for IME');
});

for (const action of ['search', 'base', 'brand'] as const) {
  test(`the header ${action} action waits for the editor to save`, async ({ page }) => {
    await signUp(page);
    await page.getByLabel("I've saved my kit").check();
    await page.getByRole('button', { name: 'Continue' }).click();
    const noteRoute = await makeNoteRoute(page);
    await page.evaluate(route => { location.hash = route; }, noteRoute);
    await expect(page.locator('.ProseMirror')).toBeVisible();
    await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true })));
    await page.locator('.ProseMirror').click();
    await page.keyboard.type('Not saved yet');
    if (action === 'search') {
      await page.getByRole('searchbox', { name: 'Search', exact: true }).fill('trip');
      await page.getByRole('searchbox', { name: 'Search', exact: true }).press('Enter');
    } else {
      await page.getByRole('link', { name: action === 'brand' ? 'BaseHero' : 'Personal' }).click();
    }
    await expect(page).toHaveURL(new RegExp(`${noteRoute}$`));
    await expect(page.locator('.ProseMirror')).toHaveText('Not saved yet');
    await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true })));
    await expect(page).not.toHaveURL(new RegExp(`${noteRoute}$`));
    await expect.poll(() => page.evaluate(route => window.__fake.noteText(route.split('/').at(-1)!), noteRoute)).toBe('Not saved yet');
  });
}

test('an unknown-account route waits for the editor drain', async ({ page }) => {
  await signUp(page);
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  const noteRoute = await makeNoteRoute(page);
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true })));
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Still editing');
  await page.evaluate(() => { location.hash = '#/a/unknown/b/missing'; });
  await expect(page).toHaveURL(new RegExp(`${noteRoute}$`));
  await expect(page.locator('.ProseMirror')).toHaveText('Still editing');
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true })));
  await expect(page).not.toHaveURL(new RegExp(`${noteRoute}$`));
  await expect.poll(() => page.evaluate(route => window.__fake.noteText(route.split('/').at(-1)!), noteRoute)).toBe('Still editing');
});

test('an unknown-account route asks before hiding an unsaved kit', async ({ page }) => {
  await signUp(page);
  let confirmations = 0;
  page.on('dialog', dialog => { confirmations++; void dialog.dismiss(); });
  await page.evaluate(() => { location.hash = '#/a/unknown/b/missing'; });
  await expect.poll(() => confirmations).toBe(1);
  await expect(page.getByTestId('kit')).toBeVisible();
  await expect(page).toHaveURL('/');
  page.removeAllListeners('dialog');
  page.once('dialog', dialog => { void dialog.accept(); });
  await page.evaluate(() => { location.hash = '#/a/unknown/b/missing'; });
  await expect(page.getByTestId('kit')).toHaveCount(0);
  await expect(page).not.toHaveURL(/unknown/);
});

test('leaving an unsaved kit for a note route requires confirmation and retains the reminder', async ({ page }) => {
  await signUp(page);
  const noteRoute = await makeNoteRoute(page);
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); void dialog.dismiss(); });
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page.getByTestId('kit')).toBeVisible();
  await expect(page).toHaveURL('/');
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); void dialog.accept(); });
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page).toHaveURL(new RegExp(`${noteRoute}$`));
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.evaluate(() => window.__bhBack?.());
  await expect(page.getByRole('button', { name: 'Make a new recovery kit' })).toBeVisible();
});
