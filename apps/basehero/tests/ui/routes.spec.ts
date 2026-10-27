import { test, expect, type Page } from '@playwright/test';

const noteRoute = '#/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/n/cccccccccccccccccccccccccccccccc';

async function signUp(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByTestId('kit')).toBeVisible();
}

test('an account can enter a note route and Back waits for the editor drain', async ({ page }) => {
  await signUp(page);
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
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
  await expect.poll(() => page.evaluate(() => window.__fake.noteText('cccccccccccccccccccccccccccccccc'))).toBe('Waiting for IME');
});

test('leaving an unsaved kit for a note route requires confirmation and retains the reminder', async ({ page }) => {
  await signUp(page);
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); void dialog.dismiss(); });
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page.getByTestId('kit')).toBeVisible();
  await expect(page).toHaveURL('/');
  page.once('dialog', dialog => { expect(dialog.type()).toBe('confirm'); void dialog.accept(); });
  await page.evaluate(route => { location.hash = route; }, noteRoute);
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.evaluate(() => window.__bhBack?.());
  await expect(page.getByRole('button', { name: 'Make a new recovery kit' })).toBeVisible();
});
