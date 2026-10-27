import { test, expect, type Page } from '@playwright/test';

async function note(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('button', { name: 'Later' }).click();
  const ids = await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    const base = (await window.__fake.createBase(account, 'Personal')).id;
    const id = await window.__fake.createObject({ account, base }, { kind: 'note', parent: null, after: null, name: 'Trip' });
    return { account, base, id };
  });
  await page.evaluate(({ account, base, id }) => { location.hash = `#/a/${account}/b/${base}/n/${id}`; }, ids);
  await expect(page.getByRole('region', { name: 'Note editor' }).locator('.ProseMirror')).toBeVisible();
  return ids;
}

async function history(page: Page) {
  await page.getByRole('button', { name: 'Note options' }).click();
  return page.getByRole('region', { name: 'Versions' });
}

async function seed(page: Page, ids: { account: string; base: string; id: string }, text: string) {
  await page.evaluate(async ({ ids, text }) => window.__fake.addVersion({ account: ids.account, base: ids.base }, ids.id, text), { ids, text });
}

test('versions list newest first under Current', async ({ page }) => {
  const ids = await note(page);
  await seed(page, ids, 'First draft');
  await seed(page, ids, 'Second draft');
  const panel = await history(page);
  await expect(panel.getByRole('heading', { name: 'Versions' })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Current' })).toBeVisible();
  await expect(panel.locator('li')).toHaveCount(3);
  await expect(panel.locator('li').nth(1)).toContainText('Mac');
  await expect(panel.locator('li').nth(1)).toContainText(new Date().getFullYear().toString());
  expect(await panel.locator('li').nth(1).getAttribute('data-seq')).toBe('2');
  expect(await panel.locator('li').nth(2).getAttribute('data-seq')).toBe('1');
});

test('a version shows read-only', async ({ page }) => {
  const ids = await note(page);
  await seed(page, ids, 'Old text');
  const panel = await history(page);
  await panel.locator('li[data-seq="1"] button').click();
  const preview = panel.getByRole('region', { name: 'Note editor' }).locator('.ProseMirror');
  await expect(preview).toContainText('Old text');
  await expect(preview).toHaveAttribute('contenteditable', 'false');
  await expect(page.getByRole('region', { name: 'Note editor' }).last().locator('.ProseMirror')).toBeVisible();
});

test('restore asks first, then the editor shows the old text', async ({ page }) => {
  const ids = await note(page);
  await seed(page, ids, 'Old text');
  const live = page.getByRole('region', { name: 'Note editor' }).last().locator('.ProseMirror');
  await live.fill('New text');
  const panel = await history(page);
  await panel.locator('li[data-seq="1"] button').click();
  await panel.getByRole('button', { name: 'Restore this version' }).click();
  await expect(panel.getByText('Restore this version? The current text is kept as a version too, so you can switch back.')).toBeVisible();
  await expect(live).toContainText('New text');
  await panel.getByRole('button', { name: 'Confirm restore' }).click();
  await expect(live).toContainText('Old text');
});

test('offline, history says it needs a connection', async ({ page }) => {
  await note(page);
  await page.evaluate(() => window.__fake.setOnline(false));
  const panel = await history(page);
  await expect(panel.getByText('Version history needs a connection.')).toBeVisible();
});

test('Show older loads the next page', async ({ page }) => {
  const ids = await note(page);
  for (let i = 0; i < 51; i++) await seed(page, ids, `Draft ${i}`);
  const panel = await history(page);
  await expect(panel.locator('li')).toHaveCount(51);
  await panel.getByRole('button', { name: 'Show older' }).click();
  await expect(panel.locator('li')).toHaveCount(52);
  await expect(panel.getByRole('button', { name: 'Show older' })).toHaveCount(0);
});
