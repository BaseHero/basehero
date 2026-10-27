import { test, expect, type Page } from '@playwright/test';

async function account(page: Page): Promise<string> {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill('WELCOME');
  await page.getByLabel('Email').fill('dan@example.com');
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel("I've saved my kit").check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('link', { name: 'Personal' })).toBeVisible();
  return page.evaluate(() => window.__fake.accounts().then(accounts => accounts[0].id));
}

test('search finds this base first, then others, and opens a hit', async ({ page }) => {
  const id = await account(page);
  const { personal, work } = await page.evaluate(async account => {
    const personal = await window.__fake.createBase(account, 'Personal');
    const work = await window.__fake.createBase(account, 'Work');
    await window.__fake.createObject({ account, base: work.id }, { kind: 'folder', parent: null, after: null, name: 'Meeting folder' });
    await window.__fake.createObject({ account, base: personal.id }, { kind: 'note', parent: null, after: null, name: 'Meeting notes' });
    return { personal: personal.id, work: work.id };
  }, id);
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+k' : 'Control+k');
  await expect(page.getByRole('searchbox', { name: 'Search' })).toBeFocused();
  await page.getByRole('searchbox', { name: 'Search' }).fill('Meeting');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page).toHaveURL(new RegExp(`#/a/${id}/search\\?q=Meeting`));
  const groups = page.locator('[data-search-base]');
  await expect(groups).toHaveCount(2);
  await expect(groups.nth(0)).toHaveAttribute('data-search-base', personal);
  await expect(groups.nth(1)).toHaveAttribute('data-search-base', work);
  await expect(groups.nth(0).getByRole('heading', { name: 'Personal' })).toBeVisible();
  await expect(groups.nth(1).getByRole('heading', { name: 'Work' })).toBeVisible();
  await expect(groups.nth(0).getByRole('link', { name: 'Meeting notes' })).toHaveCount(1);
  await expect(groups.nth(0).getByRole('link', { name: 'Meeting folder' })).toHaveCount(0);
  await expect(groups.nth(1).getByRole('link', { name: 'Meeting folder' })).toHaveCount(1);
  await expect(groups.nth(1).getByRole('link', { name: 'Meeting notes' })).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('search ')))).toHaveLength(1);
  await expect(groups.nth(0).locator('li small')).toHaveText('Note');
  await expect(groups.nth(1).locator('li small')).toHaveText('Folder');
  await groups.nth(0).getByRole('link', { name: 'Meeting notes' }).click();
  await expect(page).toHaveURL(new RegExp(`#/a/${id}/b/${personal}/n/`));
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Search' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(0);
});

test('search opens folders and projects as notes in the matching base', async ({ page }) => {
  const id = await account(page);
  const base = await page.evaluate(async account => {
    const base = await window.__fake.createBase(account, 'Work');
    await window.__fake.createObject({ account, base: base.id }, { kind: 'folder', parent: null, after: null, name: 'Receipts folder' });
    await window.__fake.createObject({ account, base: base.id }, { kind: 'project', parent: null, after: null, name: 'Receipts project' });
    return base.id;
  }, id);
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.getByRole('searchbox', { name: 'Search' }).fill('Receipts');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page.locator('[data-search-base] li small')).toHaveText(['Folder', 'Project']);
  await page.getByRole('link', { name: 'Receipts folder' }).click();
  await expect(page).toHaveURL(new RegExp(`#/a/${id}/b/${base}/n/`));
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').fill('Folder body');
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Search' })).toBeVisible();
  await page.getByRole('link', { name: 'Receipts project' }).click();
  await expect(page).toHaveURL(new RegExp(`#/a/${id}/b/${base}/n/`));
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
});

test('search displays markup-like hit text literally', async ({ page }) => {
  const id = await account(page);
  await page.evaluate(async account => {
    const base = await window.__fake.createBase(account, 'Personal');
    await window.__fake.createObject({ account, base: base.id }, { kind: 'note', parent: null, after: null, name: '<img src=x onerror=alert(1)>' });
    const search = window.__fake.search.bind(window.__fake);
    window.__fake.search = async (...args) => (await search(...args)).map(result => ({
      ...result, hit: { ...result.hit, ty: { name: 'example.custom', version: 2 }, snippet: '<b>bold</b>' },
    }));
  }, id);
  await page.getByRole('link', { name: 'Personal' }).click();
  await page.getByRole('searchbox', { name: 'Search' }).fill('<img');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  const result = page.locator('[data-search-base] li');
  await expect(result.getByRole('link')).toHaveText('<img src=x onerror=alert(1)>');
  await expect(result.locator('p')).toHaveText('<b>bold</b>');
  await expect(result.locator('small')).toHaveText('example.custom');
  await expect(result.locator('img, b')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__pwned)).toBeUndefined();
});
