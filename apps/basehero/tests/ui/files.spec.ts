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
  await expect(page.locator('.ProseMirror')).toBeVisible();
  return ids;
}

async function files(page: Page) {
  await page.getByRole('button', { name: 'Note options' }).click();
  await expect(page.getByRole('heading', { name: 'Files' })).toBeVisible();
}

async function add(page: Page, name = 'photo.png') {
  await page.getByLabel('Add file').setInputFiles({ name, mimeType: 'image/png', buffer: Buffer.from('some bytes') });
  await expect(page.getByText(name, { exact: true })).toBeVisible();
  return page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('fileAdd ')).length);
}

test('add a file from the Files panel and watch it upload', async ({ page }) => {
  await note(page); await files(page);
  expect(await add(page)).toBe(1);
  const id = await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    const base = (await window.__fake.bases(account))[0].id;
    return (await window.__fake.files({ account, base }, null))[0]?.id;
  });
  // The file is a child of the note, not of the base root.
  expect(id).toBeUndefined();
  const fileId = await page.evaluate(async () => {
    const account = (await window.__fake.accounts())[0].id;
    const base = (await window.__fake.bases(account))[0].id;
    const found = await window.__fake.search(account, base, 'photo.png', 10);
    return found[0].hit.id;
  });
  await page.evaluate(id => window.__fake.setFileStatus(id, { kind: 'sending', done: 3, parts: 25 }), fileId);
  await expect(page.getByText('Uploading 3 of 25')).toBeVisible();
});

test('Open asks the backend and never opens a URL', async ({ page }) => {
  await note(page); await files(page); await add(page);
  await page.getByRole('button', { name: 'Open' }).click();
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('fileOpen ')))).toHaveLength(1);
  expect(await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('openExternal ')))).toHaveLength(0);
});

test('Delete moves the file to the trash', async ({ page }) => {
  const { account, base } = await note(page); await files(page); await add(page);
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('No files in this note.')).toBeVisible();
  expect(await page.evaluate(async r => (await window.__fake.trash(r)).filter(x => x.ty?.name === 'core.file').length, { account, base })).toBe(1);
});

test('each status reads as words', async ({ page }) => {
  const { account, base, id } = await note(page); await files(page); await add(page);
  const file = await page.evaluate(async ({ account, base, id }) => (await window.__fake.files({ account, base }, id))[0], { account, base, id });
  await expect(page.getByText('10 B')).toBeVisible();
  for (const [status, words] of [
    [{ kind: 'sending', done: 3, parts: 25 }, 'Uploading 3 of 25'],
    [{ kind: 'fetching', done: 3, parts: 25 }, 'Downloading 3 of 25'],
    [{ kind: 'remote' }, 'Not on this device'],
    [{ kind: 'waiting' }, 'Waiting for the device that added it'],
    [{ kind: 'broken' }, "Can't open this file"],
  ] as const) {
    await page.evaluate(({ id, status }) => window.__fake.setFileStatus(id, status), { id: file.id, status });
    await expect(page.getByText(words)).toBeVisible();
  }
});

test('a file found by search opens its note with Files open', async ({ page }) => {
  const { account, base, id } = await note(page); await files(page); await add(page, 'itinerary.pdf');
  await page.getByRole('searchbox', { name: 'Search' }).fill('itinerary');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page.getByText('File', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'itinerary.pdf' }).click();
  await expect(page).toHaveURL(new RegExp(`/n/${id}\\?files=1`));
  await expect(page.getByRole('heading', { name: 'Files' })).toBeVisible();
});
