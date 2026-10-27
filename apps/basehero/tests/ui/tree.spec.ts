import { test, expect, type Page } from '@playwright/test';

async function setup(page: Page) {
  await page.goto('/');
  const r = await page.evaluate(async () => {
    const account = await window.__fake.signUp({ invite: 'WELCOME', email: 'dan@example.com', password: 'password', deviceName: 'Mac' });
    const base = await window.__fake.createBase(account.account.id, 'Personal');
    await window.__fake.setKitSaved(account.account.id);
    return { account: account.account.id, base: base.id };
  });
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}/b/${ref.base}`; }, r);
  await expect(page.getByRole('heading', { name: 'Personal' })).toBeVisible();
  return r;
}
async function create(page: Page, kind: 'Folder' | 'Project' | 'Note', name: string) {
  await page.getByRole('button', { name: `New ${kind.toLowerCase()}` }).click();
  await page.getByRole('textbox', { name: 'Name' }).fill(name);
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
}

test('the base list opens existing bases and creates a base', async ({ page }) => {
  const r = await setup(page);
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}`; }, r);
  await expect(page.getByRole('button', { name: 'Personal', exact: true })).toBeVisible();
  await page.getByLabel('Base name').fill('Family');
  await page.getByRole('button', { name: 'Create base' }).click();
  await expect(page.getByRole('heading', { name: 'Family' })).toBeVisible();
  await page.getByRole('link', { name: 'Bases' }).click();
  await expect(page.getByRole('button', { name: 'Family', exact: true })).toBeVisible();
});

test('create a folder, a project, a note and a note inside that note, and see them in order', async ({ page }) => {
  await setup(page);
  await create(page, 'Folder', 'Trips');
  await create(page, 'Project', 'Winter photography');
  await create(page, 'Note', 'Packing');
  await page.getByRole('button', { name: 'Packing', exact: true }).click();
  await create(page, 'Note', 'Camera kit');
  const rows = page.locator('[data-testid="tree-row"]');
  await expect(rows).toHaveText(['Trips', 'Winter photography', 'Packing', 'Camera kit']);
});

test('the location bar opens Search and Devices routes', async ({ page }) => {
  const r = await setup(page);
  const address = page.getByRole('textbox', { name: 'Go to location' });
  await address.fill(`/a/${r.account}/search?q=Packing`);
  await address.press('Enter');
  await expect(page).toHaveURL(new RegExp(`#/a/${r.account}/search\\?q=Packing$`));
  await expect(page.getByRole('heading', { name: 'Search' })).toBeVisible();
  await page.evaluate(ref => { location.hash = `#/a/${ref.account}/b/${ref.base}`; }, r);
  await expect(address).toBeVisible();
  await address.fill(`/a/${r.account}/devices`);
  await address.press('Enter');
  await expect(page).toHaveURL(new RegExp(`#/a/${r.account}/devices$`));
  await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible();
});

test('rename from the item menu refreshes the tree and the location bar', async ({ page }) => {
  await setup(page);
  await create(page, 'Note', 'Packing');
  await page.getByRole('button', { name: 'Packing', exact: true }).click();
  await page.getByRole('button', { name: 'More options for Packing' }).click();
  await page.getByRole('button', { name: 'Rename' }).click();
  await page.getByRole('textbox', { name: 'New name' }).fill('Checklist');
  await page.getByRole('button', { name: 'Save name' }).click();
  await expect(page.getByRole('button', { name: 'Checklist', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Location' }).locator('.plate')).toHaveText('Checklist');
  expect(await page.evaluate(() => window.__fake.calls.includes('renameObject'))).toBe(true);
});

test('move a note into a folder with Move to…', async ({ page }) => {
  await setup(page);
  await create(page, 'Folder', 'Trips');
  await create(page, 'Note', 'Packing');
  await page.getByRole('button', { name: 'More options for Packing' }).click();
  await page.getByRole('button', { name: 'Move to…' }).click();
  await page.getByRole('button', { name: 'Trips', exact: true }).last().click();
  await page.getByRole('button', { name: 'Move', exact: true }).click();
  await page.getByRole('button', { name: 'Expand Trips' }).click();
  await expect(page.locator('[data-testid="tree-row"]')).toHaveText(['Trips', 'Packing']);
});

test('delete goes to Trash and Restore brings it back', async ({ page }) => {
  await setup(page);
  await create(page, 'Note', 'Packing');
  await page.getByRole('button', { name: 'More options for Packing' }).click();
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('[data-testid="tree-row"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Trash' }).click();
  await expect(page.getByText('Packing')).toBeVisible();
  await page.getByRole('button', { name: 'Restore Packing' }).click();
  await expect(page.getByRole('button', { name: 'Packing', exact: true })).toBeVisible();
});

test('a failed restore leaves the item in Trash and shows the error', async ({ page }) => {
  await setup(page);
  await create(page, 'Note', 'Packing');
  await page.getByRole('button', { name: 'More options for Packing' }).click();
  await page.getByRole('button', { name: 'Delete' }).click();
  await page.getByRole('button', { name: 'Trash' }).click();
  await page.evaluate(() => { window.__fake.restoreObject = async () => { throw new Error('Restore unavailable'); }; });
  await page.getByRole('button', { name: 'Restore Packing' }).click();
  await expect(page.getByRole('button', { name: 'Restore Packing' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText("Can't reach BaseHero. Check your connection.");
});

test('a change from another device appears in the tree', async ({ page }) => {
  const r = await setup(page);
  const trips = await page.evaluate(ref => window.__fake.remoteCreate(ref, { kind: 'folder', parent: null, after: null, name: 'Trips' }), r);
  await expect(page.getByRole('button', { name: 'Trips', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Expand Trips' }).click();
  await page.evaluate(({ ref, parent }) => window.__fake.remoteCreate(ref, { kind: 'note', parent, after: null, name: 'Remote itinerary' }), { ref: r, parent: trips });
  await expect(page.getByRole('button', { name: 'Remote itinerary', exact: true })).toBeVisible();
  await page.evaluate(ref => {
    const emit = window.__fake.emit.bind(window.__fake);
    window.__fake.emit = () => {};
    const id = window.__fake.remoteCreate(ref, { kind: 'note', parent: null, after: null, name: 'Remote packing' });
    window.__fake.emit = emit;
    emit({ kind: 'Base', account: ref.account, base: ref.base, event: { kind: 'ObjectsChanged', ids: [id] } });
  }, r);
  await expect(page.getByRole('button', { name: 'Remote packing', exact: true })).toBeVisible();
});

test('fake noteOpen accepts containers but rejects unknown and non-note IDs', async ({ page }) => {
  const r = await setup(page);
  const errors = await page.evaluate(async ref => {
    const fake = window.__fake;
    const folder = await fake.createObject(ref, { kind: 'folder', parent: null, after: null, name: 'Folder' });
    const project = await fake.createObject(ref, { kind: 'project', parent: null, after: null, name: 'Project' });
    const chat = fake.remoteCreate(ref, { kind: 'chat' as 'note', parent: null, after: null, name: 'Chat' });
    for (const id of [folder, project]) await fake.noteClose((await fake.noteOpen(ref, id, () => {})).session);
    const kind = async (id: string) => { try { await fake.noteOpen(ref, id, () => {}); return 'opened'; } catch (e) { return (e as { kind: string }).kind; } };
    return [await kind('missing'), await kind(chat)];
  }, r);
  expect(errors).toEqual(['NotFound', 'Invalid']);
});

test('records that are not notes, folders or projects stay out of the tree', async ({ page }) => {
  const r = await setup(page);
  const project = await page.evaluate(ref => window.__fake.remoteCreate(ref, { kind: 'project', parent: null, after: null, name: 'Winter photography' }), r);
  await page.evaluate(({ ref, parent }) => window.__fake.remoteCreate(ref, { kind: 'chat' as 'note', parent, after: null, name: 'Private chat' }), { ref: r, parent: project });
  await page.getByRole('button', { name: 'Expand Winter photography' }).click();
  await expect(page.getByText('Private chat')).toHaveCount(0);
});

test('folded the tree is a drawer, unfolded it sits beside the note', async ({ page }) => {
  const r = await setup(page);
  const id = await page.evaluate(ref => window.__fake.remoteCreate(ref, { kind: 'note', parent: null, after: null, name: 'Packing' }), r);
  await page.setViewportSize({ width: 412, height: 915 });
  await page.evaluate(({ ref, note }) => { location.hash = `#/a/${ref.account}/b/${ref.base}/n/${note}`; }, { ref: r, note: id });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Tree' })).toBeHidden();
  await page.getByRole('button', { name: 'Open tree' }).click();
  await expect(page.getByRole('navigation', { name: 'Tree' })).toBeVisible();
  await page.setViewportSize({ width: 884, height: 1000 });
  await expect(page.getByRole('navigation', { name: 'Tree' })).toBeVisible();
  await expect(page.locator('.ProseMirror')).toBeVisible();
});

test('the location bar shows the base, the path and the current item on the plate', async ({ page }) => {
  const r = await setup(page);
  const folder = await page.evaluate(ref => window.__fake.remoteCreate(ref, { kind: 'folder', parent: null, after: null, name: 'Trips' }), r);
  const id = await page.evaluate(({ ref, parent }) => window.__fake.remoteCreate(ref, { kind: 'note', parent, after: null, name: 'Packing' }), { ref: r, parent: folder });
  await page.evaluate(({ ref, note }) => { location.hash = `#/a/${ref.account}/b/${ref.base}/n/${note}`; }, { ref: r, note: id });
  await expect(page.getByRole('navigation', { name: 'Location' })).toContainText('Personal');
  await expect(page.getByRole('navigation', { name: 'Location' })).toContainText('Trips');
  await expect(page.getByRole('navigation', { name: 'Location' }).locator('.plate')).toHaveText('Packing');
});
