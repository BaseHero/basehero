import { test, expect, type Page } from '@playwright/test';

async function setup(page: Page) {
  await page.goto('/');
  const data = await page.evaluate(async () => {
    const signed = await window.__fake.signUp({ invite: 'WELCOME', email: 'dan@example.com', password: 'password', deviceName: 'Mac' });
    const account = signed.account.id;
    await window.__fake.setKitSaved(account, signed.kit);
    const personal = (await window.__fake.createBase(account, 'Personal')).id;
    const health = await window.__fake.createObject({ account, base: personal }, { kind: 'folder', parent: null, after: null, name: 'Health' });
    const inside = await window.__fake.createObject({ account, base: personal }, { kind: 'note', parent: health, after: null, name: 'Inside' });
    const outside = await window.__fake.createObject({ account, base: personal }, { kind: 'note', parent: null, after: null, name: 'Outside' });
    return { account, personal, health, inside, outside };
  });
  await page.evaluate(({ account, personal }) => { location.hash = `#/a/${account}/b/${personal}`; }, data);
  await expect(page.getByRole('heading', { name: 'Personal' })).toBeVisible();
  return data;
}
async function grant(page: Page, data: Awaited<ReturnType<typeof setup>>) {
  return page.evaluate(({ account, personal, health }) => window.__fake.grantFolder(account, personal, health, 'Dan - Sample'), data);
}

test('a granted folder shows its contents in place, marked with who can see it', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await expect(page.getByText('Shared with Dan - Sample')).toBeVisible();
  await page.getByRole('button', { name: 'Expand Health' }).click();
  await expect(page.getByRole('button', { name: 'Inside', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Inside', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`b/${mounted}/n/${data.inside}$`));
  await expect(page.getByRole('heading', { name: 'Personal' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Location' })).toContainText('Health');
  await page.screenshot({ path: '/tmp/bh-folders-tree.png' });
});

test('new notes and folders inside a granted folder live in its mounted base', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`b/${data.personal}/n/${data.health}$`));
  for (const [action, title] of [['New note', 'Reading'], ['New folder', 'Archive']] as const) {
    await page.getByRole('button', { name: action }).click();
    await page.getByLabel('Name', { exact: true }).fill(title);
    await page.getByRole('button', { name: 'Create', exact: true }).click();
  }
  const children = await page.evaluate(({ account, mounted }) => window.__fake.treeChildren({ account, base: mounted }, null), { account: data.account, mounted });
  expect(children.map(item => item.title)).toEqual(expect.arrayContaining(['Reading', 'Archive']));
  expect(children.filter(item => ['Reading', 'Archive'].includes(item.title)).every(item => item.base === mounted && item.parent === null)).toBe(true);
  expect(await page.evaluate(({ account, personal, health }) => window.__fake.children({ account, base: personal }, health).then(items => items.some(item => ['Reading', 'Archive'].includes(item.title))), data)).toBe(false);
  expect(await page.evaluate(({ account, mounted }) => window.__fake.apps(account).then(apps => apps.some(app => app.bases.some(grant => grant.base === mounted))), { account: data.account, mounted })).toBe(true);
});

test('a file added inside a granted folder belongs to its mounted base', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await page.getByRole('button', { name: 'Note options' }).click();
  await page.locator('input[aria-label="Add file"]').setInputFiles({ name: 'receipt.txt', mimeType: 'text/plain', buffer: Buffer.from('receipt') });
  await expect(page.getByText('receipt.txt')).toBeVisible();
  const files = await page.evaluate(({ account, mounted }) => window.__fake.files({ account, base: mounted }, null), { account: data.account, mounted });
  expect(files.map(file => file.name)).toEqual(['receipt.txt']);
  expect(await page.evaluate(({ account, personal, health }) => window.__fake.files({ account, base: personal }, health).then(files => files.length), data)).toBe(0);
});

for (const entry of ['insert', 'paste', 'drop'] as const) {
  test(`${entry} image in a selected granted folder stores the file in its mounted base`, async ({ page }) => {
    const data = await setup(page);
    const mounted = await grant(page, data);
    await page.getByRole('button', { name: 'Health', exact: true }).click();
    await expect(page.locator('.ProseMirror')).toBeVisible();
    const image = { name: `${entry}.png`, mimeType: 'image/png', buffer: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0]) };
    if (entry === 'insert') {
      await page.locator('input[accept="image/png,image/jpeg,image/gif,image/webp"]').setInputFiles(image);
    } else {
      await page.locator('.ProseMirror').evaluate((el, { name, bytes, event }) => {
        const transfer = new DataTransfer();
        transfer.items.add(new File([new Uint8Array(bytes)], name, { type: 'image/png' }));
        el.dispatchEvent(event === 'paste'
          ? new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: transfer })
          : new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: transfer }));
      }, { name: image.name, bytes: [...image.buffer], event: entry });
    }
    await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
    await expect.poll(() => page.evaluate(({ account, base }) => window.__fake.files({ account, base }, null).then(rows => rows.map(row => row.name)), { account: data.account, base: mounted })).toContain(image.name);
    expect(await page.evaluate(({ account, base, parent }) => window.__fake.files({ account, base }, parent).then(rows => rows.map(row => row.name)), { account: data.account, base: data.personal, parent: data.health })).not.toContain(image.name);
    await page.getByRole('button', { name: 'Note options' }).click();
    await expect(page.getByText(image.name)).toBeVisible();
    await page.evaluate(({ account, base }) => { location.hash = `#/a/${account}/b/${base}`; }, { account: data.account, base: data.personal });
    await expect(page.locator('.ProseMirror')).toHaveCount(0);
    await page.getByRole('button', { name: 'Health', exact: true }).click();
    await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  });
}

test('an earlier version of a shared folder shows its mounted image', async ({ page }) => {
  const data = await setup(page);
  await grant(page, data);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').fill('Version with image');
  const before = await page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('noteApply')).length);
  await page.locator('input[accept="image/png,image/jpeg,image/gif,image/webp"]').setInputFiles({
    name: 'version.png', mimeType: 'image/png', buffer: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0]),
  });
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(call => call.startsWith('noteApply')).length)).toBeGreaterThan(before);
  await page.evaluate(({ account, personal }) => { location.hash = `#/a/${account}/b/${personal}`; }, data);
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  // Save the editor's actual document as the version, including its image node.
  await page.evaluate(async ({ account, personal, health }) => {
    const r = { account, base: personal };
    const fake = window.__fake as unknown as { versionData: Map<string, { row: object; state: Uint8Array }[]> };
    const opened = await window.__fake.noteOpen(r, health, () => {});
    const state = opened.state;
    await window.__fake.noteClose(opened.session);
    const seq = window.__fake.addVersion(r, health, 'Before image');
    fake.versionData.get(`${account}:${personal}:${health}`)!.unshift({
      row: { seq: seq + 1, at: Date.now(), deviceId: 'mac', deviceName: 'Mac' }, state,
    });
  }, data);
  await page.getByRole('button', { name: 'Note options' }).click();
  const history = page.getByRole('region', { name: 'Versions' });
  await expect(history.getByRole('button', { name: /Mac/ })).toHaveCount(2);
  await history.getByRole('button', { name: /Mac/ }).first().click();
  await expect(history.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  await expect(history.getByText("Can't show this image")).toHaveCount(0);
});

test('a mount that cannot be opened still shows an image from the note’s own base', async ({ page }) => {
  const data = await setup(page);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await page.locator('input[accept="image/png,image/jpeg,image/gif,image/webp"]').setInputFiles({
    name: 'before-grant.png', mimeType: 'image/png', buffer: Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0]),
  });
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  const mounted = await grant(page, data);
  // Keep this old image in the outer base, as an image belonging to the note can be.
  // The fake moves the file's item but not its file data when granting.
  await page.evaluate(({ account, personal, health, mounted }) => {
    const fake = window.__fake as unknown as {
      items: Map<string, { id: string; title: string; parent: string | null }[]>;
      fileInfo: typeof window.__fake.fileInfo;
    };
    const inner = `${account}:${mounted}`, outer = `${account}:${personal}`;
    const image = fake.items.get(inner)!.find(item => item.title === 'before-grant.png')!;
    fake.items.set(inner, fake.items.get(inner)!.filter(item => item !== image));
    fake.items.get(outer)!.push({ ...image, parent: health });
    const original = fake.fileInfo.bind(fake);
    fake.fileInfo = async (r, id) => {
      if (r.base === mounted) throw new Error('Mounted base not yet on this device');
      return original(r, id);
    };
  }, { ...data, mounted });
  const oldImage = await page.evaluate(async ({ account, personal, health }) => {
    const file = (await window.__fake.files({ account, base: personal }, health))[0];
    return file && await window.__fake.fileInfo({ account, base: personal }, file.id);
  }, data);
  expect(oldImage?.name).toBe('before-grant.png');
  await page.evaluate(({ account, personal }) => { location.hash = `#/a/${account}/b/${personal}`; }, data);
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await page.getByRole('button', { name: 'Health', exact: true }).click();
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src', /^blob:/);
  await expect(page.getByText("Can't show this image")).toHaveCount(0);
});

test('the base list leaves out granted folders', async ({ page }) => {
  const data = await setup(page);
  await grant(page, data);
  await page.getByRole('link', { name: 'Bases' }).click();
  await expect(page.getByRole('button', { name: 'Personal', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Health', exact: true })).toHaveCount(0);
});

test('moving a note into a granted folder moves it between bases', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await page.evaluate(({ account, mounted }) => window.__fake.createObject({ account, base: mounted }, { kind: 'folder', parent: null, after: null, name: 'Reports' }), { account: data.account, mounted });
  await page.getByRole('button', { name: 'More options for Outside' }).click();
  await page.getByRole('button', { name: 'Move to…' }).click();
  await expect(page.getByRole('dialog', { name: 'Move to…' }).getByRole('button', { name: 'Reports' })).toBeVisible();
  await page.getByRole('dialog', { name: 'Move to…' }).getByRole('button', { name: 'Health' }).click();
  await page.screenshot({ path: '/tmp/bh-folders-move-dialog.png' });
  await page.getByRole('button', { name: 'Move', exact: true }).click();
  await expect.poll(() => page.evaluate(({ account, base, id }) => window.__fake.getObject({ account, base }, id).then(row => row?.parent), { account: data.account, base: mounted, id: data.outside })).toBe(null);
  await page.getByRole('button', { name: 'Expand Health' }).click();
  await expect(page.getByRole('button', { name: 'Outside', exact: true })).toBeVisible();
  await page.screenshot({ path: '/tmp/bh-folders-move.png' });
});

test('the trash of a base lists deleted items from its granted folders and restores them', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await page.evaluate(({ account, base, id }) => window.__fake.deleteObject({ account, base }, id), { account: data.account, base: mounted, id: data.inside });
  await page.getByRole('button', { name: 'Trash' }).click();
  await expect(page.getByRole('button', { name: 'Restore Inside' })).toBeVisible();
  await page.screenshot({ path: '/tmp/bh-folders-trash.png' });
  await page.getByRole('button', { name: 'Restore Inside' }).click();
  await expect.poll(() => page.evaluate(({ account, base, id }) => window.__fake.getObject({ account, base }, id).then(row => row?.deleted), { account: data.account, base: mounted, id: data.inside })).toBe(false);
});

test('an open note follows its move to a granted folder', async ({ page }) => {
  const data = await setup(page);
  await page.evaluate(({ account, personal, outside }) => { location.hash = `#/a/${account}/b/${personal}/n/${outside}`; }, data);
  await expect(page.locator('.ProseMirror')).toBeVisible();
  const mounted = await grant(page, data);
  await page.evaluate(({ account, personal, id, mounted }) => window.__fake.moveObject({ account, base: personal }, id, mounted, null, null), { account: data.account, personal: data.personal, id: data.outside, mounted });
  await expect(page).toHaveURL(new RegExp(`b/${mounted}/n/${data.outside}$`));
  await page.locator('.ProseMirror').first().fill('After move');
  await expect(page.locator('.ProseMirror').first()).toContainText('After move');
});

test('a moved note’s history shows its earlier versions under Before it moved', async ({ page }) => {
  const data = await setup(page);
  await page.evaluate(({ account, base, id }) => window.__fake.addVersion({ account, base }, id, 'Earlier'), { account: data.account, base: data.personal, id: data.inside });
  const mounted = await grant(page, data);
  await page.evaluate(({ account, base, id }) => { location.hash = `#/a/${account}/b/${base}/n/${id}`; }, { account: data.account, base: mounted, id: data.inside });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.getByRole('button', { name: 'Note options' }).click();
  await expect(page.getByRole('heading', { name: 'Before it moved' })).toBeVisible();
  await page.getByRole('button', { name: /Mac/ }).last().click();
  await expect(page.getByText('Earlier')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Restore this version' })).toHaveCount(0);
  await page.screenshot({ path: '/tmp/bh-folders-history.png' });
});

test('a search hit in a granted folder opens in place', async ({ page }) => {
  const data = await setup(page);
  const mounted = await grant(page, data);
  await page.getByRole('searchbox', { name: 'Search' }).fill('Inside');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page.getByRole('heading', { name: 'Search' })).toBeVisible();
  await page.getByText('Inside', { exact: true }).first().click();
  await expect(page).toHaveURL(new RegExp(`b/${mounted}/n/${data.inside}$`));
  await expect(page.getByRole('heading', { name: 'Personal' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Inside', exact: true })).toBeVisible();
});
