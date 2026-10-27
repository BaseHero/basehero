import { test, expect, type Page } from '@playwright/test';

const account = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const base = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const note = 'cccccccccccccccccccccccccccccccc';

async function openNote(page: Page, save: 'slow' | 'fail') {
  await page.addInitScript(mode => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      const state = fake as unknown as {
        accountList: { id: string; email: string; kind: 'full' }[];
        baseList: Map<string, { id: string; name: string; mode: 'readWrite' }[]>;
        items: Map<string, { id: string; title: string; parent: null; deleted: false; kind: 'note' }[]>;
      };
      const account = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const base = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      state.accountList.push({ id: account, email: 'fixture@example.com', kind: 'full' });
      state.baseList.set(account, [{ id: base, name: 'Personal', mode: 'readWrite' }]);
      state.items.set(`${account}:${base}`, [{ id: 'cccccccccccccccccccccccccccccccc', title: 'Note', parent: null, deleted: false, kind: 'note' }]);
      const apply = fake.noteApply.bind(fake);
      fake.noteApply = async (session, update) => {
        if (mode === 'fail') throw new Error('Could not save');
        await new Promise(resolve => setTimeout(resolve, 500));
        await apply(session, update);
        fake.calls.push('noteApply resolved');
      };
    } });
  }, save);
  await page.goto(`/?update=0.1.1#/a/${account}/b/${base}/n/${note}`);
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Restart to update' })).toBeVisible();
}

test('non-Mac platforms do not show an update even when available', async ({ page }) => {
  await page.goto('/?update=0.1.1&platform=android');
  await expect(page.getByText('BaseHero 0.1.1 is ready')).toHaveCount(0);
  expect(await page.evaluate(() => window.__fake.calls.some(c => c === 'updateCheck'))).toBe(false);
});

test('an update installs only when asked', async ({ page }) => {
  await page.goto('/?update=0.1.1');
  await expect(page.getByText('BaseHero 0.1.1 is ready')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'updateInstall').length)).toBe(0);
  await page.getByRole('button', { name: 'Restart to update' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c === 'updateInstall').length)).toBe(1);
});

test('installing waits for open notes to save', async ({ page }) => {
  await openNote(page, 'slow');
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Ferry at 9');
  await page.getByRole('button', { name: 'Restart to update' }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls)).toContain('noteApply resolved');
  await expect.poll(() => page.evaluate(() => window.__fake.calls)).toContain('updateInstall');
  const calls = await page.evaluate(() => window.__fake.calls);
  expect(calls.filter(call => call === 'noteApply resolved').length).toBeGreaterThan(0);
  expect(calls.indexOf('updateInstall')).toBeGreaterThan(calls.lastIndexOf('noteApply resolved'));
  expect(await page.evaluate(id => window.__fake.noteText(id), note)).toBe('Ferry at 9');
});

test('a failed note save prevents the update and shows an error', async ({ page }) => {
  await openNote(page, 'fail');
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Unsaved note');
  await page.getByRole('button', { name: 'Restart to update' }).click();
  await expect(page.getByRole('alert')).toHaveText('Could not save your notes. The update was not installed. Try again.');
  expect(await page.evaluate(() => window.__fake.calls)).not.toContain('updateInstall');
});
