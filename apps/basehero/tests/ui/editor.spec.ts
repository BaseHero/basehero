import { test, expect, type Page } from '@playwright/test';

const r = { account: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', base: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' };
const note = 'cccccccccccccccccccccccccccccccc';
// Seed the fake before App loads, including on reload and in a second window.
test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
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
      state.items.set(`${account}:${base}`, ['cccccccccccccccccccccccccccccccc', 'dddddddddddddddddddddddddddddddd'].map(id => ({ id, title: 'Note', parent: null, deleted: false, kind: 'note' })));
    } });
  });
});
async function open(page: Page, id = note) {
  await page.goto(`/#/a/${r.account}/b/${r.base}/n/${id}`);
  await expect(page.locator('.ProseMirror')).toBeVisible();
}

test('typing saves through the backend and survives a reload', async ({ page }) => {
  await open(page);
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Ferry at 9');
  await expect.poll(() => page.evaluate(id => window.__fake.noteText(id), note)).toBe('Ferry at 9');
  await page.reload();
  await expect(page.locator('.ProseMirror')).toHaveText('Ferry at 9');
});

test('a native quit drain request saves the editor before acknowledging', async ({ page }) => {
  await open(page);
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Last keystrokes');
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:drain-requested', { detail: { requestId: 42 } })));
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __bhDrainAcks?: { requestId: number; ok: boolean }[] }).__bhDrainAcks)).toEqual([{ requestId: 42, ok: true }]);
  expect(await page.evaluate(id => window.__fake.noteText(id), note)).toBe('Last keystrokes');
});

test('a failed quit drain keeps the window open and gives a copyable warning', async ({ page }) => {
  await open(page);
  await page.evaluate(() => { window.__fake.noteApply = async () => { throw new Error('disk unavailable'); }; });
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Keep this text');
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:drain-requested', { detail: { requestId: 43 } })));
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __bhDrainAcks?: { requestId: number; ok: boolean }[] }).__bhDrainAcks)).toEqual([{ requestId: 43, ok: false }]);
  await expect(page.getByRole('alert')).toContainText('Could not save your notes.');
  await expect(page.locator('.ProseMirror')).toHaveText('Keep this text');
});

test('leaving during composition saves its final text before changing notes', async ({ page }) => {
  await open(page);
  const destination = 'dddddddddddddddddddddddddddddddd';
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true })));
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Composed words');
  await expect(page.locator('.ProseMirror')).toHaveText('Composed words');
  await page.evaluate(id => { location.hash = `#/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/n/${id}`; }, destination);
  await expect(page.locator('.ProseMirror')).toHaveText('Composed words');
  await expect(page).toHaveURL(new RegExp(`${note}$`));
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true })));
  await expect(page).toHaveURL(new RegExp(`${destination}$`));
  await expect.poll(() => page.evaluate(id => window.__fake.noteText(id), note)).toBe('Composed words');
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
});

test('composition timeout keeps note mounted and offers navigation retry', async ({ page }) => {
  test.setTimeout(45_000);
  await open(page);
  const destination = 'dddddddddddddddddddddddddddddddd';
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true })));
  await page.evaluate(id => { location.hash = `#/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/n/${id}`; }, destination);
  await expect(page.getByRole('alert')).toContainText('Could not save note', { timeout: 35_000 });
  await expect(page).toHaveURL(new RegExp(`${note}$`));
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__fake.openSessions())).toBe(1);
  await page.locator('.ProseMirror').evaluate(el => el.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true })));
  await page.getByRole('button', { name: 'Retry leaving note' }).click();
  await expect(page).toHaveURL(new RegExp(`${destination}$`));
});

test('a note whose open fails can still be left', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => {
    window.__fake.noteOpen = async () => { throw new Error('note open failed'); };
  });
  await page.evaluate(({ account, base }) => { location.hash = `#/a/${account}/b/${base}/n/cccccccccccccccccccccccccccccccc`; }, r);
  await expect(page.getByRole('alert')).toContainText('note open failed');
  await page.evaluate(() => { location.hash = '#/'; });
  await expect(page).toHaveURL(/#\/$/);
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('an edit from another window appears without echo', async ({ context }) => {
  const a = await context.newPage(), b = await context.newPage();
  await open(a); await open(b);
  await b.locator('.ProseMirror').click();
  const caret = await b.evaluate(() => window.getSelection()?.anchorOffset);
  await a.locator('.ProseMirror').click();
  await a.keyboard.type('Together');
  await expect.poll(() => a.evaluate(id => window.__fake.noteText(id), note)).toBe('Together');
  const ownBatches = await a.evaluate(() => window.__fake.calls.filter(x => x.startsWith('noteApply')).length);
  await expect(b.locator('.ProseMirror')).toHaveText('Together', { timeout: 1000 });
  expect(await a.evaluate(() => window.__fake.calls.filter(x => x.startsWith('noteApply')).length)).toBe(ownBatches);
  expect(await b.evaluate(() => window.__fake.calls.filter(x => x.startsWith('noteApply')).length)).toBe(0);
  expect(await b.evaluate(() => window.getSelection()?.anchorOffset)).toBe(caret);
});

test('links open outside and note links navigate inside', async ({ page }) => {
  await open(page);
  const external = 'https://example.com/';
  const destination = 'dddddddddddddddddddddddddddddddd';
  const internal = `https://basehero.com/open/${r.base}/${destination}`;
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Outside');
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('textbox', { name: /link/i }).fill(external);
  await page.getByRole('button', { name: 'Done' }).click();
  await page.locator('.ProseMirror a').click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls)).toContain(`openExternal ${external}`);
  await page.locator('.ProseMirror').click();
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('textbox', { name: /link/i }).fill(internal);
  await page.getByRole('button', { name: 'Done' }).click();
  await page.locator('.ProseMirror a').last().click();
  await expect(page).toHaveURL(new RegExp(`#\/a\/${r.account}\/b\/${r.base}\/n\/${destination}$`));
  expect(await page.evaluate(() => window.__fake.calls)).not.toContain(`openExternal ${internal}`);
});

test('Link to a note searches and inserts an internal note link', async ({ page }) => {
  await open(page);
  const target = await page.evaluate(async ref => {
    await window.__fake.createObject(ref, { kind: 'folder', parent: null, after: null, name: 'Ferry folder' });
    return window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Ferry schedule' });
  }, r);
  await page.locator('.ProseMirror').click();
  await page.keyboard.type('Ferry');
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('ControlOrMeta+k');
  await page.getByRole('button', { name: 'Link to a note' }).click();
  await page.getByRole('searchbox', { name: 'Search notes' }).fill('Ferry');
  await expect(page.locator('.note-link-results').getByRole('button', { name: 'Ferry folder' })).toHaveCount(0);
  await page.locator('.note-link-results').getByRole('button', { name: 'Ferry schedule' }).click();
  await expect(page.locator('.ProseMirror a')).toHaveAttribute('href', `https://basehero.com/open/${r.base}/${target}`);
});

test('a newer note cannot open and plainly asks for an update', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(id => window.__fake.seedNewerNote(id), note);
  await page.goto(`/#/a/${r.account}/b/${r.base}/n/${note}`);
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await expect(page.getByRole('alert')).toHaveText('This note needs a newer version of BaseHero. Update the app to open it.');
});

test('pasted content cannot run script', async ({ page }) => {
  await open(page);
  await page.locator('.ProseMirror').click();
  await page.locator('.ProseMirror').evaluate(el => {
    const data = new DataTransfer();
    data.setData('text/html', '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>Safe');
    data.setData('text/plain', 'Safe');
    el.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }));
  });
  await expect(page.locator('.ProseMirror')).toContainText('Safe');
  expect(await page.evaluate(() => (window as any).__pwned)).toBeUndefined();
  await expect(page.locator('.ProseMirror img, .ProseMirror script')).toHaveCount(0);
});
