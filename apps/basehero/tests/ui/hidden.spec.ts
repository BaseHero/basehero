import { test, expect, type Page } from '@playwright/test';

const password = 'ferry lantern quartz';
async function setup(page: Page) {
  await page.goto('/');
  const account = await page.evaluate(async () => {
    const signed = await window.__fake.signUp({ invite: 'WELCOME', email: 'dan@example.com', password: 'account password', deviceName: 'Mac' });
    await window.__fake.setKitSaved(signed.account.id, signed.kit);
    await window.__fake.createBase(signed.account.id, 'Personal');
    return signed.account.id;
  });
  await page.evaluate(id => { location.hash = `#/a/${id}`; }, account);
  await expect(page.getByText('HIDDEN BASES')).toBeVisible();
  return account;
}
async function create(page: Page, name = 'Zebra Diary', secret = password) {
  await page.getByRole('button', { name: 'New hidden base…' }).click();
  const dialog = page.getByRole('dialog', { name: 'New hidden base' });
  await dialog.getByLabel('Name').fill(name);
  await dialog.getByLabel('Extra password', { exact: true }).fill(secret);
  await dialog.getByLabel('Type it again').fill(secret);
  await dialog.getByLabel("I understand this password can't be recovered").check();
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

test('the hidden section looks the same with and without hidden bases', async ({ page }) => {
  const account = await setup(page);
  const before = await page.locator('.bases-screen').innerText();
  await page.evaluate(async ({ account, password }) => {
    await window.__fake.createHiddenBase(account, 'Zebra Diary', password);
    await window.__fake.createHiddenBase(account, 'Another Diary', password);
    await window.__fake.lockAllHidden();
  }, { account, password });
  await expect.poll(() => page.locator('.bases-screen').innerText()).toBe(before);
});
test('unlocking shows the bases a password opens, and a wrong one says only that', async ({ page }) => {
  const account = await setup(page);
  await page.evaluate(async ({ account, password }) => {
    await window.__fake.createHiddenBase(account, 'Zebra Diary', password);
    await window.__fake.createHiddenBase(account, 'Another Diary', password);
    await window.__fake.lockAllHidden();
  }, { account, password });
  await page.getByRole('button', { name: 'Unlock…' }).click();
  const dialog = page.getByRole('dialog', { name: 'Unlock hidden bases' });
  await dialog.getByLabel('Extra password').fill('wrong');
  await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(dialog.getByRole('alert')).toHaveText('No hidden bases open with that password.');
  await dialog.getByLabel('Extra password').fill(password);
  await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Another Diary', exact: true })).toBeVisible();
});
test('create coaches on strength and needs matching passwords and the acknowledgement', async ({ page }) => {
  await setup(page);
  await page.getByRole('button', { name: 'New hidden base…' }).click();
  const dialog = page.getByRole('dialog', { name: 'New hidden base' });
  await dialog.getByLabel('Name').fill('Zebra Diary');
  await dialog.getByLabel('Extra password', { exact: true }).fill('password123');
  await dialog.getByLabel('Type it again').fill('different');
  await expect(dialog.getByText("The passwords don't match.")).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Create', exact: true })).toBeDisabled();
  await dialog.getByLabel('Type it again').fill('password123');
  await expect(dialog.getByText('Weak')).toBeVisible();
  await expect(dialog.getByText('Add another word or two. Length helps more than symbols.')).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Create', exact: true })).toBeDisabled();
  await dialog.getByLabel("I understand this password can't be recovered").check();
  await expect(dialog.getByRole('button', { name: 'Create', exact: true })).toBeEnabled();
});
test('locking hides the base in every window', async ({ context }) => {
  const first = await context.newPage(); const second = await context.newPage();
  const account = await setup(first);
  await create(first);
  const base = await first.evaluate(async id => (await window.__fake.bases(id)).find(b => b.hidden)!.id, account);
  const note = await first.evaluate(ref => window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Gelato with Marguerite' }), { account, base });
  await setup(second); await create(second);
  await second.evaluate(async ({ account, base, note }) => {
    const own = await window.__fake.createObject({ account, base }, { kind: 'note', parent: null, after: null, name: 'Gelato with Marguerite' });
    if (own !== note) throw new Error('The two fake windows must seed the same note ID');
    location.hash = `#/a/${account}/b/${base}/n/${note}`;
  }, { account, base, note });
  await expect(second.getByTestId('tree-row').getByText('Gelato with Marguerite')).toBeVisible();
  await first.getByRole('button', { name: 'Lock Zebra Diary' }).click();
  await expect(second).toHaveURL(new RegExp(`#/a/${account}$`));
  for (const page of [first, second]) { await expect(page.locator('body')).not.toContainText('Zebra Diary'); await expect(page.locator('body')).not.toContainText('Gelato with Marguerite'); }
});
test('locking waits for open notes to save', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(async id => (await window.__fake.bases(id)).find(b => b.hidden)!.id, account);
  const note = await page.evaluate(ref => window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Draft' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; window.__fake.noteApply = async function (session, update) { await new Promise(resolve => setTimeout(resolve, 500)); return Object.getPrototypeOf(this).noteApply.call(this, session, update); }; }, { account, base, note });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').fill('Tripod');
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => /noteApply|lockHidden/.test(c)).map(c => c.split(' ')[0]).slice(-2))).toEqual(['noteApply', 'lockHidden']);
});
test('leaving the app drains and blanks at once, and locks after a minute', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(async id => (await window.__fake.bases(id)).find(b => b.hidden)!.id, account);
  const note = await page.evaluate(ref => window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Gelato with Marguerite' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.getByTestId('tree-row').getByText('Gelato with Marguerite')).toBeVisible();
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').fill('Tripod');
  await expect(page.locator('.ProseMirror')).toContainText('Tripod');
  await page.clock.install();
  const stoppedAt = await page.evaluate(() => { const now = Date.now(); window.dispatchEvent(new Event('bh:stop')); return now; });
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(call => call === 'noteApply'))).toBe(true);
  await expect(page.getByTestId('tree-row').getByText('Gelato with Marguerite')).toBeHidden();
  await expect(page.locator('.ProseMirror')).toBeHidden();
  // The save needed time to run; now freeze it, so a loaded machine's delays
  // can't carry the clock past the minute before the check.
  // Until paused, the page's clock runs with real time, so this is ahead of it.
  const pausedAt = Date.now() + 2_000;
  await page.clock.pauseAt(pausedAt);
  await page.clock.runFor(59_000 - (pausedAt - stoppedAt));
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(0);
  await page.clock.runFor(1_000);
  // Past the minute; locking drains the editor first, which needs time to run.
  await page.clock.resume();
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
  expect(await page.evaluate(() => window.__fake.calls.findIndex(c => c === 'noteApply') < window.__fake.calls.findIndex(c => c === 'lockAllHidden'))).toBe(true);
});
test('coming back within the minute keeps hidden bases open; later, locks first', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(async id => (await window.__fake.bases(id)).find(b => b.hidden)!.id, account);
  const note = await page.evaluate(ref => window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Gelato with Marguerite' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.getByTestId('tree-row').getByText('Gelato with Marguerite')).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 5000 } })));
  await expect(page.getByTestId('tree-row').getByText('Gelato with Marguerite')).toBeVisible();
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(0);
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } })));
  await expect(page).toHaveURL(new RegExp(`#/a/${account}$`));
  await expect(page.locator('body')).not.toContainText('Gelato with Marguerite');
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
});
test('a note open when leaving the app takes typing again on return', async ({ page }) => {
  const account = await setup(page);
  const base = await page.evaluate(async id => (await window.__fake.bases(id)).find(b => !b.hidden)!.id, account);
  const note = await page.evaluate(ref => window.__fake.createObject(ref, { kind: 'note', parent: null, after: null, name: 'Ferry at 9' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  const editor = page.locator('[aria-label="Note editor"] .ProseMirror');
  await expect(editor).toHaveAttribute('contenteditable', 'true');
  // Android suspends the page's timers while it's away, so the return can
  // arrive before the drain has taken its hold.
  await page.clock.install();
  await page.evaluate(() => {
    window.dispatchEvent(new Event('bh:stop'));
    window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 1000 } }));
  });
  await page.clock.runFor(1000);
  await page.clock.resume();
  await editor.click();
  await page.keyboard.type('Pier ');
  await expect(editor).toContainText('Pier');
  for (const awayMs of [5000, 61000]) {
    // Within the minute, and after it, when hidden bases lock on return.
    await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
    await page.evaluate(ms => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: ms } })), awayMs);
    await expect(editor).toHaveAttribute('contenteditable', 'true');
    await expect(page.getByText('Saving before update…')).toHaveCount(0);
  }

  await editor.click();
  await page.keyboard.type('Gate 4');
  await expect(editor).toContainText('Gate 4');
});
test('debug lock timeout override locks after the configured time', async ({ page }) => {
  const account = await setup(page); await create(page);
  await page.evaluate(() => localStorage.setItem('bh.lockAfterMs', '100'));
  // An installed clock keeps running with real time until paused, which would
  // let a loaded machine's delays cross the 100 ms boundary.
  await page.clock.install();
  await page.clock.pauseAt(Date.now() + 1_000);
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await page.clock.runFor(99);
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(0);
  await page.clock.runFor(1);
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 101 } })));
  await expect(page.getByRole('button', { name: 'Unlock…' })).toBeVisible();
  expect(account).toBeTruthy();
});

test('automatic timer locks despite a failed editor save', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  const note = await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Secret' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.evaluate(() => { window.__fake.noteApply = async () => { throw Error('save failed'); }; localStorage.setItem('bh.lockAfterMs', '100'); });
  await page.locator('.ProseMirror').fill('Secret pending text');
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
  expect(await page.evaluate(id => window.__fake.bases(id).then(b => b.some(x => x.hidden)), account)).toBe(false);
});

test('a late resume locks despite a failed editor save before uncovering', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  const note = await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Secret' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.evaluate(() => { window.__fake.noteApply = async () => { throw Error('save failed'); }; });
  await page.locator('.ProseMirror').fill('Secret pending text');
  await page.evaluate(() => {
    window.dispatchEvent(new Event('bh:stop'));
    window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } }));
  });
  await expect(page).toHaveURL(new RegExp(`#/a/${account}$`));
  await expect(page.locator('body')).not.toContainText('Secret pending text');
  expect(await page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
});

test('failed automatic lock stays covered and retries on resume and stop', async ({ page }) => {
  const account = await setup(page); await create(page);
  await page.evaluate(() => {
    const original = window.__fake.lockAllHidden.bind(window.__fake);
    let failures = 2;
    window.__fake.lockAllHidden = async () => { if (failures-- > 0) throw Error('lock failed'); return original(); };
    window.dispatchEvent(new Event('bh:stop'));
    window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } }));
  });
  await expect(page.getByRole('alert')).toContainText('Could not lock hidden bases');
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeHidden();
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } })));
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeHidden();
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } })));
  await expect.poll(() => page.evaluate(id => window.__fake.bases(id).then(b => b.some(x => x.hidden)), account)).toBe(false);
});

test('locking removes visible hidden search results and refuses a pending old search response', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Pistachio secret title' }), { account, base });
  await page.getByRole('searchbox', { name: 'Search' }).fill('Pistachio');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page.getByText('Pistachio secret title')).toBeVisible();
  await page.evaluate(account => {
    const search = window.__fake.search.bind(window.__fake);
    window.__fake.search = async (...args) => {
      const snapshot = await search(...args);
      await new Promise<void>(resolve => { (window as typeof window & { releaseSearch?: () => void }).releaseSearch = resolve; });
      return snapshot;
    };
    window.__fake.emit({ kind: 'account', account, event: 'BasesChanged' });
  }, account);
  await expect.poll(() => page.evaluate(() => !!(window as typeof window & { releaseSearch?: () => void }).releaseSearch)).toBe(true);
  await page.evaluate(() => { void window.__fake.lockAllHidden(); (window as typeof window & { releaseSearch?: () => void }).releaseSearch?.(); });
  await expect(page.locator('body')).not.toContainText('Pistachio secret title');
  await expect(page.locator('body')).not.toContainText('Zebra Diary');
});

test('a base-list invalidation during an older request evicts the locked route', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  const note = await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Secret title' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.getByTestId('tree-row').getByText('Secret title')).toBeVisible();
  await page.evaluate(account => {
    const bases = window.__fake.bases.bind(window.__fake);
    let first = true;
    window.__fake.bases = async (id) => {
      if (!first) return bases(id);
      first = false;
      const snapshot = await bases(id);
      await new Promise<void>(resolve => { (window as typeof window & { releaseBases?: () => void }).releaseBases = resolve; });
      return snapshot;
    };
    window.__fake.emit({ kind: 'account', account, event: 'BasesChanged' });
  }, account);
  await expect.poll(() => page.evaluate(() => !!(window as typeof window & { releaseBases?: () => void }).releaseBases)).toBe(true);
  await page.evaluate(({ account, base }) => { void window.__fake.lockHidden(account, base); (window as typeof window & { releaseBases?: () => void }).releaseBases?.(); }, { account, base });
  await expect(page).toHaveURL(new RegExp(`#/a/${account}$`));
  await expect(page.locator('body')).not.toContainText('Secret title');
});

test('late resume keeps a hidden editor covered until an in-flight base check evicts it', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  const note = await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Secret title' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.locator('.ProseMirror').fill('Private body visible after lock');
  await page.evaluate(account => {
    const bases = window.__fake.bases.bind(window.__fake);
    let first = true;
    window.__fake.bases = async id => {
      if (!first) return bases(id);
      first = false;
      const snapshot = await bases(id);
      await new Promise<void>(resolve => { (window as typeof window & { releaseBases?: () => void }).releaseBases = resolve; });
      return snapshot;
    };
    window.__fake.emit({ kind: 'account', account, event: 'BasesChanged' });
  }, account);
  await expect.poll(() => page.evaluate(() => !!(window as typeof window & { releaseBases?: () => void }).releaseBases)).toBe(true);
  await page.evaluate(() => {
    window.dispatchEvent(new Event('bh:stop'));
    window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 61000 } }));
  });
  await expect.poll(() => page.evaluate(() => window.__fake.calls.filter(c => c === 'lockAllHidden').length)).toBe(1);
  expect(await page.evaluate(id => window.__fake.bases(id).then(b => b.some(x => x.hidden)), account)).toBe(false);
  // Let the lock's promise continuation run while the old snapshot remains held.
  await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 0)));
  await expect(page.locator('.ProseMirror')).toBeHidden();
  await expect(page.locator('.away-hidden')).toHaveCount(1);
  await expect(page.getByText('Private body visible after lock')).toBeHidden();
  await page.evaluate(() => (window as typeof window & { releaseBases?: () => void }).releaseBases?.());
  await expect(page).toHaveURL(new RegExp(`#/a/${account}$`));
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await expect(page.locator('.away-hidden')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('Private body visible after lock');
});

test('away cover hides unlocked names in the list and search, then restores the list', async ({ page }) => {
  await setup(page); await create(page);
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeHidden();
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('bh:resume', { detail: { awayMs: 5000 } })));
  await expect(page.getByRole('button', { name: 'Zebra Diary', exact: true })).toBeVisible();
  await page.getByRole('searchbox', { name: 'Search' }).fill('Zebra');
  await page.getByRole('searchbox', { name: 'Search' }).press('Enter');
  await expect(page.getByRole('searchbox', { name: 'Search' })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('bh:stop')));
  await expect(page.getByRole('searchbox', { name: 'Search' })).toBeHidden();
});

test('evicting a hidden route disposes its editor even when saving fails', async ({ page }) => {
  const account = await setup(page); await create(page);
  const base = await page.evaluate(id => window.__fake.bases(id).then(b => b.find(x => x.hidden)!.id), account);
  const note = await page.evaluate(r => window.__fake.createObject(r, { kind: 'note', parent: null, after: null, name: 'Secret title' }), { account, base });
  await page.evaluate(({ account, base, note }) => { location.hash = `#/a/${account}/b/${base}/n/${note}`; }, { account, base, note });
  await expect(page.locator('.ProseMirror')).toBeVisible();
  await page.evaluate(() => { window.__fake.noteApply = async () => { throw Error('save failed'); }; });
  await page.locator('.ProseMirror').fill('Secret pending text');
  await page.evaluate(({ account, base }) => window.__fake.lockHidden(account, base), { account, base });
  await expect(page).toHaveURL(new RegExp(`#/a/${account}$`));
  await expect.poll(() => page.evaluate(() => window.__fake.calls.some(c => c.startsWith('noteClose')))).toBe(true);
  expect(await page.evaluate(async () => {
    const { drainAll } = await import('../../src/lib/editor/host');
    const before = window.__fake.calls.filter(call => call.startsWith('noteApply')).length;
    try { await drainAll(); }
    catch { return false; }
    return window.__fake.calls.filter(call => call.startsWith('noteApply')).length === before;
  })).toBe(true);
});

test('the UI never stores an extra password', async ({ page }) => {
  const account = await setup(page); await create(page, 'Zebra Diary', password);
  await page.getByRole('button', { name: 'Lock Zebra Diary' }).click();
  await page.getByRole('button', { name: 'Unlock…' }).click();
  await page.getByRole('dialog').getByLabel('Extra password').fill(password);
  await page.getByRole('dialog').getByRole('button', { name: 'Unlock', exact: true }).click();
  expect(await page.evaluate(async secret => {
    const values = [...Object.values(localStorage), ...Object.values(sessionStorage)];
    for (const db of await indexedDB.databases()) if (db.name) values.push(db.name);
    return values.some(v => String(v).includes(secret)) || [...document.querySelectorAll<HTMLInputElement>('input[type=password]')].some(input => input.value.includes(secret));
  }, password)).toBe(false);
});
test('the dialogs fit folded and unfolded', async ({ page }) => {
  await setup(page);
  for (const size of [{ width: 412, height: 915 }, { width: 884, height: 1000 }]) {
    await page.setViewportSize(size);
    for (const [button, title, main] of [['Unlock…', 'Unlock hidden bases', 'Unlock'], ['New hidden base…', 'New hidden base', 'Create']]) {
      await page.getByRole('button', { name: button }).click();
      const dialog = page.getByRole('dialog', { name: title });
      if (main === 'Create') {
        await dialog.getByLabel('Name').fill('Zebra Diary');
        await dialog.getByLabel('Extra password', { exact: true }).fill('password123');
        await dialog.getByLabel('Type it again').fill('password123');
        await expect(dialog.getByText('Weak')).toBeVisible();
      }
      for (const item of [dialog, dialog.getByRole('button', { name: main, exact: true })]) {
        const box = await item.boundingBox(); expect(box).not.toBeNull();
        expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.y).toBeGreaterThanOrEqual(0);
        expect(box!.x + box!.width).toBeLessThanOrEqual(size.width); expect(box!.y + box!.height).toBeLessThanOrEqual(size.height);
      }
      if (process.env.BH_HIDDEN_SCREENSHOTS === '1') {
        await page.screenshot({ path: `/tmp/hidden-${main.toLowerCase()}-${size.width}x${size.height}.png` });
      }
      await dialog.getByRole('button', { name: 'Cancel' }).click();
    }
  }
});
