import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, fold, unfold, signUpOnDev, saved, bh, temporaryHome } from './lib.mjs';
import { afterLayout } from './geometry.mjs';

const password = 'ferry lantern quartz';
const name = `Hidden ${Date.now()}`;
const editor = page => page.locator('[aria-label="Note editor"] .ProseMirror');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function bases(page) {
  await page.getByRole('link', { name: 'BaseHero' }).click();
  await page.getByRole('button', { name: 'New hidden base…' }).waitFor();
}
async function unlock(page) {
  await page.getByRole('button', { name: 'Unlock…' }).click();
  const dialog = page.getByRole('dialog', { name: 'Unlock hidden bases' });
  await dialog.getByLabel('Extra password').click();
  adb('shell', 'input', 'text', password.replaceAll(' ', '%s'));
  await assertClearOfKeyboard(page, dialog.getByLabel('Extra password'), dialog.getByRole('button', { name: 'Unlock', exact: true }));
  await dialog.getByRole('button', { name: 'Unlock', exact: true }).click();
  await page.getByRole('button', { name, exact: true }).waitFor();
}
async function assertClearOfKeyboard(page, field, button) {
  const deadline = Date.now() + 10_000;
  while (!/mInputShown=true/.test(adb('shell', 'dumpsys', 'input_method'))) {
    assert(Date.now() < deadline, 'the Android IME must be shown');
    await pause(100);
  }
  await afterLayout(page);
  for (const [label, target] of [['field', field], ['button', button]]) {
    const box = await target.boundingBox();
    assert(box, `${label} has no box`);
    const bottom = await page.evaluate(() => visualViewport.height);
    const dialog = await page.evaluate(() => {
      const node = document.querySelector('.hidden-dialog');
      const box = node?.getBoundingClientRect();
      return { top: box?.top, bottom: box?.bottom, clientHeight: node?.clientHeight,
        scrollHeight: node?.scrollHeight, scrollTop: node?.scrollTop, innerHeight };
    });
    assert(box.y + box.height <= bottom - 8,
      `${label} is not clear of the keyboard: ${JSON.stringify({ box, bottom, dialog })}`);
  }
}

// A missing Android IME inset, a remounted WebView on fold, or a missing
// onStop/onStart lock each fails a separate observable assertion here.
test('create and unlock with the keyboard up', { timeout: 120_000 }, async () => {
  await unfold();
  assert.match(adb('shell', 'pm', 'clear', 'app.basehero'), /Success/);
  await launch();
  const page = await webview();
  const temp = temporaryHome();
  try {
    const { email, password: accountPassword, kit } = await signUpOnDev(page);
    await bases(page);
    await page.getByRole('button', { name: 'New hidden base…' }).click();
    const dialog = page.getByRole('dialog', { name: 'New hidden base' });
    await dialog.getByLabel('Name').click();
    adb('shell', 'input', 'text', name.replaceAll(' ', '%s'));
    await dialog.getByLabel('Extra password', { exact: true }).click();
    adb('shell', 'input', 'text', password.replaceAll(' ', '%s'));
    await dialog.getByLabel("I understand this password can't be recovered").check();
    await dialog.getByLabel('Type it again').click();
    adb('shell', 'input', 'text', password.replaceAll(' ', '%s'));
    await assertClearOfKeyboard(page, dialog.getByLabel('Type it again'), dialog.getByRole('button', { name: 'Create', exact: true }));
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByRole('button', { name, exact: true }).waitFor();
    await page.getByRole('button', { name, exact: true }).click();
    const base = new URL(page.url()).hash.match(/\/b\/([^/]+)/)?.[1];
    assert(base, 'hidden base route missing');
    await page.getByRole('button', { name: 'New note' }).click();
    await page.getByLabel('Name').fill('Gelato draft');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByTestId('tree-row').last().click();
    await editor(page).fill('Gelato with Marguerite');
    await saved(page);
    await bases(page);
    await page.getByRole('button', { name: `Lock ${name}` }).click();
    await page.getByRole('button', { name, exact: true }).waitFor({ state: 'hidden' });
    await unlock(page);
    bh(['--home', temp.home, 'signin', '--server', 'https://dev-api.basehero.com',
      '--email', email, '--name', 'CLI hidden check', '--kit', kit], { home: temp.home, password: accountPassword });
    let hits = [];
    const deadline = Date.now() + 60_000;
    do {
      bh(['--home', temp.home, 'sync'], { home: temp.home });
      hits = bh(['--home', temp.home, '--unlock', 'search', 'Gelato'], { home: temp.home, hiddenPassword: password });
      if (hits.some(hit => hit.baseId === base && JSON.stringify(hit).includes('Marguerite'))) break;
      await pause(1000);
    } while (Date.now() < deadline);
    assert(hits.some(hit => hit.baseId === base && JSON.stringify(hit).includes('Marguerite')),
      'CLI did not find the Android hidden note through dev');
  } finally { temp.remove(); await page.context().browser()?.close(); }
});

test('folding with the unlock dialog open keeps the typed password and what is unlocked', { timeout: 90_000 }, async () => {
  await unfold(); await launch();
  const page = await webview();
  try {
    await bases(page);
    await page.getByRole('button', { name, exact: true }).waitFor();
    await page.getByRole('button', { name: 'Unlock…' }).click();
    const input = page.getByRole('dialog', { name: 'Unlock hidden bases' }).getByLabel('Extra password');
    await input.click();
    adb('shell', 'input', 'text', password.replaceAll(' ', '%s'));
    const length = (await input.inputValue()).length;
    assert.equal(length, password.length);
    const wide = await page.evaluate(() => innerWidth);
    fold();
    await page.waitForFunction(old => innerWidth !== old, wide, { timeout: 20_000 });
    assert.equal((await input.inputValue()).length, length);
    assert.equal(await page.getByRole('button', { name, exact: true }).isVisible(), true);
    unfold();
    await page.waitForFunction(old => innerWidth === old, wide, { timeout: 20_000 });
    assert.equal((await input.inputValue()).length, length);
    assert.equal(await page.getByRole('button', { name, exact: true }).isVisible(), true);
    await page.getByRole('dialog', { name: 'Unlock hidden bases' }).getByRole('button', { name: 'Cancel' }).click();
  } finally { await unfold(); await page.context().browser()?.close(); }
});

test('leaving briefly keeps hidden bases open', { timeout: 60_000 }, async () => {
  await launch(); const page = await webview();
  try {
    await bases(page);
    await page.getByRole('button', { name, exact: true }).waitFor();
    adb('shell', 'input', 'keyevent', 'KEYCODE_HOME');
    await launch();
    await page.getByRole('button', { name, exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name, exact: true }).isVisible(), true);
  } finally { await page.context().browser()?.close(); }
});

test('leaving longer locks hidden bases and keeps what was typed', { timeout: 120_000 }, async () => {
  await launch(); const page = await webview();
  try {
    await page.evaluate(() => localStorage.setItem('bh.lockAfterMs', '1000'));
    await bases(page);
    await page.getByRole('button', { name, exact: true }).click();
    await page.getByRole('button', { name: 'New note' }).click();
    await page.getByLabel('Name').fill('Hidden draft');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByTestId('tree-row').last().click();
    await editor(page).fill('Tripod');
    await saved(page);
    // Android freezes the renderer once BaseHero is backgrounded, so this test
    // records that the native pause reached the page and checks the lock and the
    // text on return. The blanking itself is covered by tests/ui/hidden.spec.ts.
    await page.evaluate(() => {
      window.__stopSeen = false;
      window.addEventListener('bh:stop', () => { window.__stopSeen = true; }, { once: true });
    });
    adb('shell', 'input', 'keyevent', 'KEYCODE_HOME');
    await pause(2000);
    await launch();
    assert.equal(await page.evaluate(() => window.__stopSeen), true, 'the native pause did not reach the page');
    await page.getByRole('button', { name: 'Unlock…' }).waitFor();
    await page.getByRole('button', { name, exact: true }).waitFor({ state: 'hidden' });
    await unlock(page);
    await page.getByRole('button', { name, exact: true }).click();
    await page.getByTestId('tree-row').filter({ hasText: /Hidden draft|Tripod/ }).last().click();
    await editor(page).getByText('Tripod').waitFor();
    assert.match(await editor(page).innerText(), /Tripod/);
  } finally {
    await page.evaluate(() => localStorage.removeItem('bh.lockAfterMs')).catch(() => {});
    await page.context().browser()?.close();
  }
});
