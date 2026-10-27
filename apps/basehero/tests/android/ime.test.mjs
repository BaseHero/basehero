import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, fold, unfold, newNote, saved } from './lib.mjs';
import { caret, afterLayout } from './geometry.mjs';

async function waitForIme(shown) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (/mInputShown=(true|false)/.exec(adb('shell', 'dumpsys', 'input_method'))?.[1] === String(shown)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail(`Android IME did not become ${shown ? 'visible' : 'hidden'}`);
}

test('Android keyboard does not cover a caret near the bottom', { timeout: 90_000 }, async () => {
  await unfold(); await launch();
  const page = await webview();
  try {
    const edit = await newNote(page, 'Keyboard check');
    await edit.fill(Array.from({ length: 35 }, (_, i) => `Bottom line ${i}`).join('\n'));
    await saved(page);
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
    await waitForIme(false);
    await edit.locator('p').last().click();
    await waitForIme(true);
    await afterLayout(page);
    const rect = await caret(page);
    assert(rect.bottom <= rect.visibleBottom - 8, `IME covers caret: ${JSON.stringify(rect)}`);
  } finally { await page.context().browser()?.close(); }
});

test('Japanese composition survives folding and leaving/reopening the note', { timeout: 90_000 }, async () => {
  await unfold(); await launch();
  const page = await webview();
  const cdp = await page.context().newCDPSession(page);
  try {
    const edit = await newNote(page, 'Composition check');
    await edit.click();
    await cdp.send('Input.imeSetComposition', { text: 'こん', selectionStart: 2, selectionEnd: 2 });
    await page.waitForFunction(() => document.querySelector('[aria-label="Note editor"] .ProseMirror')?.textContent.includes('こん'));
    const width = await page.evaluate(() => innerWidth);
    fold();
    await page.waitForFunction(old => innerWidth !== old, width, { timeout: 20_000 });
    await afterLayout(page);
    assert.match(await edit.textContent(), /こん/, 'composition vanished on fold');
    await cdp.send('Input.insertText', { text: 'こん' });
    await saved(page);
    const path = new URL(page.url()).hash;
    await page.evaluate(() => window.__bhBack());
    await page.waitForFunction(old => location.hash !== old, path);
    await page.evaluate(hash => { location.hash = hash; }, path);
    await page.locator('[aria-label="Note editor"] .ProseMirror').getByText('こん').waitFor();
  } finally {
    await unfold(); await cdp.detach(); await page.context().browser()?.close();
  }
});
