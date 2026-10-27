import { test } from 'node:test';
import assert from 'node:assert/strict';
import { launch, webview, fold, unfold, newNote, saved } from './lib.mjs';
import { afterLayout, caret, assertVisible } from './geometry.mjs';

const paragraph = n => `Paragraph ${String(n).padStart(3, '0')} ferry travel notes.`;
async function resize(page, action) {
  const oldWidth = await page.evaluate(() => innerWidth);
  action();
  await page.waitForFunction(before => innerWidth !== before, oldWidth, { timeout: 20_000 });
  await afterLayout(page);
}
async function selectParagraph(page, n) {
  await page.evaluate(index => {
    const p = document.querySelectorAll('[aria-label="Note editor"] .ProseMirror p')[index];
    if (!p) throw Error(`paragraph ${index} missing`);
    const range = document.createRange();
    range.setStart(p.firstChild, Math.min(5, p.firstChild.textContent.length)); range.collapse(true);
    const selection = getSelection(); selection.removeAllRanges(); selection.addRange(range);
    p.closest('.ProseMirror').focus();
  }, n);
}
async function firstVisibleParagraph(page) {
  return page.evaluate(() => {
    const paragraphs = [...document.querySelectorAll('[aria-label="Note editor"] .ProseMirror p')];
    return paragraphs.findIndex(p => p.getBoundingClientRect().bottom > 48);
  });
}

test('folding and unfolding keep paragraph 120 caret in view and preserve a reading anchor', { timeout: 120_000 }, async () => {
  await unfold(); await launch();
  const page = await webview();
  try {
    const edit = await newNote(page, 'Fold check');
    await edit.fill(Array.from({ length: 200 }, (_, i) => paragraph(i)).join('\n'));
    await page.waitForFunction(() => document.querySelectorAll('[aria-label="Note editor"] .ProseMirror p').length === 200);
    await saved(page);
    await selectParagraph(page, 120);
    await page.evaluate(() => getSelection().anchorNode.parentElement.scrollIntoView({ block: 'center' }));
    await resize(page, fold); assertVisible(await caret(page));
    await resize(page, unfold); assertVisible(await caret(page));
    // A reader who has scrolled away must not be yanked back to the caret.
    await page.evaluate(() => window.scrollTo(0, 0));
    await afterLayout(page);
    const anchor = await firstVisibleParagraph(page);
    await resize(page, fold);
    assert.equal(await firstVisibleParagraph(page), anchor, 'reading anchor moved on folding');
    await resize(page, unfold);
    assert.equal(await firstVisibleParagraph(page), anchor, 'reading anchor moved on unfolding');
  } finally { await unfold(); await page.context().browser()?.close(); }
});
