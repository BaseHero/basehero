import assert from 'node:assert/strict';

export const afterLayout = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(resolve, 500)))));
export async function caret(page) {
  return page.evaluate(() => {
    const edit = document.querySelector('[aria-label="Note editor"] .ProseMirror');
    const range = getSelection().getRangeAt(0);
    const rect = range.getBoundingClientRect();
    let area = edit;
    while (area && area !== document.body) {
      if (/(auto|scroll)/.test(getComputedStyle(area).overflowY) && area.scrollHeight > area.clientHeight) break;
      area = area.parentElement;
    }
    const visible = area && area !== document.body ? area.getBoundingClientRect() : { top: 0, bottom: visualViewport.height };
    return { top: rect.top, bottom: rect.bottom, visibleTop: Math.max(visible.top, 0),
      visibleBottom: Math.min(visible.bottom, visualViewport.height) };
  });
}
export function assertVisible(rect) {
  assert(rect.top >= rect.visibleTop + 8, `caret above scroller: ${JSON.stringify(rect)}`);
  assert(rect.bottom <= rect.visibleBottom - 8, `caret below scroller: ${JSON.stringify(rect)}`);
}
