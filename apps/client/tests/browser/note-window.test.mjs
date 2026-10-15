// Shell-level regression for a bound editing view. The IPC fixture is not an
// enrolled account, native Mac window, Android emulator or real Fold.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';

function boundHost() {
  const surface = crypto.randomUUID();
  window.__bhIpc.handle('note_binding', () => ({note:Array(32).fill(3),surface}));
  window.__bhIpc.handle('note_selection', () => []);
  window.__bhIpc.handle('note_open', () => ({ state: [0, 0], generation: 7, sequence: 0 }));
  window.__bhIpc.handle('note_commit', args => ({ requestId: args.requestId }));
  window.__bhIpc.handle('note_close', () => null);
}

for (const browserName of browserMatrix) {
  describe(`note window lifecycle in ${browserName}`, () => {
    test('two views keep different window-local inputs without sending a note edit', async () => {
      const server = await startUiServer();
      let browser;
      try {
        browser = await launchBrowser(browserName);
        const left = await openPage(browser, server.origin, { extraInit: [boundHost] });
        const right = await openPage(browser, server.origin, { extraInit: [boundHost] });
        await left.locator('.ProseMirror').waitFor();
        await right.locator('.ProseMirror').waitFor();
        await left.getByRole('textbox', { name: 'Link URL' }).fill('https://left.example/draft');
        await right.getByRole('textbox', { name: 'Link URL' }).fill('https://right.example/draft');
        assert.equal(await left.getByRole('textbox', { name: 'Link URL' }).inputValue(), 'https://left.example/draft');
        assert.equal(await right.getByRole('textbox', { name: 'Link URL' }).inputValue(), 'https://right.example/draft');
        for (const page of [left, right]) {
          assert.equal(await page.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_commit').length), 0);
        }
        await left.close(); await right.close();
      } finally { await browser?.close(); await server.close(); }
    });
    test('two bound views display relayed selection separately from their own', async () => {
      const server = await startUiServer();let browser;
      try {
        browser = await launchBrowser(browserName);
        const left = await openPage(browser, server.origin, {extraInit:[boundHost]});
        const right = await openPage(browser, server.origin, {extraInit:[boundHost]});
        await left.locator('.ProseMirror').waitFor();await right.locator('.ProseMirror').waitFor();
        await left.locator('.ProseMirror').click();await left.keyboard.insertText('abcd');
        await right.locator('.ProseMirror').click();await right.keyboard.insertText('abcd');
        const selected=await left.locator('.ProseMirror').evaluate(element=>{
          element.editor.commands.setTextSelection({from:1,to:3});
          const {anchor,head}=element.editor.state.selection;return {anchor,head};
        });
        await left.waitForFunction(()=>window.__bhIpc.calls.some(c=>
          c.command==='note_selection' && c.args.anchor===1 && c.args.head===3));
        const sent=await left.evaluate(()=>window.__bhIpc.calls.filter(c=>
          c.command==='note_selection' && c.args.anchor===1 && c.args.head===3).at(-1).args);
        assert.equal(sent.anchor,selected.anchor);
        assert.equal(typeof sent.surface,'string');
        await right.evaluate(message=>window.__bhNotePeers({type:'set',id:message.surface,anchor:message.anchor,head:message.head}),sent);
        assert.equal(await right.locator('.bh-peer-cursor').count(),1);
        assert.equal(await right.locator('.bh-peer-selection').count(),1);
        assert.equal(await left.locator('.bh-peer-cursor').count(),0);
        assert.equal(await right.locator('.bh-own-cursor').count(),0);
        await right.evaluate(id=>window.__bhNotePeers({type:'remove',id}),sent.surface);
        assert.equal(await right.locator('.bh-peer-cursor').count(),0);
        assert.equal(await right.locator('.bh-peer-selection').count(),0);
        await left.close();await right.close();
      } finally {await browser?.close();await server.close();}
    });
    test('a window retains its own selection indicator, input and editor through resize', async () => {
      const server = await startUiServer();
      let browser;
      try {
        browser = await launchBrowser(browserName);
        const page = await openPage(browser, server.origin, { extraInit: [boundHost] });
        const editor = page.locator('.ProseMirror');
        await editor.waitFor();
        await editor.click();
        await page.keyboard.insertText('folded typing');
        await page.waitForFunction(() => document.querySelector('[role="status"]')?.textContent === 'Saved on this device');
        const selected = await editor.evaluate(element => {
          element.editor.commands.setTextSelection({ from: 1, to: 7 });
          const { from, to } = element.editor.state.selection;
          return { from, to, text: element.editor.state.doc.textBetween(from, to) };
        });
        assert.deepEqual(selected, { from: 1, to: 7, text: 'folded' },
          'ProseMirror must hold the actual range before the toolbar takes focus');
        const input = page.getByRole('textbox', { name: 'Link URL' });
        await input.fill('https://example.com/draft');
        await page.setViewportSize({ width: 420, height: 740 });
        await page.setViewportSize({ width: 920, height: 740 });
        assert.equal(await input.inputValue(), 'https://example.com/draft');
        assert.equal(await editor.textContent(), 'folded typing');
        assert.equal(await page.locator('.bh-own-selection').count(), 1,
          'own unfocused selection remains visible at its actual text');
        assert.equal(await page.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length), 1,
          'resize must not reconstruct an editing session');
        if (process.env.BH_NOTE_SCREENSHOT_DIR) {
          mkdirSync(process.env.BH_NOTE_SCREENSHOT_DIR, { recursive: true });
          await page.screenshot({ path: path.join(process.env.BH_NOTE_SCREENSHOT_DIR, `${browserName}-local-selection.png`) });
        }
        await page.close();
      } finally { await browser?.close(); await server.close(); }
    });
  });
}
