import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, bh, temporaryHome, signUpOnDev, newNote, saved, openBase } from './lib.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

test('a note typed in the real Android editor reaches a second device through dev', { timeout: 180_000 }, async () => {
  await launch();
  const page = await webview();
  const temp = temporaryHome();
  try {
    const { email, password, kit } = await signUpOnDev(page);
    const editor = await newNote(page);
    await editor.fill('Ferry at 9'); // Exercises Android note_apply's JSON number-array IPC.
    await saved(page);
    bh(['--home', temp.home, 'signin', '--server', 'https://dev-api.basehero.com',
      '--email', email, '--name', 'CLI check', '--kit', kit], { home: temp.home, password });
    let hits = [];
    const deadline = Date.now() + 60_000;
    do {
      bh(['--home', temp.home, 'sync'], { home: temp.home });
      hits = bh(['--home', temp.home, 'search', 'Ferry'], { home: temp.home });
      if (hits.some(hit => JSON.stringify(hit).includes('Ferry at 9'))) break;
      await pause(1000);
    } while (Date.now() < deadline);
    assert(hits.some(hit => JSON.stringify(hit).includes('Ferry at 9')), 'CLI did not find the Android note after sync');
  } finally {
    temp.remove();
    await page.context().browser()?.close();
  }
});

test('force-stop immediately after typing preserves the edit on relaunch', { timeout: 90_000 }, async () => {
  await launch();
  const page = await webview();
  try {
    const editor = await newNote(page, 'Shutdown check');
    await editor.fill('Tripod');
    adb('shell', 'am', 'force-stop', 'app.basehero');
    await launch();
    const reopened = await webview();
    try {
      await openBase(reopened);
      await reopened.getByTestId('tree-row').filter({ hasText: 'Tripod' }).first().click();
      await reopened.locator('[aria-label="Note editor"] .ProseMirror').getByText('Tripod').waitFor();
    } finally { await reopened.context().browser()?.close(); }
  } finally { await page.context().browser()?.close(); }
});
