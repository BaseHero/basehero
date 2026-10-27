import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { adb, launch, webview, bh, temporaryHome, signUpOnDev, newNote, saved } from './lib.mjs';

// A valid, hand-checked 1x1 PNG; the export must contain these exact bytes.
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg==', 'base64');
const pdf = Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n');
const noteName = `Emulator files ${crypto.randomUUID().slice(0, 8)}`;
const imageName = 'emulator-photo.png';
const pdfName = 'emulator-document.pdf';
const older = 'Ferry at 9';
const newer = 'Ferry at 10';
let page, home, baseId, noteId;

function cli(args) { return bh(['--home', home.home, ...args], { home: home.home }); }
async function attach(editor, event, name, mime, bytes) {
  await editor.evaluate((el, { event, name, mime, bytes }) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([new Uint8Array(bytes)], name, { type: mime }));
    if (event === 'paste') el.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: transfer }));
    else el.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: transfer }));
  }, { event, name, mime, bytes: Array.from(bytes) });
}
async function waitForCliNote() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    cli(['sync']);
    const notes = cli(['ls', '--base', baseId]);
    const found = notes.find(note => note.id === noteId);
    if (found) return;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.fail('Android note did not reach the CLI within 30 seconds');
}

test.after(async () => {
  home?.remove();
  await page?.context().browser()?.close();
});

test('an image pasted on the emulator reaches the CLI export unchanged', { timeout: 180_000 }, async () => {
  assert.match(adb('shell', 'pm', 'clear', 'app.basehero'), /Success/);
  await launch();
  page = await webview();
  home = temporaryHome();
  const { email, password, kit } = await signUpOnDev(page);
  const editor = await newNote(page, noteName);
  await editor.fill(older);
  await saved(page);
  const ids = new URL(page.url()).hash.match(/\/b\/([0-9a-f]{32})\/n\/([0-9a-f]{32})/);
  assert(ids, 'note route must identify the base and note');
  [, baseId, noteId] = ids;
  await attach(editor, 'paste', imageName, 'image/png', png);
  const image = editor.locator('img');
  await image.waitFor({ timeout: 30_000 });
  assert.match(await image.getAttribute('src'), /^blob:/);
  await image.evaluate(img => img.decode());
  assert.equal(await image.evaluate(img => img.naturalWidth), 1);
  await saved(page);
  bh(['--home', home.home, 'signin', '--server', 'https://dev-api.basehero.com',
    '--email', email, '--name', 'CLI files check', '--kit', kit], { home: home.home, password });
  await waitForCliNote();
  const out = join(home.home, 'export');
  cli(['export', '--base', baseId, '--out', out]);
  const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
  const file = manifest.objects.find(item => item.type === 'core.file' && item.path.endsWith(`/${imageName}`));
  assert(file, 'export manifest must identify the pasted image');
  assert.deepEqual(readFileSync(resolve(out, file.path)), png);
});

test('a PDF opens in the system viewer', { timeout: 90_000 }, async t => {
  if (!noteId) return t.skip('account setup failed');
  const editor = page.locator('[aria-label="Note editor"] .ProseMirror[contenteditable="true"]');
  await attach(editor, 'drop', pdfName, 'application/pdf', pdf);
  await page.getByRole('button', { name: 'Note options' }).click();
  const files = page.getByRole('region', { name: 'Files' });
  await files.getByText(pdfName, { exact: true }).waitFor({ timeout: 30_000 });
  const row = files.locator('li').filter({ hasText: pdfName });
  await row.getByRole('button', { name: 'Open' }).click();
  try {
    const activities = adb('shell', 'dumpsys', 'activity', 'activities');
    assert.match(activities, new RegExp(`Intent \\{ act=android\\.intent\\.action\\.VIEW dat=content://app\\.basehero\\.files/open/${baseId}/[0-9a-f]{32}/${pdfName} typ=application/pdf`));
  } finally {
    await launch();
  }
  // Android drains the editor while Docs is in front; coming back, the same
  // note must take typing again without being reopened.
  await editor.locator('p').last().click();
  adb('shell', 'input', 'text', 'Back%sfrom%sDocs');
  await page.waitForFunction(() =>
    document.querySelector('[aria-label="Note editor"] .ProseMirror')?.textContent?.includes('Back from Docs'), null, { timeout: 30_000 });
  await saved(page);
});

test('restoring a version on the emulator shows the old text', { timeout: 90_000 }, async t => {
  if (!noteId) return t.skip('account setup failed');
  const step = resolve(import.meta.dirname, '../../../../target/debug/examples/keep_emulator_version');
  const env = { PATH: process.env.PATH, HOME: home.home, XDG_CONFIG_HOME: home.home, GH_CONFIG_DIR: home.home };
  try {
    execFileSync(step, [home.home, baseId, noteId], { env, timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    assert.fail(`CLI version step failed: ${error.code ?? error.status}: ${error.stderr?.toString() ?? ''}`);
  }
  const { versions } = cli(['versions', '--base', baseId, noteId]);
  assert(versions.length > 0, 'the CLI-side clock step must keep the old version');
  const editor = page.locator('[aria-label="Note editor"] .ProseMirror[contenteditable="true"]');
  await editor.fill(newer);
  await saved(page);
  assert.match(await editor.innerText(), /Ferry at 10/);
  const panel = page.getByRole('region', { name: 'Versions' });
  const options = page.getByRole('button', { name: 'Note options' });
  if (await panel.count()) await options.click();
  await options.click(); // Remount history after the CLI-side version was posted.
  await panel.locator(`li[data-seq="${versions[0].seq}"] button`).click();
  await panel.getByRole('button', { name: 'Restore this version' }).click();
  await panel.getByText('Restore this version? The current text is kept as a version too, so you can switch back.').waitFor();
  await panel.getByRole('button', { name: 'Confirm restore' }).click();
  await editor.getByText(older).waitFor({ timeout: 30_000 });
  assert.doesNotMatch(await editor.innerText(), /Ferry at 10/);
});
