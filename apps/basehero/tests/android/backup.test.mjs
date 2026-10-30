import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, signUpOnDev, newNote, saved, createDevInvite } from './lib.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const folderName = `BaseHero-${crypto.randomUUID().slice(0, 8)}`;
const noteName = `Folder backup ${crypto.randomUUID().slice(0, 8)}`;
let page, credentials, folder, filesBefore, accountId;

async function nodeWith(attributes, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    adb('shell', 'uiautomator', 'dump', '/sdcard/bh-picker.xml');
    const xml = adb('shell', 'cat', '/sdcard/bh-picker.xml');
    const match = [...xml.matchAll(/<node\s([^>]*?)\/>/g)].find(([, node]) => Object.entries(attributes).every(([key, value]) => new RegExp(`${key}="[^"]*${value}[^"]*"`, 'i').test(node)));
    if (match) return match[0];
    await pause(250);
  }
  assert.fail(`DocumentsUI did not show ${JSON.stringify(attributes)}`);
}
async function tap(attributes) {
  const node = await nodeWith(attributes);
  const bounds = /bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/.exec(node);
  assert(bounds, `node has no bounds: ${node}`);
  adb('shell', 'input', 'tap', String((Number(bounds[1]) + Number(bounds[3])) / 2), String((Number(bounds[2]) + Number(bounds[4])) / 2));
}
async function chooseFolder(create = false) {
  await tap({ text: 'Download' });
  if (create) {
    await tap({ 'content-desc': 'New folder' });
    await nodeWith({ 'class': 'android.widget.EditText' });
    adb('shell', 'input', 'text', folderName);
    await tap({ text: 'OK' });
    // DocumentsUI enters the folder it just created.
  } else {
    await tap({ text: folderName });
  }
  await tap({ text: 'Use this folder' });
  await tap({ text: 'Allow', class: 'android.widget.Button' });
}
function backupFiles() {
  return adb('shell', 'find', `/sdcard/Download/${folderName}`, '-type', 'f').split('\n').filter(Boolean).sort();
}

 test.after(async () => { await page?.context().browser()?.close(); });

test('backup on the emulator writes through the picker and restores into a new account', { timeout: 240_000 }, async () => {
  assert.match(adb('shell', 'pm', 'clear', 'app.basehero'), /Success/);
  await launch(); page = await webview();
  credentials = await signUpOnDev(page);
  const editor = await newNote(page, noteName);
  await editor.fill('Kept in an encrypted folder');
  await saved(page);
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.waitForURL(/\/backup$/, { timeout: 30_000 });
  await page.getByRole('button', { name: 'Back up to a folder…' }).click();
  await chooseFolder(true);
  await page.getByText(/This will write about/).waitFor();
  await page.getByRole('button', { name: 'Start', exact: true }).click();
  await page.getByRole('button', { name: 'Change folder…' }).waitFor({ timeout: 60_000 });
  await page.getByRole('link', { name: 'Personal' }).first().click();
  await page.getByTestId('tree-row').filter({ hasText: 'Kept in an encrypted folder' }).click();
  const updated = 'Kept in an encrypted folder, updated';
  const note = page.locator('[aria-label="Note editor"] .ProseMirror[contenteditable="true"]');
  await note.waitFor();
  await note.fill(updated);
  await saved(page);
  const logsBefore = backupFiles().filter(path => path.endsWith('.bhl'));
  adb('shell', 'input', 'keyevent', 'KEYCODE_HOME');
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline && backupFiles().filter(path => path.endsWith('.bhl')).length <= logsBefore.length) await pause(250);
  filesBefore = backupFiles();
  assert(filesBefore.filter(path => path.endsWith('.bhl')).length > logsBefore.length, 'leaving after a note edit writes a new log');
  assert(filesBefore.some(path => /\/[0-9a-f]{32}\/[0-9a-f]{32}\/keys\/[^/]+\.bhk$/.test(path)), 'backup has a keys file');
  assert.match(adb('shell', 'pm', 'clear', 'app.basehero'), /Success/);
  await launch(); page = await webview();
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('button', { name: 'Restore from a backup' }).click();
  await page.getByRole('button', { name: 'Pick folder…' }).click();
  await chooseFolder();
  await page.getByText(credentials.email).first().click();
  await page.getByLabel('Password').fill(credentials.password);
  await page.getByLabel('Recovery kit').fill(credentials.kit);
  await page.getByRole('button', { name: 'Open backup' }).click();
  await page.getByText('1 note ·').first().waitFor({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Continue to sign up' }).click();
  await page.getByLabel('Invite code').fill(createDevInvite());
  await page.getByLabel('Email').fill(`restored-${Date.now()}@example.com`);
  await page.getByLabel('New password').fill(`Restored-${crypto.randomUUID()}-long`);
  await page.getByRole('button', { name: 'Sign up and restore' }).click();
  await page.getByRole('heading', { name: 'Restore complete' }).waitFor({ timeout: 45_000 });
  await page.getByRole('button', { name: 'Done' }).click();
  await page.getByRole('button', { name: "I've saved it" }).click();
  await page.getByRole('button', { name: /Personal \(restored/ }).click();
  await page.getByTestId('tree-row').filter({ hasText: 'Kept in an encrypted folder, updated' }).click();
  await page.locator('[aria-label="Note editor"] .ProseMirror').getByText('Kept in an encrypted folder, updated').waitFor({ timeout: 30_000 });
});

test('a second run with nothing changed writes nothing to the picked folder', { timeout: 90_000 }, async t => {
  if (!filesBefore) return t.skip('no previous backup');
  const account = /\/a\/([0-9a-f]{32})/.exec(page.url())?.[1];
  assert(account, 'new account is open');
  accountId = account;
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Back up to a folder…' }).click();
  await chooseFolder();
  await page.getByRole('button', { name: 'Start', exact: true }).click();
  await page.getByRole('button', { name: 'Change folder…' }).waitFor({ timeout: 60_000 });
  const invoke = (command, args) => page.evaluate(([name, params]) => window.__TAURI_INTERNALS__.invoke(name, params), [command, args]);
  const status = await invoke('backup_status', { account });
  folder = status.location.uri;
  assert.match(folder, /^content:\/\//);
  // A new device publishes its public key on its first refresh, which changes account
  // data, and so the keys file, once. Let that happen before checking unchanged runs.
  await invoke('refresh_account', { account });
  await invoke('backup_now', { account });
  const files = backupFiles().filter(path => path.includes(`/${account}/`));
  assert(files.some(path => path.endsWith('.bhk')), 'new account wrote its own backup');
  const stat = () => files.map(path => adb('shell', 'stat', '-c', '%n,%s,%Y', path));
  const before = stat();
  await page.context().browser().close();
  adb('shell', 'am', 'force-stop', 'app.basehero');
  await launch(); page = await webview();
  await page.getByRole('link', { name: 'Backup' }).waitFor({ timeout: 30_000 });
  await page.evaluate(id => window.__TAURI_INTERNALS__.invoke('backup_now', { account: id }), account);
  assert.deepEqual(backupFiles().filter(path => path.includes(`/${account}/`)), files);
  assert.deepEqual(stat(), before, 'no file was rewritten after an unchanged run across a restart');
});

test('a revoked folder permission asks to choose the folder again', { timeout: 90_000 }, async t => {
  if (!folder) return t.skip('no selected folder');
  const account = accountId;
  assert(account, 'new account is open');
  await page.getByRole('link', { name: 'Backup' }).click();
  const invoke = (command, args) => page.evaluate(([name, params]) => window.__TAURI_INTERNALS__.invoke(name, params), [command, args]);
  await invoke('release_backup_folder_for_test', { uri: folder });
  await invoke('backup_now', { account });
  const status = await invoke('backup_status', { account });
  assert.equal(status.problem?.kind, 'permissionLost');
  await page.getByRole('link', { name: 'Personal' }).first().click();
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByText('Choose the backup folder again.').first().waitFor({ timeout: 30_000 });
  assert.deepEqual(backupFiles().filter(path => filesBefore.includes(path)), filesBefore, 'revocation does not erase a backup');
});

test('a deleted picked folder pauses backup as unreachable', { timeout: 90_000 }, async t => {
  if (!folder) return t.skip('no selected folder');
  const account = accountId;
  assert(account, 'account is open');
  await page.getByRole('link', { name: 'Backup' }).click();
  await page.getByRole('button', { name: 'Change folder…' }).click();
  await chooseFolder();
  await page.getByText(/This will write about/).waitFor();
  await page.getByRole('button', { name: 'Start', exact: true }).click();
  await page.getByRole('button', { name: 'Change folder…' }).waitFor({ timeout: 60_000 });
  adb('shell', 'rm', '-r', `/sdcard/Download/${folderName}`);
  const status = await page.evaluate(id => window.__TAURI_INTERNALS__.invoke('backup_now', { account: id })
    .then(() => window.__TAURI_INTERNALS__.invoke('backup_status', { account: id })), account);
  assert.equal(status.problem?.kind, 'unreachable');
  await page.getByText(/Backup paused: can't reach/).first().waitFor({ timeout: 30_000 });
});
