import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { adb, bh, createAdb, createDevInvite, launch, temporaryHome, webview } from '../../../basehero/tests/android/lib.mjs';

const pkg = 'app.basehero.sample';
const { home, remove } = temporaryHome();
let page, base;
const password = `Test-${randomUUID()}-long`;
const options = { home, password };
test.after(async () => {
  if (page) await page.context().browser()?.close();
  remove();
});

test('the sample installs credentials from bh app connect', async () => {
  const invite = createDevInvite();
  const email = `sample-${randomUUID()}@example.com`;
  const signup = bh(['signup', '--server', 'https://dev-api.basehero.com', '--invite', invite,
    '--email', email, '--name', 'Tester'], options);
  assert(signup.kit);
  const file = join(home, 'creds.json');
  const connection = bh(['app', 'connect', '--name', 'Tester - BaseHero Sample',
    '--new-base', 'Sample readings', '--out', file], options);
  base = connection.base ?? JSON.parse(readFileSync(file, 'utf8')).bases[0];
  const input = readFileSync(file);
  createAdb((bin, args, opts) => execFileSync(bin, args, { ...opts, input }))(
    'exec-in', 'run-as', pkg, 'sh', '-c', 'cat > app-credentials.json');
  rmSync(file);
  await launch(pkg);
  page = await webview(pkg);
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.locator('#status').filter({ hasText: new RegExp(`connected ${base} as [a-f0-9]{32}`) }).waitFor({ timeout: 30_000 });
  assert(!adb('shell', 'run-as', pkg, 'ls', '-a').split(/\s+/).includes('app-credentials.json'),
    'credentials file must be deleted after connection');
  const devices = bh(['devices'], options);
  assert(devices.some(d => d.name === 'Tester - BaseHero Sample' && d.kind.toLowerCase() === 'app'));
});

test('it writes a typed record and reads it back', async () => {
  await page.getByLabel('Reading value').fill('42');
  await page.getByRole('button', { name: 'Write reading' }).click();
  await page.locator('#status').filter({ hasText: /wrote 42/ }).waitFor({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Read back' }).click();
  await page.locator('#status').filter({ hasText: /42/ }).waitFor({ timeout: 30_000 });
  // The app syncs independently; poll the owner's local copy by asking it to sync.
  let rows;
  const deadline = Date.now() + 30_000;
  do {
    bh(['sync'], options);
    rows = bh(['record', 'query', '--type', 'sample.reading'], options);
    if (rows.length === 1 && rows[0].fields.value === 42) break;
    assert(Date.now() < deadline, 'reading did not reach the full device');
  } while (true);
  assert.equal(rows.length, 1);
});

test('Hero uses the record', () => {
  const response = bh(['hero', 'ask', '--base', base,
    'List the sample.reading records in this base and read today\'s record. What was the sample reading today?'], options);
  assert(response.steps.some(step => step.tool === 'read' && step.base === base),
    'Hero must read the sample record');
  assert.match(response.text, /42/, 'Hero must answer using the record value');
  console.log('Hero reply:', response.text);
});

test('the app calls a model as its device', async () => {
  await page.getByLabel('Model question').fill('Reply with the word ferry.');
  await page.getByRole('button', { name: 'Ask the model' }).click();
  await page.locator('#status').filter({ hasText: /ferry/i }).waitFor({ timeout: 30_000 });
});
