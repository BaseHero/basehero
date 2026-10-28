import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, bh, launch, signUpOnDev, temporaryHome, webview } from '../../../basehero/tests/android/lib.mjs';

const pkg = 'app.basehero.sample';
const { home, remove } = temporaryHome();
let page, ownerPage, base, sampleDevice, sampleName;
const options = { home };
test.after(async () => {
  if (page) await page.context().browser()?.close();
  if (ownerPage) await ownerPage.context().browser()?.close();
  remove();
});

test('the sample connects by approval in BaseHero on the same emulator', { timeout: 240_000 }, async () => {
  adb('shell', 'pm', 'clear', 'app.basehero');
  adb('shell', 'pm', 'clear', pkg);
  await launch();
  ownerPage = await webview();
  const { email, password, kit } = await signUpOnDev(ownerPage);
  options.password = password;
  try {
    bh(['signin', '--server', 'https://dev-api.basehero.com', '--email', email,
      '--name', 'Test CLI', '--kit', kit], options);
  } catch { throw new Error('host CLI could not sign in with the emulator account kit'); }

  await launch(pkg);
  page = await webview(pkg);
  await page.getByLabel('BaseHero email').fill(email);
  await page.getByRole('button', { name: 'Connect to BaseHero' }).click();
  await launch(); // The approving app must be foregrounded before its WebView is visible.
  await ownerPage.getByText('An app wants to connect.').waitFor({ timeout: 30_000 });
  await ownerPage.getByRole('button', { name: 'Open request' }).click();
  const digitsElement = page.locator('#digits').filter({ hasText: /^\d{3} \d{3}$/ });
  await digitsElement.waitFor({ state: 'attached', timeout: 30_000 });
  const digits = (await digitsElement.textContent()).trim();
  assert.match(digits, /^\d{3} \d{3}$/);
  await ownerPage.getByLabel('Digits shown in the app').fill(digits);
  await ownerPage.getByRole('button', { name: 'Check digits' }).click();
  await ownerPage.getByText('Not verified').waitFor({ timeout: 30_000 });
  assert.equal(await ownerPage.getByLabel('Personal', { exact: true }).isChecked(), true);
  await ownerPage.locator('.approval-requests').screenshot({ path: '/tmp/bh-connect-approval.png' });
  await ownerPage.getByRole('button', { name: 'Connect app' }).click();
  await launch(pkg);
  const status = page.locator('#status');
  await status.filter({ hasText: /connected [a-f0-9]{32} as [a-f0-9]{32}/ }).waitFor({ timeout: 30_000 });
  base = (await status.textContent()).match(/connected ([a-f0-9]{32}) as [a-f0-9]{32}/)[1];
  await page.locator('#email').evaluate(input => input.blur());
  await page.screenshot({ path: '/tmp/bh-connect-sample.png' });
  sampleName = `${email.split('@')[0][0].toUpperCase()}${email.split('@')[0].slice(1)} - BaseHero Sample`;
  const devices = bh(['devices'], options);
  const sample = devices.find(d => d.name === sampleName && d.kind.toLowerCase() === 'app');
  assert(sample, `sample device ${sampleName} is missing`);
  assert.equal(sample.capMicroUsd, 1_000_000);
  sampleDevice = sample.id;
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

test('Hero uses the record', { skip: process.env.BH_SKIP_LIVE_MODEL_TESTS === '1' }, () => {
  const response = bh(['hero', 'ask', '--base', base,
    'List the sample.reading records in this base and read today\'s record. What was the sample reading today?'], options);
  assert(response.steps.some(step => step.tool === 'read' && step.base === base),
    'Hero must read the sample record');
  assert.match(response.text, /42/, 'Hero must answer using the record value');
  console.log('Hero reply:', response.text);
});

test('the app calls a model as its device', { skip: process.env.BH_SKIP_LIVE_MODEL_TESTS === '1' }, async () => {
  await page.getByLabel('Model question').fill('Reply with the word ferry.');
  await page.getByRole('button', { name: 'Ask the model' }).click();
  await page.locator('#status').filter({ hasText: /ferry/i }).waitFor({ timeout: 30_000 });
});

test('a cap of zero stops the sample\'s model calls', async () => {
  bh(['device', 'cap', sampleDevice, '0'], options);
  await page.getByRole('button', { name: 'Ask the model' }).click();
  await page.locator('#status').filter({ hasText: /rate/i }).waitFor({ timeout: 30_000 });
  bh(['device', 'cap', sampleDevice, '1'], options);
});

test('disconnecting in BaseHero erases the sample\'s copy', async () => {
  await launch();
  await ownerPage.getByRole('link', { name: 'Devices' }).click();
  const row = ownerPage.locator(`[data-device-id="${sampleDevice}"]`);
  await row.getByText(sampleName).waitFor({ timeout: 30_000 });
  let confirmed = false;
  ownerPage.once('dialog', async dialog => {
    assert.match(dialog.message(), /Disconnect .*? It erases its copy of your data\./);
    confirmed = true;
    await dialog.accept();
  });
  await row.getByRole('button', { name: 'Disconnect' }).click();
  assert(confirmed, 'the disconnect confirmation was not shown');
  // Revoked devices remain in the device history, so the row does not disappear.
  const deadline = Date.now() + 30_000;
  while (bh(['devices'], options).find(d => d.id === sampleDevice)?.status !== 'revoked') {
    assert(Date.now() < deadline, 'the sample device was not revoked');
  }
  adb('shell', 'am', 'force-stop', pkg);
  await page.context().browser()?.close();
  page = null;
  await launch(pkg);
  page = await webview(pkg);
  await page.locator('#status').filter({ hasText: 'not connected' }).waitFor({ timeout: 30_000 });
});
