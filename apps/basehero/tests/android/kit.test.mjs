import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, signUpOnDev } from './lib.mjs';

async function signIn(page, { email, password }) {
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Device name').fill('Fold kit check');
  await page.getByRole('button', { name: 'Continue' }).click();
}

test('after pm clear Android sign-in needs approval or the kit', { timeout: 180_000 }, async () => {
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  let page = await webview();
  let credentials;
  try {
    credentials = await signUpOnDev(page);
  } finally { await page.context().browser()?.close(); }

  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  page = await webview();
  try {
    await signIn(page, credentials);
    await page.getByRole('heading', { name: 'Open this device' }).waitFor({ timeout: 30_000 });
    assert.equal(await page.getByRole('link', { name: 'Personal' }).count(), 0);
    await page.getByRole('button', { name: 'Use your recovery kit instead' }).click();
    await page.getByLabel('Recovery kit').fill(credentials.kit);
    await page.getByRole('button', { name: 'Use kit' }).click();
    await page.getByRole('link', { name: 'Personal' }).waitFor({ timeout: 30_000 });
  } finally { await page.context().browser()?.close(); }
});
