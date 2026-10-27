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

test('Block Store save and pm clear fallback; signing out removes the saved entry', { timeout: 180_000 }, async () => {
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  let page = await webview();
  let credentials;
  try {
    credentials = await signUpOnDev(page);
    // Block Store's copy doesn't count as saved, so check the entry itself.
    await page.waitForFunction(async () => {
      const accounts = await window.__TAURI_INTERNALS__.invoke('accounts');
      return window.__TAURI_INTERNALS__.invoke('kit_kept_here', { account: accounts[0].id });
    }, null, { timeout: 30_000 });
  } finally { await page.context().browser()?.close(); }

  // On this google_apis emulator without a Google account the spike found that
  // Block Store works locally, but pm clear erases the entry. Check the fallback.
  adb('shell', 'pm', 'clear', 'app.basehero');
  await launch();
  page = await webview();
  try {
    await signIn(page, credentials);
    await page.getByRole('heading', { name: 'Open this device' }).waitFor({ timeout: 30_000 });
    await page.getByRole('button', { name: 'Use your recovery kit instead' }).click();
    await page.getByLabel('Recovery kit').fill(credentials.kit);
    await page.getByRole('button', { name: 'Use kit' }).click();
    await page.getByRole('link', { name: 'Personal' }).waitFor({ timeout: 30_000 });
    const accounts = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('accounts'));
    assert.equal(accounts.length, 1);
    await page.evaluate(id => window.__TAURI_INTERNALS__.invoke('sign_out', { account: id }), accounts[0].id);
  } finally { await page.context().browser()?.close(); }
  // Sign-out removes even the local saved entry; the next password alone never opens the account.
  adb('shell', 'am', 'force-stop', 'app.basehero');
  await launch();
  page = await webview();
  try {
    await signIn(page, credentials);
    await page.getByRole('heading', { name: 'Open this device' }).waitFor({ timeout: 30_000 });
    assert.equal(await page.getByRole('link', { name: 'Personal' }).count(), 0);
  } finally { await page.context().browser()?.close(); }
});
