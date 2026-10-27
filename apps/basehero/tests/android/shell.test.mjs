import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adb, launch, webview, fold, unfold } from './lib.mjs';

test('the app survives folding without restarting', async () => {
  await launch();
  const page = await webview();
  const wide = await page.evaluate(() => innerWidth);
  const boot = await page.evaluate(() => performance.timeOrigin);
  try {
    await fold();
    await page.waitForFunction(w => innerWidth < w, wide, { timeout: 20_000 });
    await unfold();
    await page.waitForFunction(w => innerWidth >= w, wide, { timeout: 20_000 });
    assert.equal(await page.evaluate(() => performance.timeOrigin), boot); // configChanges kept the WebView.
  } finally {
    await unfold();
    await page.context().browser()?.close();
  }
});

test('backup is off', () => {
  const dump = adb('shell', 'dumpsys', 'package', 'app.basehero');
  assert.match(dump, /Package \[app\.basehero\]/, 'the installed app is the expected package');
  assert.doesNotMatch(dump, /pkgFlags=\[[^\]]*ALLOW_BACKUP/);
});

test('hardware Back calls the page hook and resume notifies the live WebView', async () => {
  await launch();
  const page = await webview();
  await page.evaluate(() => {
    window.__bhBack = () => { window.__backCalls = (window.__backCalls ?? 0) + 1; return true; };
    window.addEventListener('bh:resume', () => { window.__resumeCalls = (window.__resumeCalls ?? 0) + 1; });
  });
  try {
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
    await page.waitForFunction(() => window.__backCalls === 1);
    adb('shell', 'input', 'keyevent', 'KEYCODE_HOME');
    await launch();
    await page.waitForFunction(() => (window.__resumeCalls ?? 0) >= 1);
  } finally {
    await page.context().browser()?.close();
  }
});

test('webview attachment does not depend on the placeholder heading', async () => {
  await launch();
  const first = await webview();
  let second;
  try {
    await first.evaluate(() => document.querySelector('#app h1')?.remove());
    second = await webview();
    assert.equal(await second.evaluate(() => document.readyState), 'complete');
    assert.equal(await second.evaluate(() => !!document.querySelector('#app')?.firstElementChild), true);
  } finally {
    await second?.context().browser()?.close();
    await first.context().browser()?.close();
  }
});
