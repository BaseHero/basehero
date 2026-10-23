// Camera bridge contract only. The plugin is stubbed here; actual camera pixels
// and native account state are exercised by the Android emulator test.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { browserMatrix, launchBrowser, startUiServer } from './harness.mjs';
import { tauriIpcStub } from './tauri-ipc-stub.mjs';

const ANDROID = 'Mozilla/5.0 (Linux; Android 16; Pixel Fold) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36';
const QR = 'BH1:' + 'Q'.repeat(163);
function host() {
  const ipc = window.__bhIpc;
  const model = window.__scanTest = { permission: 'granted', permissionHold: false, scanHold: false, pendingPermission: [], pendingScan: [], joins: [], status: { state: 'waiting-approval' }, screen: { screen: 'welcome' } };
  ipc.handle('note_binding', () => null);
  ipc.handle('account_screen', () => model.screen);
  ipc.handle('plugin:qr-scan|request_permissions', () => model.permissionHold ? new Promise(resolve => model.pendingPermission.push(resolve)) : { camera: model.permission });
  ipc.handle('plugin:qr-scan|scan', () => new Promise((resolve, reject) => model.pendingScan.push({ resolve, reject })));
  ipc.handle('plugin:qr-scan|cancel', () => null);
  ipc.handle('pairing_join', ({ qrText }) => { model.joins.push(qrText); if (!qrText.startsWith('BH1:')) throw 'pairing code invalid'; return { ticket: 'ticket' }; });
  ipc.handle('pairing_join_status', () => model.status);
}
async function page(browser, origin, native = true, android = true) {
  const view = await browser.newPage({ userAgent: android ? ANDROID : undefined });
  await view.addInitScript(tauriIpcStub);
  await view.addInitScript(host);
  if (!native) await view.addInitScript(() => { delete window.__TAURI_INTERNALS__.metadata; });
  await view.goto(origin + '/');
  if (!android) await view.getByRole('button', { name: 'I already have an account' }).click();
  await view.getByRole('button', { name: 'Use my other device' }).click();
  await view.getByRole('heading', { name: 'Join your account' }).waitFor();
  return view;
}
const calls = (v, name) => v.evaluate(n => window.__bhIpc.calls.filter(c => c.command === n), name);
const settle = v => v.evaluate(() => new Promise(resolve => setTimeout(resolve, 0)));

for (const engine of browserMatrix) describe(`camera bridge in ${engine}`, () => {
  test('permission is never requested before a deliberate Android-native tap', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      assert.equal((await calls(v, 'plugin:qr-scan|request_permissions')).length, 0);
      assert.equal((await calls(v, 'plugin:qr-scan|scan')).length, 0);
      assert.equal(await v.getByRole('button', { name: 'Scan code' }).count(), 1);
      await v.close();
      const web = await page(browser, server.origin, false);
      assert.equal(await web.getByRole('button', { name: 'Scan code' }).count(), 0);
      await web.close();
      const desktop = await page(browser, server.origin, true, false);
      assert.equal(await desktop.getByRole('button', { name: 'Scan code' }).count(), 0);
      await desktop.close();
    } finally { await browser.close(); await server.close(); }
  });
  test('denied camera permission explains paste fallback without account creation and can retry', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      await v.evaluate(() => window.__scanTest.permission = 'denied');
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.getByRole('alert').filter({ hasText: /camera.*denied|camera.*permission/i }).waitFor();
      assert.equal((await calls(v, 'plugin:qr-scan|scan')).length, 0);
      assert.equal((await calls(v, 'account_create')).length, 0);
      assert.equal((await calls(v, 'pairing_join')).length, 0);
      await v.getByLabel('Pairing code').fill(QR);
      await v.getByRole('button', { name: 'Join' }).click();
      await v.getByText(/Approve this device/).waitFor();
      assert.deepEqual(await v.evaluate(() => window.__scanTest.joins), [QR]);
      await v.close();
    } finally { await browser.close(); await server.close(); }
  });
  test('camera read enters the existing join once, never as markup, and closes camera', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.waitForFunction(() => window.__scanTest.pendingScan.length === 1);
      assert.equal((await calls(v, 'plugin:qr-scan|request_permissions')).length, 1);
      const scan = await calls(v, 'plugin:qr-scan|scan');
      // The page chooses no camera, format or code: the native adapter is back-camera QR only.
      assert.deepEqual(Object.keys(scan[0].args ?? {}), []);
      await v.evaluate(() => document.querySelector('#pair-scan button').click());
      assert.equal((await calls(v, 'plugin:qr-scan|scan')).length, 1);
      await v.evaluate(code => window.__scanTest.pendingScan[0].resolve({ content: code }), QR);
      await v.getByText(/Approve this device/).waitFor();
      assert.deepEqual(await v.evaluate(() => window.__scanTest.joins), [QR]);
      assert.equal((await calls(v, 'account_create')).length, 0);
      assert.equal((await calls(v, 'plugin:qr-scan|cancel')).length, 1);
      await v.close();
    } finally { await browser.close(); await server.close(); }
  });
  test('cancel, invalid read and stale permission/camera callback keep paste usable', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.waitForFunction(() => window.__scanTest.pendingScan.length === 1);
      await v.getByRole('button', { name: 'Cancel scan' }).click();
      await v.evaluate(code => window.__scanTest.pendingScan[0].resolve({ content: code }), QR);
      await settle(v);
      assert.equal((await calls(v, 'pairing_join')).length, 0);
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.waitForFunction(() => window.__scanTest.pendingScan.length === 2);
      await v.evaluate(() => window.__scanTest.pendingScan[1].resolve({ content: '<script>hello</script>' }));
      await v.getByRole('alert').filter({ hasText: /isn.t a BaseHero pairing code/ }).waitFor();
      assert.equal(await v.locator('main script').count(), 0, 'no scanned markup inserted');
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.waitForFunction(() => window.__scanTest.pendingScan.length === 3);
      await v.getByRole('button', { name: 'Cancel scan' }).click();
      await v.getByLabel('Pairing code').fill(QR);
      await v.getByRole('button', { name: 'Join' }).click();
      await v.getByText(/Approve this device/).waitFor();
      await v.evaluate(code => window.__scanTest.pendingScan[2].resolve({ content: code }), QR);
      await settle(v);
      assert.equal((await calls(v, 'pairing_join')).length, 2, 'invalid read and paste only');
      await v.close();
    } finally { await browser.close(); await server.close(); }
  });
  test('the transient ready screen after joining is device-neutral with no disconnected footer', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      await v.getByLabel('Pairing code').fill(QR);
      await v.getByRole('button', { name: 'Join' }).click();
      await v.evaluate(() => { window.__scanTest.screen = { screen: 'ready' }; window.__scanTest.status = { state: 'ready' }; });
      await v.waitForFunction(() => document.querySelector('main h1')?.textContent === 'Opening your note');
      assert.match(await v.locator('main').textContent(), /ready on this device/);
      assert.doesNotMatch(await v.locator('main').textContent(), /this Mac/);
      assert.equal(await v.locator('footer').textContent(), '');
      await v.close();
    } finally { await browser.close(); await server.close(); }
  });
  test('closed screen before permission returns never opens camera', async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const v = await page(browser, server.origin);
      await v.evaluate(() => window.__scanTest.permissionHold = true);
      await v.getByRole('button', { name: 'Scan code' }).click();
      await v.waitForFunction(() => window.__scanTest.pendingPermission.length === 1);
      await v.evaluate(() => { document.querySelector('main').replaceChildren(); window.__scanTest.pendingPermission[0]({ camera: 'granted' }); });
      await settle(v);
      assert.equal((await calls(v, 'plugin:qr-scan|scan')).length, 0);
      assert.equal((await calls(v, 'pairing_join')).length, 0);
      await v.close();
    } finally { await browser.close(); await server.close(); }
  });
});
