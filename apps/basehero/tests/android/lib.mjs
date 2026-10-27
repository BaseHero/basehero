import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';

// Only the disposable BaseHero emulator is ever a target of these tests.
const serial = 'emulator-5580';
const { chromium } = createRequire(new URL('../../package.json', import.meta.url))('@playwright/test');
export function createAdb(run = execFileSync) {
  return (...args) => {
    // Validate before *every* command, including fold, WebView forwarding and
    // cleanup: the port may have been taken by another AVD since launch().
    const name = run('adb', ['-s', serial, 'shell', 'getprop', 'ro.boot.qemu.avd_name'],
      { encoding: 'utf8', timeout: 10_000 }).trim();
    assert.equal(name, 'bh-fold-36', 'refusing another AVD on port 5580');
    const emulator = run('adb', ['-s', serial, 'shell', 'getprop', 'ro.kernel.qemu'],
      { encoding: 'utf8', timeout: 10_000 }).trim();
    assert.equal(emulator, '1', 'refusing a physical device on port 5580');
    return run('adb', ['-s', serial, ...args], { encoding: 'utf8', timeout: 30_000 }).trim();
  };
}
export const adb = createAdb();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function launch(pkg = 'app.basehero') {
  adb('shell', 'am', 'start', '-W', '-n', `${pkg}/.MainActivity`);
  const deadline = Date.now() + 30_000;
  while (!adb('shell', 'pidof', pkg)) {
    assert(Date.now() < deadline, `${pkg} did not start`);
    await pause(200);
  }
}

export async function webview(pkg = 'app.basehero') {
  const pid = adb('shell', 'pidof', pkg).split(/\s+/)[0];
  assert.match(pid, /^\d+$/, `${pkg} is not running`);
  const port = adb('forward', 'tcp:0', `localabstract:webview_devtools_remote_${pid}`);
  const endpoint = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  process.once('exit', () => {
    try { adb('forward', '--remove', `tcp:${port}`); } catch { /* Emulator already stopped. */ }
  });
  {
    let targets;
    while (true) {
      try {
        targets = await (await fetch(`${endpoint}/json`)).json();
        if (targets.some(t => t.url.startsWith('http://tauri.localhost/') && JSON.parse(t.description || '{}').attached)) break;
      } catch { /* WebView still starting. */ }
      assert(Date.now() < deadline, 'app WebView DevTools did not become ready');
      await pause(200);
    }
    const browser = await chromium.connectOverCDP(endpoint, { noDefaults: true });
    const target = targets.find(t => t.url.startsWith('http://tauri.localhost/') && JSON.parse(t.description || '{}').attached);
    for (const page of browser.contexts().flatMap(c => c.pages())) {
      const session = await page.context().newCDPSession(page);
      const { targetInfo } = await session.send('Target.getTargetInfo');
      await session.detach();
      if (targetInfo.targetId === target.id) {
        await page.waitForFunction(() => document.readyState === 'complete' &&
          !!document.querySelector('#app')?.firstElementChild);
        return page;
      }
    }
    await browser.close();
    throw new Error('the attached app WebView was not found');
  }
}

export const fold = () => adb('emu', 'fold');
export const unfold = () => adb('emu', 'unfold');

const cli = resolve(import.meta.dirname, '../../../../target/debug/bh');
export function bh(args, { home, password, hiddenPassword, operatorToken } = {}) {
  // A CLI test has no ambient GitHub/operator credentials and never sees the real
  // home. Only invite gets the dev operator token, and neither its value nor
  // subprocess stderr is logged.
  const scratch = home ? null : mkdtempSync(join(tmpdir(), 'bh-cli-'));
  const dir = home ?? scratch;
  const env = { PATH: process.env.PATH, HOME: dir, XDG_CONFIG_HOME: dir, GH_CONFIG_DIR: dir };
  if (password !== undefined) env.BH_PASSWORD = password;
  if (hiddenPassword !== undefined) env.BH_HIDDEN_PASSWORD = hiddenPassword;
  if (operatorToken !== undefined) env.BH_OPERATOR_TOKEN = operatorToken;
  try {
    const result = execFileSync(cli, ['--json', ...args], { encoding: 'utf8', timeout: 60_000,
      env, stdio: ['ignore', 'pipe', 'pipe'] });
    return JSON.parse(result);
  } finally {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  }
}
export function createDevInvite() {
  const token = readFileSync(join(homedir(), '.config/basehero/dev-operator-token'), 'utf8').trim();
  let code;
  try { code = bh(['admin', 'invite', '--server', 'https://dev-api.basehero.com'], { operatorToken: token }).code; }
  catch { throw new Error('could not create a dev invite'); }
  assert.match(code, /^.+$/, 'dev invite must have a code');
  return code;
}
export async function signUpOnDev(page) {
  const code = createDevInvite();
  const email = `android-${Date.now()}-${process.pid}@example.com`;
  const password = `Test-${crypto.randomUUID()}-long`;
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel('Invite code').fill(code);
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Device name').fill('Emulator');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByRole('heading', { name: 'Your recovery kit' }).waitFor({ timeout: 30_000 });
  const kit = (await page.getByTestId('kit').textContent()).trim();
  await page.getByRole('button', { name: "I've saved it" }).click();
  await page.getByRole('heading', { name: 'BaseHero' }).first().waitFor();
  return { email, password, kit };
}

export async function openBase(page) {
  await page.getByRole('link', { name: 'Personal' }).first().click();
  await page.getByRole('button', { name: 'New note' }).waitFor();
}
export async function newNote(page, name = 'Ferry at 9') {
  await openBase(page);
  await page.getByRole('button', { name: 'New note' }).click();
  await page.getByLabel('Name').fill(name);
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await page.getByTestId('tree-row').last().click();
  await page.locator('[aria-label="Note editor"] .ProseMirror[contenteditable="true"]').waitFor();
  return page.locator('[aria-label="Note editor"] .ProseMirror');
}
export async function saved(page) {
  await page.locator('[aria-label="Note editor"] [data-status="saved"]').waitFor({ timeout: 30_000 });
}
export function temporaryHome() { const home = mkdtempSync(join(tmpdir(), 'bh-android-')); return { home, remove: () => rmSync(home, { recursive: true, force: true }) }; }
