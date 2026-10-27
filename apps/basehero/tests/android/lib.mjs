import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

// Only the disposable BaseHero emulator is ever a target of these tests.
const serial = 'emulator-5580';
const app = 'app.basehero';
const { chromium } = createRequire(new URL('../../package.json', import.meta.url))('@playwright/test');
export function createAdb(run = execFileSync) {
  return (...args) => {
    // Validate before *every* command, including fold, WebView forwarding and
    // cleanup: the port may have been taken by another AVD since launch().
    const name = run('adb', ['-s', serial, 'emu', 'avd', 'name'], { encoding: 'utf8' })
      .trim().split(/\r?\n/)[0];
    assert.equal(name, 'bh-fold-36', 'refusing another AVD on port 5580');
    return run('adb', ['-s', serial, ...args], { encoding: 'utf8' }).trim();
  };
}
export const adb = createAdb();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function launch() {
  adb('shell', 'am', 'start', '-W', '-n', `${app}/.MainActivity`);
  const deadline = Date.now() + 30_000;
  while (!adb('shell', 'pidof', app)) {
    assert(Date.now() < deadline, `${app} did not start`);
    await pause(200);
  }
}

export async function webview() {
  const pid = adb('shell', 'pidof', app).split(/\s+/)[0];
  assert.match(pid, /^\d+$/, `${app} is not running`);
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
