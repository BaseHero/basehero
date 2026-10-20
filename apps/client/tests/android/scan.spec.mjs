// Real Android camera pixels -> the app's QR decoder -> WebView event -> native join.
// WebDriver is used only to tap/observe the app; no scan result is injected.
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const serial = process.env.ANDROID_SERIAL;
if (!/^emulator-\d+$/.test(serial ?? '')) throw new Error('own emulator serial required');
const mode = process.argv[2];
const shots = process.argv[3];
const candidate = process.argv[4];
if (!['refusal', 'scan'].includes(mode) || !shots) throw new Error('mode and screenshot path required');
const adb = (...args) => execFileSync('adb', ['-s', serial, ...args], { encoding: 'utf8', timeout: 15_000, maxBuffer: 16 * 1024 * 1024 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function call(method, suffix, body) {
  const response = await fetch('http://127.0.0.1:4445' + suffix, {
    method, headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok) throw new Error(`${method} ${suffix}: ${JSON.stringify(json.value)}`);
  return json.value;
}
const id = (await call('POST', '/session', { capabilities: {} })).sessionId;
const run = script => call('POST', `/session/${id}/execute/sync`, { script, args: [] });
async function until(action, description, timeout = 15_000) {
  let last;
  for (const end = Date.now() + timeout; Date.now() < end; await sleep(200)) {
    last = await action();
    if (last) return last;
  }
  throw new Error(`timed out waiting for ${description}: ${JSON.stringify(last)}`);
}
async function shot(name) {
  // adb screencap includes the Android permission dialog and native CameraX
  // overlay, neither of which a WebView-only screenshot necessarily captures.
  const bytes = execFileSync('adb', ['-s', serial, 'exec-out', 'screencap', '-p'], { timeout: 15_000, maxBuffer: 16 * 1024 * 1024 });
  const start = bytes.indexOf(Buffer.from([0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10]));
  if (start < 0) throw new Error('screencap had no PNG signature');
  writeFileSync(path.join(shots, `${name}.png`), bytes.subarray(start));
}
function files() {
  return adb('shell', 'run-as', 'app.basehero.client', 'sh', '-c', 'find files -type f 2>/dev/null | sort').trim().split('\n').filter(Boolean);
}
async function permissionButton() {
  const label = mode === 'refusal' ? /Don.t allow/i : /While using the app|Allow only while using the app/i;
  const bounds = await until(async () => {
    adb('shell', 'uiautomator', 'dump', '/sdcard/bh-camera-dialog.xml');
    const xml = adb('exec-out', 'cat', '/sdcard/bh-camera-dialog.xml');
    for (const item of xml.matchAll(/<node\b[^>]*\/>/g)) {
      if (!label.test(item[0])) continue;
      const found = item[0].match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
      if (found) return found.slice(1).map(Number);
    }
    return null;
  }, 'genuine OS camera permission dialog', 25_000);
  await shot('permission-prompt');
  adb('shell', 'input', 'tap', String(Math.floor((bounds[0] + bounds[2]) / 2)), String(Math.floor((bounds[1] + bounds[3]) / 2)));
}
let failed = false;
let fingers;
try {
  await until(async () => (await run('return document.querySelector("main h1")?.textContent')) === 'Join your account', 'join screen', 60_000);
  // Observe the genuine IPC replies without supplying a permission or scan result.
  // Retain only command names, permission state and refusal reasons, never QR text.
  await run(`
    window.cameraTrace = [];
    const stringify = JSON.stringify;
    const record = event => {
      const entry = { time: Date.now(), ...event };
      window.cameraTrace.push(entry);
      console.info('camera-ipc-trace ' + stringify(entry));
    };
    // Android IPC serializes through JSON; the native postMessage is read-only.
    const observer = (message, ...args) => {
      if (message?.cmd?.startsWith('plugin:qr-scan|')) {
        record({ command: message.cmd, phase: 'invoke', hidden: document.hidden });
        for (const phase of ['callback', 'error']) {
          const id = message[phase];
          const callback = window.__TAURI_INTERNALS__.callbacks.get(id);
          window.__TAURI_INTERNALS__.callbacks.set(id, result => {
            record({ command: message.cmd, phase,
              ...(phase === 'error' ? { reason: typeof result === 'string' ? result : stringify(result) } :
                message.cmd.endsWith('|request_permissions') ? { camera: result?.camera } : {}) });
            return callback(result);
          });
        }
      }
      return stringify(message, ...args);
    };
    JSON.stringify = observer;
    if (JSON.stringify !== observer) throw new Error('IPC observer not installed');
  `);
  const before = files();
  const button = await call('POST', `/session/${id}/element`, { using: 'css selector', value: '#pair-scan button' });
  await call('POST', `/session/${id}/element/${Object.values(button)[0]}/click`, {});
  await permissionButton();
  if (mode === 'refusal') {
    await until(async () => (await run('return document.querySelector("#pair-scan [role=alert]")?.textContent'))?.includes('Camera permission denied'), 'denial and paste fallback');
    await shot('permission-refused');
    const after = files();
    const heading = await run('return document.querySelector("main h1")?.textContent');
    if (heading !== 'Join your account') throw new Error(`camera refusal changed the join screen: ${heading}`);
    if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error(`camera refusal changed app files: before ${JSON.stringify(before)}, after ${JSON.stringify(after)}`);
    if (!(await run('return !!document.querySelector("#pair-code")'))) throw new Error('paste field unavailable after denial');
    console.log('PASS camera_refusal_explained_no_account_created: native screen welcome; app files unchanged (' + before.length + ' files); paste usable');
  } else {
    await until(async () => (await run('return document.documentElement.classList.contains("pair-camera-active")')), 'camera preview opened', 30_000);
    await sleep(1200); // CameraX needs a frame after binding its preview.
    await shot('camera-preview');
    // Joining creates this device's biometric-bound keys. Touch the enrolled
    // emulator finger while a prompt may be showing; touches without one are ignored.
    fingers = setInterval(() => { try { adb('emu', 'finger', 'touch', '1'); } catch {} }, 1500);
    try {
      await until(async () => (await run('return document.querySelector("main")?.textContent'))?.includes('Code accepted. Approve this device'), 'decoded camera QR entered native pairing_join', 75_000);
      await until(async () => existsSync(candidate), 'same session candidate in real showing host', 20_000);
    } catch (error) {
      await shot('camera-diagnostic');
      writeFileSync(path.join(shots, 'camera-diagnostic.log'), adb('logcat', '-d', '-t', '4000').split('\n').filter(x => /camera|qrscan|basehero|chromium|biometric|keystore/i.test(x)).join('\n'));
      throw error;
    }
    await shot('joined-transition');
    console.log('PASS scan_camera_qr_calls_join: camera pixels decoded by the app adapter; existing UI entered native pairing_join; showing host observed candidate in same session');
  }
} catch (error) {
  failed = true;
  console.error('FAIL ' + mode + ': ' + (error?.stack ?? error));
  try {
    console.error('native-camera-diagnostic:', JSON.stringify({
      view: await run('return {hidden:document.hidden, camera:document.documentElement.classList.contains("pair-camera-active"), scan:document.querySelector("#pair-scan")?.textContent, heading:document.querySelector("main h1")?.textContent}'),
      permission: adb('shell', 'dumpsys', 'package', 'app.basehero.client').split('\n').filter(x => x.includes('android.permission.CAMERA')).slice(0, 6),
    }));
    await shot('failure');
  } catch (diagnostic) { console.error('diagnostic unavailable: ' + diagnostic); }
} finally {
  if (fingers) clearInterval(fingers);
  try {
    writeFileSync(path.join(shots, 'camera-ipc-trace.json'), JSON.stringify(await run('return window.cameraTrace'), null, 2) + '\n');
  } catch (diagnostic) { console.error('IPC trace unavailable: ' + diagnostic); }
  await call('DELETE', `/session/${id}`).catch(() => {});
}
if (failed) process.exitCode = 1;
