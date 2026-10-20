// Emulator fixture account: create a test account through the labelled fixture,
// then force-stop and relaunch the app and reopen it from the Android Keystore.
// Emulator evidence only; run by run-fixture.sh against its own disposable AVD.
//
//   ANDROID_SERIAL=emulator-5554 node fixture-account.spec.mjs [screenshot-prefix]
//
// Plain W3C HTTP over the WebDriver plugin's forwarded loopback port. Every adb
// command names ANDROID_SERIAL; no other device is ever addressed.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const serial = process.env.ANDROID_SERIAL;
if (!/^emulator-\d+$/.test(serial ?? '')) {
  console.error('ANDROID_SERIAL must name the disposable emulator, e.g. emulator-5554');
  process.exit(2);
}
const shots = process.argv[2] ?? 'fixture';
const base = 'http://127.0.0.1:4445';
const activity = 'app.basehero.client/.MainActivity';
const adb = (...args) => execFileSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const t0 = performance.now();
const elapsed = () => Math.round(performance.now() - t0);

async function call(method, path, body) {
  const response = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok) throw new Error(`${method} ${path}: ${JSON.stringify(json?.value ?? json)}`);
  return json.value;
}
async function status() {
  for (let i = 0; i < 600; i += 1) {
    try {
      if ((await fetch(base + '/status')).ok) return;
    } catch {}
    await sleep(100);
  }
  throw new Error('no WebDriver /status after 60 s');
}
const open = async () => (await call('POST', '/session', { capabilities: {} })).sessionId;
const run = (id, script) => call('POST', `/session/${id}/execute/sync`, { script, args: [] });
async function until(id, script, ms, what) {
  let last;
  for (const end = Date.now() + ms; Date.now() < end; await sleep(500)) {
    try {
      last = await run(id, script);
      if (last?.ok) return last;
    } catch (error) {
      last = String(error);
    }
  }
  throw new Error(`timed out waiting for ${what}; last ${JSON.stringify(last)}`);
}
async function screenshot(id, name) {
  const png = Buffer.from(await call('GET', `/session/${id}/screenshot`), 'base64');
  writeFileSync(`${shots}-${name}.png`, png);
}
const SHELL = `
  const fixture = document.getElementById('bh-emulator-fixture');
  const button = fixture?.querySelector('button');
  return {
    label: document.querySelector('main .label')?.textContent ?? null,
    heading: document.querySelector('main h1')?.textContent ?? null,
    note: !!document.querySelector('section[aria-label="Note"]'),
    noteStatus: document.querySelector('.note-pane [role="status"]')?.textContent ?? null,
    fixture: fixture?.textContent ?? null,
    button: button && getComputedStyle(button).display !== 'none' ? button.textContent : null,
  };`;
const welcome = `const s = (() => {${SHELL}})(); return { ...s, ok: s.label === 'WELCOME' };`;
const noteOpen = `const s = (() => {${SHELL}})(); return { ...s, ok: s.note };`;
const creations = () => adb('logcat', '-d', '-s', 'BaseHero:I')
  .split('\n').filter((line) => line.includes('EMULATOR FIXTURE: creating emulator test account')).length;

const failures = [];
const expect = (condition, message) => { if (!condition) failures.push(message); };
let id;
let fingers;
try {
  console.log('--- fixture_account_created_and_reopened_after_force_stop');
  id = await open();
  const first = await until(id, welcome, 60_000, 'the welcome screen');
  expect(first.fixture?.includes('EMULATOR FIXTURE'), `fixture label: ${JSON.stringify(first.fixture)}`);
  expect(first.button === 'Create emulator test account', `fixture button: ${JSON.stringify(first.button)}`);
  await screenshot(id, 'welcome');
  const button = await call('POST', `/session/${id}/element`, { using: 'css selector', value: '#bh-emulator-fixture button' });
  await call('POST', `/session/${id}/element/${Object.values(button)[0]}/click`, {});
  console.log(`  clicked Create emulator test account: ${elapsed()} ms`);
  // Every control-key signature is a per-use strong-biometric prompt. A touch
  // with no prompt showing is ignored by the emulator's fingerprint HAL.
  fingers = setInterval(() => { try { adb('emu', 'finger', 'touch', '1'); } catch {} }, 1500);
  const created = await until(id, noteOpen, 300_000, 'the fixture account note');
  clearInterval(fingers);
  fingers = undefined;
  console.log(`  note open after creation: ${elapsed()} ms`);
  expect(created.fixture?.includes('EMULATOR FIXTURE'), 'fixture label missing after creation');
  await screenshot(id, 'created');
  expect(creations() === 1, `native log: ${creations()} EMULATOR FIXTURE creations, want 1`);
  await call('DELETE', `/session/${id}`);
  id = undefined;

  adb('shell', 'am', 'force-stop', 'app.basehero.client');
  let stopped;
  try { stopped = adb('shell', 'pidof', 'app.basehero.client').trim() === ''; }
  catch { stopped = true; } // pidof exits 1 when no process matches
  expect(stopped, 'app still running after force-stop');
  adb('shell', 'am', 'start', '-n', activity);
  await status();
  id = await open();
  // No finger touches: reopening loads the ordinary keys without control release.
  const reopened = await until(id, noteOpen, 120_000, 'the reopened account note');
  console.log(`  note open after force-stop relaunch: ${elapsed()} ms`);
  expect(reopened.label !== 'WELCOME', 'relaunch showed the welcome screen');
  expect(reopened.fixture?.includes('EMULATOR FIXTURE'), 'fixture label missing after relaunch');
  expect(reopened.button === null, 'fixture button offered with an account open');
  await screenshot(id, 'reopened');
  expect(creations() === 1, `relaunch created another account (${creations()} creations)`);
  console.log(JSON.stringify({ first, created, reopened }, null, 2));
} catch (error) {
  failures.push('probe error: ' + error.message);
} finally {
  if (fingers) clearInterval(fingers);
  if (id) await call('DELETE', `/session/${id}`).catch(() => {});
}
if (failures.length) {
  console.error(`FAIL fixture_account_created_and_reopened_after_force_stop (${failures.length}):`);
  for (const failure of failures) console.error('- ' + failure);
  process.exit(1);
}
console.log('PASS fixture_account_created_and_reopened_after_force_stop (emulator evidence)');
