// End-to-end update on this runner's disposable emulator only. The saved note
// is local work awaiting sync (cloud sync is not connected in this build).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const [phase, record] = process.argv.slice(2);
const serial = process.env.ANDROID_SERIAL;
if (!/^emulator-\d+$/.test(serial ?? '') || !['before', 'after'].includes(phase) || !record) {
  throw Error('usage: ANDROID_SERIAL=emulator-N node update.spec.mjs before|after record.json');
}
const adb = (...args) => execFileSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const base = 'http://127.0.0.1:4445';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function call(method, path, body) {
  const response = await fetch(base + path, {
    method, headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (!response.ok) throw Error(`${method} ${path}: ${JSON.stringify(json.value ?? json)}`);
  return json.value;
}
const open = async () => (await call('POST', '/session', { capabilities: {} })).sessionId;
const run = (id, script) => call('POST', `/session/${id}/execute/sync`, { script, args: [] });
async function until(id, script, timeout, label) {
  let last;
  for (const end = Date.now() + timeout; Date.now() < end; await sleep(500)) {
    try { last = await run(id, script); if (last?.ok) return last; }
    catch (error) { last = String(error); }
  }
  throw Error(`timed out waiting for ${label}: ${JSON.stringify(last)}`);
}
const keys = () => adb('logcat', '-d', '-s', 'BaseHero:I').match(/EMULATOR FIXTURE device public keys: ([0-9a-f]{64})/g) ?? [];
const snapshot = `
  const note = document.querySelector('section[aria-label="Note"]');
  const text = note?.querySelector('.ProseMirror')?.textContent ?? null;
  const status = document.querySelector('footer [data-status]')?.textContent ?? null;
  return {ok: !!note && !!document.querySelector('nav [aria-current="true"]') &&
    status === 'Saved on this device', text, status,
    title:document.querySelector('nav [aria-current="true"]')?.textContent ?? null,
    cloud: document.querySelector('footer .cloud')?.textContent ?? null};`;
// note_list is read-only. Calling note_binding again rotates the live page token.
const started = `if (!window.__b2Started) {
  window.__b2Started = true;
  window.__TAURI_INTERNALS__.invoke('note_list').then(rows => {
    window.__b2Rows = rows;
  }).catch(error => {window.__b2Error = String(error);});
} return {ok: !!window.__b2Rows, rows:window.__b2Rows ?? null,
  error: window.__b2Error ?? null};`;
let id;
let fingers;
try {
  id = await open();
  if (phase === 'before') {
    await until(id, "return {ok: document.querySelector('main .label')?.textContent === 'WELCOME'};", 60_000, 'welcome');
    const button = await call('POST', `/session/${id}/element`, { using: 'css selector', value: '#bh-emulator-fixture button' });
    await call('POST', `/session/${id}/element/${Object.values(button)[0]}/click`, {});
    fingers = setInterval(() => { try { adb('emu', 'finger', 'touch', '1'); } catch {} }, 1500);
    await until(id, "return {ok: !!document.querySelector('section[aria-label=Note] .ProseMirror')};", 300_000, 'created note');
    clearInterval(fingers); fingers = undefined;
    // Real keyboard input into the editor. Its final title appears in the
    // native catalogue only after the editor's matching save acknowledgement.
    const inserted = await run(id, "const e=document.querySelector('.ProseMirror'); e?.focus(); return {ok: !!e && document.execCommand('insertText', false, 'B2local'), editable:e?.getAttribute('contenteditable')};");
    if (!inserted.ok) throw Error(`editor refused actual text input: ${JSON.stringify(inserted)}`);
    await until(id, "const t=document.querySelector('.ProseMirror')?.textContent; const s=document.querySelector('footer [data-status]'); const title=document.querySelector('nav [aria-current=true]')?.textContent; return {ok:t?.includes('B2local') && title==='B2local' && s?.textContent==='Saved on this device',text:t,status:s?.textContent,title};", 120_000, 'acknowledged local edit in native catalogue');
  } else {
    await until(id, "return {ok: !!document.querySelector('section[aria-label=Note] .ProseMirror')};", 120_000, 'reopened note');
  }
  const state = await until(id, snapshot, 60_000, 'note and local save status');
  const listed=await until(id, started, 30_000, 'read-only native note catalogue');
  const matches=listed.rows.filter(row=>row.title===state.title);
  if(matches.length!==1 || !Array.isArray(matches[0].note) || matches[0].note.length!==32)
    throw Error(`current note absent from native catalogue: ${JSON.stringify({state,listed})}`);
  state.note=matches[0].note;
  if (!state.text?.includes('B2local')) throw Error(`note text missing: ${JSON.stringify(state)}`);
  if (!state.cloud?.includes('Cloud sync not connected')) throw Error(`not pending sync: ${JSON.stringify(state.cloud)}`);
  const fingerprints = keys();
  if (fingerprints.length === 0) throw Error('no fixture device public-key fingerprint logged by native Keystore adapter');
  const fingerprint = fingerprints.at(-1).split(': ').at(-1);
  if (phase === 'before') {
    writeFileSync(record, JSON.stringify({fingerprint, note:state.note, text:state.text}));
  } else {
    const previous = JSON.parse(readFileSync(record, 'utf8'));
    if (fingerprint !== previous.fingerprint) throw Error(`device public keys changed: ${fingerprint} !== ${previous.fingerprint}`);
    if (JSON.stringify(state.note) !== JSON.stringify(previous.note)) throw Error('current note changed after update');
    if (state.text !== previous.text) throw Error(`note text changed: ${JSON.stringify(state.text)} !== ${JSON.stringify(previous.text)}`);
  }
  console.log(`PASS update_preserves_keys_pending_and_current_note ${phase} (emulator evidence): ${JSON.stringify({fingerprint,note:state.note,text:state.text,status:state.status})}`);
} finally {
  if (fingers) clearInterval(fingers);
  if (id) await call('DELETE', `/session/${id}`).catch(() => {});
}
