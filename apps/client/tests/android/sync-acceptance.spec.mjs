// Actual app/Android Keystore acceptance. No fake account, JS sync status,
// decoded scan injection, production debug endpoint, or Client::offline on Android.
// Shared-Rust tests own the protocol matrix; these cases cover the native bridge,
// camera enrollment, OS connectivity, package update and real fold lifecycle.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { connect } from 'node:net';
import { createInterface } from 'node:readline';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { assertSettledFold, editorTapPoint, imeShown, foldViewportScript, settledFold, verifiedPinPrompt } from './fold-state.mjs';
import { scenarioNames, verifyReceipts } from './sync-live.mjs';

const root = process.env.SYNC_RUN;
const shots = process.env.SCAN_SCREENSHOTS;
const serial = process.env.ANDROID_SERIAL;
assert(root && shots && /^emulator-\d+$/.test(serial ?? ''));
const identity = JSON.parse(readFileSync(path.join(root, 'identity.json')));
// Live: the deployed hardware-attested service (run-sync.sh run with SYNC_LIVE_ENDPOINT).
const live = process.env.SYNC_LIVE === '1';
const matrix = {};
let session, fingers;
const sleep = ms => new Promise(r => setTimeout(r, ms));
function own() {
  const fields = readFileSync(`/proc/${process.env.SCAN_EMU_PID}/stat`, 'utf8').split(') ').at(-1).split(' ');
  assert.equal(fields[19], process.env.SCAN_EMU_BIRTH, 'emulator birth changed');
  assert.notEqual(fields[0], 'Z');
  const name = execFileSync('adb', ['-s', serial, 'emu', 'avd', 'name'], { encoding: 'utf8', timeout: 5000 }).split(/\r?\n/)[0];
  assert.equal(name, process.env.SCAN_AVD_NAME, 'foreign AVD occupies serial');
}
function adb(...args) {
  own();
  return execFileSync('adb', ['-s', serial, ...args], { encoding: 'utf8', timeout: 30_000, maxBuffer: 32 * 1024 * 1024 });
}
function bytes(...args) {
  own();
  return execFileSync('adb', ['-s', serial, ...args], { timeout: 30_000, maxBuffer: 64 * 1024 * 1024 });
}
function peer(op, args = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(process.env.SYNC_PEER_SOCKET);
    socket.setTimeout(310_000, () => socket.destroy(Error(`peer ${op} timeout`)));
    socket.on('error', reject);
    socket.on('connect', () => socket.write(JSON.stringify({ op, ...args }) + '\n'));
    createInterface({ input: socket }).once('line', line => {
      const value = JSON.parse(line); value.error ? reject(Error(value.error)) : resolve(value.ok);
    });
  });
}
async function call(method, suffix, body) {
  const response = await fetch('http://127.0.0.1:4445' + suffix, { method,
    headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000) });
  const json = await response.json();
  assert(response.ok, `${method} ${suffix}: ${JSON.stringify(json)}`);
  return json.value;
}
const run = script => call('POST', `/session/${session}/execute/sync`, { script, args: [] });
async function until(action, label, timeout = 120_000) {
  let last;
  for (const end = Date.now() + timeout; Date.now() < end; await sleep(250)) {
    last = await action(); if (last) return last;
  }
  throw Error(`timeout: ${label}; last=${JSON.stringify(last)}`);
}
// Rendered text is what a reader and the keyboard see. Another device's caret
// and label are drawn outside the editable, so it equals the document exactly.
const stateScript = `const e=document.querySelector('.ProseMirror'),s=window.getSelection();
  const rendered=e?[...e.childNodes].map(n=>n.textContent):[];
  return {paragraphs:e?.editor?[...e.editor.state.doc.content.content].map(n=>n.textContent):[],
    rendered,
    bold:[...e?.querySelectorAll('strong,b')??[]].map(b=>b.textContent),
    title:document.querySelector('nav[aria-label="Notes"] [aria-current=true]')?.textContent,
    local:document.querySelector('footer [data-status]')?.dataset.status,
    sync:document.querySelector('footer .cloud')?.dataset.sync,
    syncText:document.querySelector('footer .cloud')?.textContent,
    selection:s?.toString(),anchor:s?.anchorOffset,head:s?.focusOffset,
    anchorText:s?.anchorNode?.textContent,headText:s?.focusNode?.textContent,
    camera:document.documentElement.classList.contains('pair-camera-active')};`;
const state = async () => {
  const s = await run(stateScript);
  assert.deepEqual(s.rendered, s.paragraphs, 'rendered Android note text differs from its document');
  return s;
};
// Where the remote caret is drawn: the paragraph text position whose caret
// box its 2 px line stands on. Not a hit test: the format bubble may cover it.
const remoteCaret = () => run(`const w=document.querySelector('.bh-remote-cursor');
  if(!w) return null;
  const view=document.querySelector('.ProseMirror').editor.view,b=w.getBoundingClientRect();
  let at=null;
  view.state.doc.forEach((p,start,block)=>{
    for(let offset=0;!at&&offset<=p.content.size;offset++){const c=view.coordsAtPos(start+1+offset,-1);
      if(Math.abs(c.left-b.left)<1.5&&Math.abs(c.bottom-b.bottom)<1.5)at={block,offset,text:p.textContent};}
  });
  return at&&{label:w.dataset.label??null,drawn:w.querySelector('.bh-remote-label')?.textContent??null,...at};`);
// Native, OPENED: tap the start of a note paragraph and wait for the keyboard.
async function showKeyboard(index, text) {
  const s = { posture: adb('shell', 'cmd', 'device_state', 'state'), display: adb('shell', 'dumpsys', 'display'),
    window: adb('shell', 'dumpsys', 'window', '-a'), activities: adb('shell', 'dumpsys', 'activity', 'activities'),
    ime: adb('shell', 'dumpsys', 'input_method') };
  const geometry = assertSettledFold(s, 'OPENED', false);
  const web = await run(foldViewportScript);
  const target = await run(`const e=document.querySelector('.ProseMirror'),p=e?.querySelectorAll(':scope > p')[${index}];
    const r=document.createRange();r.selectNodeContents(p);const b=r.getClientRects()[0],pane=e.closest('.note-pane').getBoundingClientRect();
    const x=b.left+Math.min(8,b.width/2),y=(b.top+b.bottom)/2;
    return {x,y,dpr:devicePixelRatio,width:innerWidth,height:innerHeight,scale:visualViewport.scale,
      top:visualViewport.offsetTop,left:visualViewport.offsetLeft,page:performance.timeOrigin,
      paragraph:p.textContent,hit:p.contains(document.elementFromPoint(x,y)),
      inside:x>Math.max(pane.left,0)&&x<Math.min(pane.right,innerWidth)&&y>Math.max(pane.top,0)&&y<Math.min(pane.bottom,innerHeight)};`);
  adb('shell', 'input', 'tap', ...editorTapPoint(target, geometry, web.page, text).map(String));
  await until(async () => imeShown(adb('shell', 'dumpsys', 'input_method')), 'keyboard shown after editor tap', 10_000);
}
// The shown Gboard key with this description, located from the IME window.
function keyboardKey(description) {
  adb('shell', 'uiautomator', 'dump', '--windows', '/sdcard/bh-sync-ime.xml');
  const node = [...adb('shell', 'cat', '/sdcard/bh-sync-ime.xml').matchAll(/<node\b[^>]*>/g)].map(([n]) => n)
    .find(n => n.includes('package="com.google.android.inputmethod.latin"') && n.includes(`content-desc="${description}"`));
  assert(node, `keyboard key ${description} not found`);
  const [x1, y1, x2, y2] = node.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/).slice(1).map(Number);
  return [String((x1 + x2) >> 1), String((y1 + y2) >> 1)];
}
async function foldBarrier(label, posture, pid) {
  const dir = path.join(root, label); mkdirSync(dir, { recursive: true });
  let index = 0, unlocked = false;
  return settledFold({ posture,
    native: async () => {
      const s = { posture: adb('shell', 'cmd', 'device_state', 'state'),
        display: adb('shell', 'dumpsys', 'display'), window: adb('shell', 'dumpsys', 'window', '-a'),
        ime: adb('shell', 'dumpsys', 'input_method'),
        activities: adb('shell', 'dumpsys', 'activity', 'activities'), pid: adb('shell', 'pidof', 'app.basehero.client').trim() };
      assert.equal(s.pid, pid, 'fold replaced app process');
      if (!unlocked && /mShowingLockscreen=true\b/.test(s.window) && /mCurrentFocus=Window\{[^\n}]*NotificationShade\}/.test(s.window)) {
        adb('shell', 'uiautomator', 'dump', '/sdcard/bh-sync-keyguard.xml');
        const xml = adb('shell', 'cat', '/sdcard/bh-sync-keyguard.xml');
        writeFileSync(path.join(dir, 'keyguard.xml'), xml);
        if (verifiedPinPrompt(s.window, xml)) {
          // Only the observed system PIN entry receives the disposable AVD PIN.
          // Re-read focus immediately before typing; never guess an app destination.
          assert(verifiedPinPrompt(adb('shell', 'dumpsys', 'window'), xml));
          adb('shell', 'input', 'text', '1234'); adb('shell', 'input', 'keyevent', '66'); unlocked = true;
        }
      }
      return s;
    },
    web: () => run(foldViewportScript), wait: () => sleep(500),
    record: s => writeFileSync(path.join(dir, `${String(index++).padStart(2, '0')}.json`), JSON.stringify(s, null, 2)),
  });
}
async function shot(name, settled) {
  // Like the continuity suite, select the Fold's active physical display.
  // Default screencap can capture the black, switched-off inner display.
  const displays = [...adb('shell', 'dumpsys', 'display').matchAll(/uniqueId="local:(\d+)", (\d+) x (\d+)/g)]
    .map(([, display, w, h]) => ({ display, area: w * h })).sort((a, b) => b.area - a.area);
  const display = settled ? { display: settled.geometry.physical } : adb('shell', 'cmd', 'device_state', 'state').includes('CLOSED') ? displays[1] : displays[0];
  assert(display, 'active physical display not identified');
  const b = bytes('exec-out', 'screencap', '-d', display.display, '-p');
  const offset = b.indexOf(Buffer.from([137,80,78,71,13,10,26,10]));
  assert(offset >= 0, 'screencap has no PNG');
  writeFileSync(path.join(shots, `${name}.png`), b.subarray(offset));
  if (settled) {
    const png = b.subarray(offset);
    const capture = { argv: ['adb', '-s', serial, 'exec-out', 'screencap', '-d', display.display, '-p'],
      time: new Date().toISOString(), width: png.readUInt32BE(16), height: png.readUInt32BE(20), bytes: png.length, settled };
    writeFileSync(path.join(root, `${name}-capture.json`), JSON.stringify(capture, null, 2));
    assert.equal(capture.width, settled.geometry.width, 'capture width differs from settled display');
    assert.equal(capture.height, settled.geometry.height, 'capture height differs from settled display');
  }
}
async function observe() {
  // Observe real callbacks without replacing inputs, results or delivery.
  await run(`window.syncAcks=[];window.syncViews=[];
    window.addEventListener('sync://status',e=>window.syncViews.push(e.detail));
    const stringify=JSON.stringify;
    JSON.stringify=(m,...args)=>{
      if(m?.cmd==='note_commit'){
        for(const phase of ['callback','error']){
          const callback=window.__TAURI_INTERNALS__.callbacks.get(m[phase]);
          window.__TAURI_INTERNALS__.callbacks.set(m[phase],result=>{
            window.syncAcks.push({phase,result,time:Date.now()});return callback(result);
          });
        }
      }
      return stringify(m,...args);
    };return true;`);
}
async function connectWebview() {
  await until(async () => { try { return (await fetch('http://127.0.0.1:4445/status')).ok; } catch { return false; } }, 'WebDriver status', 60_000);
  session = (await call('POST', '/session', { capabilities: {} })).sessionId;
  await observe();
}
async function rows() {
  await run(`delete window.syncRows;delete window.syncRowsError;
    window.__TAURI_INTERNALS__.invoke('note_list').then(r=>window.syncRows=r,e=>window.syncRowsError=String(e));return true;`);
  return until(async () => {
    const r = await run('return {rows:window.syncRows,error:window.syncRowsError};');
    assert(!r.error, r.error); return r.rows;
  }, 'read-only native catalogue');
}
async function saved(title) {
  await until(async () => {
    const s = await state(); return s.local === 'saved' && s.title === title && s;
  }, 'local matching save Ack and catalogue title');
  const r = await rows();
  assert(r.some(x => Buffer.from(x.note).toString('hex') === identity.home && x.title === title));
  const acks = await run('return window.syncAcks;');
  assert(acks.some(a => a.phase === 'callback' && /^[0-9a-f]{32}$/.test(a.result?.requestId)), 'no native note_commit Ack observed');
  return acks.filter(a => a.phase === 'callback').map(a => a.result.requestId);
}
async function titleAppend(text) {
  assert(await run(`const e=document.querySelector('.ProseMirror'),p=e?.querySelector('p');
    e.focus();window.getSelection().collapse(p,p.childNodes.length);
    return document.execCommand('insertText',false,${JSON.stringify(text)});`));
  return (await state()).paragraphs[0];
}
const note = () => peer('note', { window: 'main', note: identity.home });
const plain = paragraphs => paragraphs.map(p => p.replace(/<[^>]*>/g, ''));
async function converge(expected) {
  const n = await until(async () => {
    const n = await note(); return JSON.stringify(plain(n.accepted_paragraphs)) === JSON.stringify(expected) && n;
  }, 'peer exact Accepted text');
  assert.deepEqual(n.paragraphs, n.accepted_paragraphs, 'peer working != Accepted');
  assert.equal(n.digest, n.accepted_digest);
  await until(async () => {
    const s = await state(); return s.sync === 'synced' && JSON.stringify(s.paragraphs) === JSON.stringify(expected) && s;
  }, 'actual Android editor convergence');
  return n;
}
function airplane(enabled) {
  adb('shell', 'cmd', 'connectivity', 'airplane-mode', enabled ? 'enable' : 'disable');
  assert.equal(adb('shell', 'settings', 'get', 'global', 'airplane_mode_on').trim(), enabled ? '1' : '0');
}
async function stopSnapshot(label) {
  const acks = await run('return window.syncAcks ?? [];');
  const views = await run('return window.syncViews ?? [];');
  const before = adb('shell', 'pidof', 'app.basehero.client').trim();
  assert(/^\d+( \d+)*$/.test(before), 'app must be live before force-stop');
  adb('shell', 'am', 'force-stop', 'app.basehero.client');
  assert.equal(adb('shell', 'sh', '-c', '"pidof app.basehero.client || true"').trim(), '');
  session = undefined;
  const dir = path.join(root, label); mkdirSync(dir, { mode: 0o700 });
  const tar = path.join(dir, 'files.tar');
  const accountDirs = adb('shell', 'find', '/data/user/0/app.basehero.client', '-type', 'd', '-name', 'accounts').trim().split('\n');
  assert.equal(accountDirs.length, 1, 'one native account directory required');
  assert(accountDirs[0].startsWith('/data/user/0/app.basehero.client/'));
  writeFileSync(tar, bytes('exec-out', 'tar', '-C', path.dirname(accountDirs[0]), '-cf', '-', 'accounts'), { mode: 0o600 });
  execFileSync('tar', ['-xf', tar, '-C', dir]);
  const snapshot = JSON.parse(execFileSync('python3', ['apps/client/tests/android/sync-state.py', dir], { encoding: 'utf8' }));
  for (const ack of acks.filter(a => a.phase === 'callback')) {
    assert(snapshot.updates.some(u => u.request === ack.result.requestId), 'Ack has no durable local request row');
  }
  writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ ...snapshot, acks, views, stoppedPid: before }, null, 2));
  return snapshot;
}
async function reopen(expected) {
  adb('shell', 'am', 'start', '-n', 'app.basehero.client/.MainActivity');
  await connectWebview();
  await until(async () => JSON.stringify((await state()).paragraphs) === JSON.stringify(expected), 'offline cold reopen exact note');
}
function accepted(snapshot) {
  assert.equal(snapshot.pending, 0);
  const local = snapshot.updates.filter(row => row.packaged);
  assert(local.length > 0, 'no local outbox packages');
  // Received peer updates are in note_updates too, but have no local outbox.
  for (const row of local) {
    assert(row.acked_position > 0, `no append Ack for ${row.request}`);
    assert.equal(row.outcome, 2, `not Accepted: ${row.request}`);
    assert.equal(row.pending, 0);
  }
}
async function scenario(name, body) {
  console.log(`BEGIN ${name}`);
  try { await body(); matrix[name] = 'PASS'; console.log(`PASS ${name}`); }
  catch (error) { matrix[name] = { failed: String(error), stack: error.stack }; throw error; }
  finally { writeFileSync(path.join(root, 'matrix.json'), JSON.stringify(matrix, null, 2)); }
}
let expected = ['Existing peer note'];
let admitted;
try {
  await connectWebview();
  fingers = setInterval(() => { try { adb('emu', 'finger', 'touch', '1'); } catch (e) { console.error(`finger: ${e}`); } }, 1500);
  await scenario('scan_pair_bootstrap', async () => {
    assert.equal(JSON.parse(readFileSync(path.join(root, 'candidate'))).state, 'candidate');
    await peer('approve');
    await until(async () => { const s = await peer('pair-status'); assert.notEqual(s.state, 'failed', JSON.stringify(s)); return s.state === 'ordered'; }, 'native approval ordered');
    await converge(expected);
    const r = await rows(); assert.equal(r.length, 1); assert.equal(Buffer.from(r[0].note).toString('hex'), identity.home);
    await shot('01-joined-existing-note');
    airplane(true); // prevent replay from masking local bootstrap durability
    const s = await stopSnapshot('joined');
    admitted = await peer('admission');
    assert.equal(admitted.account, identity.account);
    assert.equal(admitted.position, 4); assert.equal(admitted.devices.length, 2);
    assert(admitted.devices.includes(s.device)); assert.notEqual(s.device, identity.device);
    assert.equal(s.account[0].head_position, 4);
    const addition = s.account_events.find(e => e.id === 4).bytes;
    assert(s.base_copies.some(c => c.account_event === addition), 'base lacks exact account AddDevice copy');
    await reopen(expected); airplane(false); await converge(expected);
  });
  clearInterval(fingers); fingers = undefined;
  await scenario('live_both_directions', async () => {
    assert(await run(`const e=document.querySelector('.ProseMirror'),t=e.querySelector('p').firstChild;e.focus();
      window.getSelection().setBaseAndExtent(t,9,t,13);return window.getSelection().toString()==='peer';`));
    assert(await run(`document.querySelector('.note-bubble button[aria-label="Bold"]').click();return !!document.querySelector('.ProseMirror strong');`));
    expected[0] = await titleAppend(' / Android live'); await saved(expected[0]);
    const n = await converge(expected); assert(n.accepted_paragraphs[0].includes('<bold>peer</bold>'), 'native peer missing bold mark');
    await peer('save', { window: 'main', note: identity.home, text: 'Peer live incoming' });
    expected.push('Peer live incoming'); await converge(expected);
    assert.deepEqual((await state()).bold, ['peer']); await shot('02-live-incoming');
    airplane(true); const s = await stopSnapshot('live'); accepted(s);
    await reopen(expected); assert.deepEqual((await state()).bold, ['peer']); airplane(false); await converge(expected);
  });
  await scenario('presence_both_directions', async () => {
    const model = adb('shell', 'getprop', 'ro.product.model').trim();
    assert(model, 'no Android model label');
    // The peer joins presence first with its own caret; otherwise this
    // device's client correctly sends nothing to an empty roster.
    const joining = await peer('relative', { window: 'main', note: identity.home,
      paragraph: 0, offset: 0 });
    await peer('select', { window: 'main', note: identity.home,
      anchor: joining.hex, head: joining.hex, label: 'Peer' });
    // Android -> peer: the editor's own selection reaches the peer.
    assert(await run(`const e=document.querySelector('.ProseMirror'),t=e.querySelector('p').firstChild;e.focus();
      window.getSelection().setBaseAndExtent(t,0,t,4);return window.getSelection().toString().length===4;`));
    const seen = await until(async () => {
      const entries = (await peer('remote-presence')).entries;
      const entry = entries.find(e => e.note === identity.home && e.label === model);
      return entry && entries.length === 1 ? entry : null;
    }, 'peer sees the Android caret');
    assert(Number.isInteger(seen.colour) && seen.colour >= 0 && seen.colour <= 5,
      `Android caret colour: ${JSON.stringify(seen.colour)}`);
    // Peer -> Android: a caret and its label appear at the reported text.
    const first = await peer('relative', { window: 'main', note: identity.home,
      paragraph: 0, offset: 2 });
    await peer('select', { window: 'main', note: identity.home,
      anchor: first.hex, head: first.hex, label: 'Peer' });
    const atFirst = await until(async () => {
      const caret = await remoteCaret();
      return caret?.label === 'Peer' && caret.offset === 2 ? caret : null;
    }, 'Android remote Peer caret');
    assert.equal(atFirst.drawn, 'Peer');
    // A tap on the idle tab shows the name again; capture it while shown.
    assert(await run(`const c=document.querySelector('.bh-remote-cursor');
      if(!c)return false;c.dispatchEvent(new MouseEvent('click',{bubbles:true}));return true;`));
    await until(async () => (await run(
      `return document.querySelector('.bh-remote-cursor')?.hasAttribute('data-collapsed')??null`)) === false,
    'remote label shown again');
    await shot('06-presence-remote-caret');
    const second = await peer('relative', { window: 'main', note: identity.home,
      paragraph: 0, offset: 12 });
    await peer('select', { window: 'main', note: identity.home,
      anchor: second.hex, head: second.hex, label: 'Peer' });
    const atSecond = await until(async () => {
      const caret = await remoteCaret();
      return caret?.offset === 12 ? caret : null;
    }, 'Android remote Peer caret moved');
    await shot('06b-presence-remote-caret-moved');
    // Typing through the caret with the real keyboard keeps the keyboard up.
    // With the caret right before this device's caret, Gboard's double-space
    // period once edited inside the drawn label and hid the keyboard.
    const through = await peer('relative', { window: 'main', note: identity.home,
      paragraph: 1, offset: expected[1].length, assoc: 'before' });
    await peer('select', { window: 'main', note: identity.home,
      anchor: through.hex, head: through.hex, label: 'Peer' });
    await until(async () => {
      const caret = await remoteCaret();
      return caret?.offset === expected[1].length && caret.text === expected[1] ? caret : null;
    }, 'Android remote Peer caret at the end of a paragraph');
    await showKeyboard(1, expected[1]);
    assert(await run(`const e=document.querySelector('.ProseMirror'),t=e.querySelectorAll(':scope > p')[1].lastChild;
      window.getSelection().collapse(t,t.length);return document.activeElement===e;`));
    const space = keyboardKey('Space');
    for (const press of [1, 2]) {
      adb('shell', 'input', 'tap', ...space);
      await sleep(400);
      assert(imeShown(adb('shell', 'dumpsys', 'input_method')), `keyboard hidden by space ${press} at the remote caret`);
    }
    const typed = await run(`const e=document.querySelector('.ProseMirror'),s=window.getSelection();
      return {focused:document.activeElement===e,inside:e.contains(s.focusNode),
        text:e.querySelectorAll(':scope > p')[1].textContent};`);
    assert(typed.focused && typed.inside, `editing ended at the remote caret: ${JSON.stringify(typed)}`);
    assert(typed.text !== expected[1] && typed.text.startsWith(expected[1]), `spaces not typed: ${JSON.stringify(typed)}`);
    await shot('06c-presence-typed-through-caret');
    expected[1] = (await state()).paragraphs[1]; await converge(expected);
    // A caret on an empty middle line, made with Enter as a person makes one,
    // shows on that line both ways (not at the end of the note).
    adb('shell', 'input', 'keyevent', 'KEYCODE_ENTER'); adb('shell', 'input', 'keyevent', 'KEYCODE_ENTER');
    adb('shell', 'input', 'text', 'after');
    expected = await until(async () => {
      const p = (await state()).paragraphs;
      return p.length === 4 && p[1] === expected[1] && p[2] === '' && p[3] === 'after' && p;
    }, 'empty middle line made with Enter');
    await converge(expected);
    assert(await run(`const e=document.querySelector('.ProseMirror');
      window.getSelection().collapse(e.querySelectorAll(':scope > p')[2],0);return document.activeElement===e;`));
    const emptyLine = await peer('relative', { window: 'main', note: identity.home, paragraph: 2, offset: 0 });
    await until(async () => (await peer('remote-presence')).entries.find(e =>
      e.note === identity.home && e.label === model && e.head === emptyLine.hex), 'peer sees the Android caret on the empty line');
    await peer('select', { window: 'main', note: identity.home,
      anchor: emptyLine.hex, head: emptyLine.hex, label: 'Peer' });
    const onEmpty = await until(async () => {
      const caret = await remoteCaret();
      return caret?.block === 2 && caret.text === '' ? caret : null;
    }, 'Android draws the Peer caret on the empty line');
    await shot('06d-presence-empty-line');
    assert.match(adb('shell', 'dumpsys', 'window'), /mCurrentFocus=Window\{[^\n}]*app\.basehero\.client\/app\.basehero\.client\.MainActivity\}/);
    assert(imeShown(adb('shell', 'dumpsys', 'input_method')));
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
    await until(async () => !imeShown(adb('shell', 'dumpsys', 'input_method')), 'keyboard hidden by Back', 5000);
    await peer('clear');
    await until(async () => (await remoteCaret()) === null, 'Android remote Peer caret cleared');
    writeFileSync(path.join(root, 'presence.json'), JSON.stringify({ model, seen, atFirst, atSecond, onEmpty }, null, 2));
  });
  await scenario('airplane_mode_offline_then_reconnect', async () => {
    airplane(true);
    // This is a real route-loss requirement, not a settings-only claim.
    await until(async () => (await state()).sync === 'waiting-network', 'actual airplane-mode connection loss', 60_000);
    expected[0] = await titleAppend(' / Android offline'); const requests = await saved(expected[0]);
    await peer('save', { window: 'main', note: identity.home, text: 'Peer while Android offline' });
    await shot('03-saved-offline');
    const s = await stopSnapshot('offline'); assert(s.pending > 0);
    assert(requests.some(r => s.updates.some(u => u.request === r && u.pending === 1 && u.acked_position === null)), 'no Acked-local / unacked-remote work');
    assert(!plain((await note()).accepted_paragraphs)[0].includes('Android offline'));
    await reopen(expected); // airplane remains enabled before and during reopen
    airplane(false); expected.push('Peer while Android offline'); await converge(expected);
  });
  await scenario('update_with_unsynced_work', async () => {
    airplane(true);
    await until(async () => (await state()).sync === 'waiting-network', 'disconnected before update');
    expected[0] = await titleAppend(' / Before update'); await saved(expected[0]);
    const before = await stopSnapshot('before-update'); assert(before.pending > 0);
    adb('install', '-r', process.env.SYNC_UPDATE_APK);
    assert.match(adb('shell', 'dumpsys', 'package', 'app.basehero.client'), /versionCode=1001\b/);
    assert.equal(adb('shell', 'settings', 'get', 'global', 'airplane_mode_on').trim(), '1');
    await reopen(expected); await shot('04-update-same-note-offline');
    const after = await stopSnapshot('after-update-offline');
    assert.deepEqual(after.identity, before.identity); assert.equal(after.file, before.file);
    assert.deepEqual(after.updates, before.updates); assert.equal(after.pending, before.pending);
    await reopen(expected); airplane(false); await converge(expected);
    assert.deepEqual(await peer('admission'), admitted, 'update changed admission');
    airplane(true); const settled = await stopSnapshot('after-update-accepted'); accepted(settled);
    await reopen(expected); airplane(false); await converge(expected);
  });
  await scenario('fold_while_incoming_edit', async () => {
    assert(!(await state()).camera, 'camera still active during fold');
    expected[0] = await titleAppend(' / F'); await saved(expected[0]); await converge(expected);
    assert(await run(`const e=document.querySelector('.ProseMirror'),t=e.querySelectorAll('p')[1].firstChild;e.focus();
      window.getSelection().setBaseAndExtent(t,0,t,4);return window.getSelection().toString()==='Peer';`));
    // Establish native widget focus once, before the baseline/transition.
    // DOM e.focus()/Range alone leave document.hasFocus() false on Android.
    const focusDir = path.join(root, 'native-focus'); mkdirSync(focusDir);
    const pid = adb('shell', 'pidof', 'app.basehero.client').trim();
    const nativeFocus = async label => {
      const s = { posture: adb('shell', 'cmd', 'device_state', 'state'),
        display: adb('shell', 'dumpsys', 'display'), window: adb('shell', 'dumpsys', 'window', '-a'),
        activities: adb('shell', 'dumpsys', 'activity', 'activities'),
        ime: adb('shell', 'dumpsys', 'input_method'), pid: adb('shell', 'pidof', 'app.basehero.client').trim() };
      assert.equal(s.pid, pid);
      s.geometry = assertSettledFold(s, 'OPENED', false);
      s.web = await run(foldViewportScript);
      writeFileSync(path.join(focusDir, `${label}.json`), JSON.stringify(s, null, 2));
      return s;
    };
    const untapped = await nativeFocus('before-tap');
    const target = await run(`const e=document.querySelector('.ProseMirror'),p=e?.querySelectorAll(':scope > p')[1];
      const r=document.createRange();r.selectNodeContents(p);const b=r.getClientRects()[0],pane=e.closest('.note-pane').getBoundingClientRect();
      const x=b.left+Math.min(8,b.width/2),y=(b.top+b.bottom)/2;
      return {x,y,dpr:devicePixelRatio,width:innerWidth,height:innerHeight,scale:visualViewport.scale,
        top:visualViewport.offsetTop,left:visualViewport.offsetLeft,page:performance.timeOrigin,
        paragraph:p.textContent,hit:p.contains(document.elementFromPoint(x,y)),
        inside:x>Math.max(pane.left,0)&&x<Math.min(pane.right,innerWidth)&&y>Math.max(pane.top,0)&&y<Math.min(pane.bottom,innerHeight)};`);
    writeFileSync(path.join(focusDir, 'target.json'), JSON.stringify(target, null, 2));
    const current = await nativeFocus('immediately-before-tap');
    assert.equal(current.web.page, untapped.web.page);
    const point = editorTapPoint(target, current.geometry, current.web.page, expected[1]);
    const tap = ['shell', 'input', 'tap', ...point.map(String)];
    writeFileSync(path.join(focusDir, 'tap-argv.json'), JSON.stringify(['adb', '-s', serial, ...tap]));
    adb(...tap);
    // Observe IME arrival; Back is permitted only while it is confirmed shown.
    let tapped;
    for (let i = 0; i < 10; i++) {
      await sleep(500); tapped = await nativeFocus(`after-tap-${i}`);
      assert.equal(tapped.web.page, untapped.web.page);
      if (imeShown(tapped.ime)) break;
    }
    if (imeShown(tapped.ime)) {
      const ime = adb('shell', 'dumpsys', 'input_method');
      writeFileSync(path.join(focusDir, 'before-back-ime.txt'), ime);
      assert(imeShown(ime));
      assert.match(adb('shell', 'dumpsys', 'window'), /mCurrentFocus=Window\{[^\n}]*app\.basehero\.client\/app\.basehero\.client\.MainActivity\}/);
      adb('shell', 'input', 'keyevent', 'KEYCODE_BACK');
      await until(async () => !imeShown(adb('shell', 'dumpsys', 'input_method')), 'IME hidden after confirmed-shown Back', 5000);
    }
    assert(await run(`const e=document.querySelector('.ProseMirror'),t=e.querySelectorAll('p')[1].firstChild;e.focus();
      window.getSelection().setBaseAndExtent(t,0,t,4);return window.getSelection().toString()==='Peer';`));
    const prepared = await nativeFocus('range-restored');
    const remoteAt = await peer('relative', { window: 'main', note: identity.home,
      paragraph: 0, offset: 9 });
    await peer('select', { window: 'main', note: identity.home,
      anchor: remoteAt.hex, head: remoteAt.hex, label: 'Peer' });
    await until(async () => {
      const caret = await remoteCaret();
      return caret?.label === 'Peer' && caret.offset === 9 ? caret : null;
    }, 'Android remote Peer caret before the fold');
    assert.equal(prepared.web.page, untapped.web.page);
    assert(prepared.web.focused, 'native tap did not establish document focus');
    const before = await state();
    const opened = await foldBarrier('fold-before', 'OPENED', pid);
    adb('emu', 'fold');
    await until(async () => adb('shell', 'cmd', 'device_state', 'state').includes('CLOSED'), 'real CLOSED device posture');
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'); adb('shell', 'wm', 'dismiss-keyguard');
    const outer = await foldBarrier('fold-outer', 'CLOSED', pid);
    assert.notEqual(outer.web.width, opened.web.width, 'no WebView reflow');
    assert.equal(outer.web.page, opened.web.page, 'WebView replaced');
    // Send only after the outer editor is live: arrival must be observed folded,
    // not merely queued in background during the OS posture transition.
    await peer('save', { window: 'main', note: identity.home, text: 'Peer during fold' });
    expected.push('Peer during fold'); await converge(expected);
    const folded = await state(), incoming = await foldBarrier('fold-incoming', 'CLOSED', pid);
    for (const key of ['selection', 'anchor', 'head', 'anchorText', 'headText']) assert.equal(folded[key], before[key], `fold selection ${key}`);
    assert.deepEqual(folded.bold, before.bold);
    const foldedRemote = await remoteCaret();
    assert.equal(foldedRemote?.label, 'Peer', 'fold lost the remote Peer caret');
    assert.equal(foldedRemote?.offset, 9, 'fold moved the remote Peer caret');
    assert(await run(`const c=document.querySelector('.bh-remote-cursor');
      if(!c)return false;c.dispatchEvent(new MouseEvent('click',{bubbles:true}));return true;`));
    await until(async () => (await run(
      `return document.querySelector('.bh-remote-cursor')?.hasAttribute('data-collapsed')??null`)) === false,
    'folded remote label shown again');
    await shot('05-folded-incoming', incoming);
    await shot('05c-folded-remote-caret', incoming);
    // Continue actual Android input while folded, in a non-title paragraph.
    const oldAcks = await run('return window.syncAcks.length;');
    assert(await run(`const e=document.querySelector('.ProseMirror'),p=e.querySelectorAll('p')[1];
      e.focus();window.getSelection().collapse(p,p.childNodes.length);return true;`));
    adb('shell', 'input', 'text', '%sFolded');
    expected[1] += ' Folded';
    await until(async () => (await run('return window.syncAcks;')).slice(oldAcks).some(a =>
      a.phase === 'callback' && /^[0-9a-f]{32}$/.test(a.result?.requestId)), 'new native Ack while folded');
    await saved(expected[0]); await converge(expected);
    const continued = await foldBarrier('fold-continued', 'CLOSED', pid);
    await shot('05b-folded-continued', continued);
    adb('emu', 'unfold');
    await until(async () => adb('shell', 'cmd', 'device_state', 'state').includes('OPENED'), 'real OPENED device posture');
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'); adb('shell', 'wm', 'dismiss-keyguard');
    const unfolded = await foldBarrier('fold-unfolded', 'OPENED', pid);
    assert.equal(unfolded.web.width, opened.web.width); assert.equal(unfolded.web.page, opened.web.page);
    const unfoldedRemote = await remoteCaret();
    assert.equal(unfoldedRemote?.offset, 9, 'unfold moved the remote Peer caret');
    await converge(expected); expected[0] = await titleAppend(' / U'); await saved(expected[0]); await converge(expected);
    writeFileSync(path.join(root, 'fold-observations.json'), JSON.stringify({ before, folded, pid, opened, outer, incoming, continued, unfolded }, null, 2));
    airplane(true); accepted(await stopSnapshot('fold')); await reopen(expected); assert.deepEqual((await state()).bold, before.bold);
    airplane(false); await converge(expected);
  });
  if (live) await scenario('receipts_verify', async () => {
    airplane(true); const s = await stopSnapshot('receipts');
    const checked = await verifyReceipts(s.progress, (receipt, row) => peer('verify-receipt', { receipt, log: row.log_id }));
    assert(checked.some(c => c.log_kind === 1 && c.log_id === identity.base), 'no verified home base receipt');
    writeFileSync(path.join(root, 'receipts.json'), JSON.stringify(checked, null, 2));
    await reopen(expected); airplane(false); await converge(expected);
  });
  if (!live) await scenario('integrity_stop_shown', async () => {
    airplane(true); const before = await stopSnapshot('before-fork');
    const progress = before.progress.find(p => p.log_kind === 1 && p.log_id === identity.base);
    assert(progress.receipt && progress.stopped_reason === null);
    execFileSync('bash', ['scripts/local-stack.sh', 'stop-part', 'edge'], { stdio: 'inherit' });
    const forged = 'ab'.repeat(32);
    const rewrite = execFileSync('node', ['tests/local-sync/storage-fixture.mjs', process.env.LOCAL_STACK_DIR,
      JSON.stringify({ op: 'rewriteHead', log: '01' + identity.base, args: [forged] })], { encoding: 'utf8' });
    writeFileSync(path.join(root, 'fork-rewrite.json'), rewrite);
    const rewritten = JSON.parse(rewrite);
    assert.deepEqual(rewritten.before, { position: progress.position, hash: progress.head_hash });
    assert.deepEqual(rewritten.after, { position: progress.position, hash: forged });
    execFileSync('bash', ['scripts/local-stack.sh', 'start-part', 'edge'], { stdio: 'inherit' });
    await peer('save', { window: 'main', note: identity.home, text: 'After forged head' });
    await until(async () => (await peer('status')).view?.state === 'stopped', 'native peer authenticated-history stop');
    const frames = readFileSync(path.join(root, 'peer/frames.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const conflict = frames.findLast(f => f.in === 'events' && f.commitments?.length);
    assert.equal(conflict.commitments[0].position, progress.position + 1);
    assert.equal(conflict.commitments[0].previous, forged);
    assert.notEqual(forged, progress.head_hash);
    const earlier = await peer('verify-receipt', { receipt: progress.receipt });
    const later = await peer('verify-receipt', { receipt: conflict.receipt });
    assert.deepEqual(earlier, { position: progress.position, hash: progress.head_hash });
    assert.equal(later.position, progress.position + 1);
    assert.equal(later.hash, conflict.commitments.at(-1).hash);
    writeFileSync(path.join(root, 'authenticated-contradiction.json'), JSON.stringify({ earlier, later, forged, conflict }, null, 2));
    await reopen(expected); airplane(false);
    await until(async () => (await state()).sync === 'stopped', 'native Android stopped history');
    assert.deepEqual((await state()).paragraphs, expected); await shot('06-history-stopped');
    airplane(true); const after = await stopSnapshot('after-fork');
    const stopped = after.progress.find(p => p.log_kind === 1 && p.log_id === identity.base);
    assert.notEqual(stopped.stopped_reason, null);
    assert.equal(stopped.position, progress.position); assert.equal(stopped.head_hash, progress.head_hash);
    await reopen(expected); await until(async () => (await state()).sync === 'stopped', 'durable stop across offline reopen');
  });
} catch (error) {
  console.error(error.stack);
  // One bounded discriminating evidence collection, not a retry of the case.
  try {
    // Native evidence must not depend on the WebView answering: an OS task
    // obscuring the app can suspend exactly the JS callback being diagnosed.
    await shot('failure');
    writeFileSync(path.join(root, 'failure-window.log'), adb('shell', 'dumpsys', 'window', '-a'));
    writeFileSync(path.join(root, 'failure-activities.log'), adb('shell', 'dumpsys', 'activity', 'activities'));
    writeFileSync(path.join(root, 'connectivity.log'), adb('shell', 'dumpsys', 'connectivity'));
    writeFileSync(path.join(root, 'failure-native.json'), JSON.stringify({
      peer: await peer('status'), admission: await peer('admission'),
      note: await peer('note', { window: 'main', note: identity.home }),
      presence: await peer('remote-presence'),
    }, null, 2));
    if (session) writeFileSync(path.join(root, 'failure-ui.json'), JSON.stringify({ state: await state(), main: await run('return document.querySelector("main")?.textContent;') }, null, 2));
  } catch (diagnostic) { console.error(`diagnostic: ${diagnostic}`); }
  process.exitCode = 1;
} finally {
  if (fingers) clearInterval(fingers);
  if (session) await call('DELETE', `/session/${session}`).catch(e => console.error(`session cleanup: ${e}`));
  for (const name of scenarioNames(live)) matrix[name] ??= 'NOT RUN (earlier prerequisite failed)';
  writeFileSync(path.join(root, 'matrix.json'), JSON.stringify(matrix, null, 2));
}
