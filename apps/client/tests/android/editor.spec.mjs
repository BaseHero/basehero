// Emulator-only real WebView editor and SQLite/Keystore force-stop regression.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const [phase, record] = process.argv.slice(2);
const serial = process.env.ANDROID_SERIAL;
if (!/^emulator-\d+$/.test(serial ?? '') || !['before', 'after'].includes(phase) || !record)
  throw Error('usage: ANDROID_SERIAL=emulator-N node editor.spec.mjs before|after record.json');
const adb = (...args) => execFileSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const base = 'http://127.0.0.1:4445';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function call(method, path, body) {
  const response = await fetch(base + path, {method, headers: {'content-type':'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const json = await response.json();
  if (!response.ok) throw Error(`${method} ${path}: ${JSON.stringify(json.value ?? json)}`);
  return json.value;
}
const open = async () => (await call('POST', '/session', {capabilities:{}})).sessionId;
const run = (id, script) => call('POST', `/session/${id}/execute/sync`, {script, args:[]});
async function until(id, script, timeout, label) {
  let last;
  for (const end=Date.now()+timeout; Date.now()<end; await sleep(500)) {
    try {last=await run(id,script);if(last?.ok)return last;}
    catch(error){last=String(error);}
  }
  throw Error(`timed out waiting for ${label}: ${JSON.stringify(last)}`);
}
const state = `const note=document.querySelector('section[aria-label="Note"]');
  const editor=note?.querySelector('.ProseMirror');
  const paragraphs=[...editor?.querySelectorAll(':scope > p')??[]];
  const selected=document.querySelector('nav[aria-label="Notes"] [aria-current="true"]');
  const status=document.querySelector('footer [data-status]');
  return {ok: !!editor && !!selected && !!status, paragraphs:paragraphs.map(p=>p.textContent),
    bold:paragraphs.map(p=>[...p.querySelectorAll('strong,b')].map(b=>({text:b.textContent,
      start:p.textContent.indexOf(b.textContent)}))), title:selected?.textContent, status:status?.textContent,
    statusState:status?.dataset.status,
    cloud:document.querySelector('footer .cloud')?.textContent??null};`;
let id, fingers;
try {
  id=await open();
  if(phase==='before') {
    await until(id,"return {ok: document.querySelector('main .label')?.textContent === 'WELCOME'};",60_000,'welcome');
    const button=await call('POST',`/session/${id}/element`,{using:'css selector',value:'#bh-emulator-fixture button'});
    await call('POST',`/session/${id}/element/${Object.values(button)[0]}/click`,{});
    fingers=setInterval(()=>{try{adb('emu','finger','touch','1');}catch{}},1500);
    await until(id,"return {ok: !!document.querySelector('section[aria-label=Note] .ProseMirror')};",300_000,'created note');
    clearInterval(fingers);fingers=undefined;
    const typed=await run(id,`const e=document.querySelector('.ProseMirror'); e?.focus();
      const first=document.execCommand('insertText',false,'First bold words');
      const selection=window.getSelection(),p=e?.querySelector('p'),t=p?.firstChild;
      if(t?.nodeType===Node.TEXT_NODE){selection.setBaseAndExtent(t,6,t,10);}
      return {ok:first && t?.nodeType===Node.TEXT_NODE && selection?.toString()==='bold',
        first,text:p?.textContent,selection:selection?.toString()};`);
    if(!typed.ok)throw Error(`could not type and select bold: ${JSON.stringify(typed)}`);
    const format=await run(id,`const button=document.querySelector('.note-bubble button[aria-label="Bold"]');
      button?.click(); return {ok: !!document.querySelector('.ProseMirror p strong'),html:document.querySelector('.ProseMirror')?.innerHTML};`);
    if(!format.ok)throw Error(`could not format bold: ${JSON.stringify(format)}`);
    const second=await run(id,`const e=document.querySelector('.ProseMirror');e?.focus();
      const s=window.getSelection(),p=e?.querySelector('p');s?.collapse(p,p.childNodes.length);
      const br=document.execCommand('insertParagraph');
      const text=document.execCommand('insertText',false,'Second plain paragraph');
      return {ok:br && text,html:e?.innerHTML};`);
    if(!second.ok)throw Error(`could not type second paragraph: ${JSON.stringify(second)}`);
    // Final title change is queued after both paragraphs and the mark. The
    // read-only native catalogue observes its durable commit only after prior
    // updates have received their matching acknowledgement from SaveQueue.
    const last=await run(id,`const e=document.querySelector('.ProseMirror'), p=e?.querySelector('p');
      e?.focus();window.getSelection()?.collapse(p,p.childNodes.length);
      return {ok:document.execCommand('insertText',false,'!'),html:e?.innerHTML};`);
    if(!last.ok)throw Error(`could not finish title: ${JSON.stringify(last)}`);
    await until(id,`const s=(()=>{${state}})();return {...s,
      ok:s.ok && s.paragraphs?.join('|')==='First bold words!|Second plain paragraph' &&
      s.bold?.[0]?.[0]?.text==='bold' && s.bold[0][0].start===6 &&
      s.status==='Saved on this device' && s.statusState==='saved' && s.title==='First bold words!'};`,120_000,'native acknowledged catalogue refresh, marks, two paragraphs and local saved state');
  } else {
    await until(id,"return {ok: !!document.querySelector('section[aria-label=Note] .ProseMirror')};",120_000,'reopened note');
  }
  const snapshot=await until(id,`const s=(()=>{${state}})();return {...s,ok:s.ok && s.status==='Saved on this device'};`,60_000,'current note');
  if(snapshot.paragraphs.join('|')!=='First bold words!|Second plain paragraph' ||
    snapshot.bold.length!==2 || snapshot.bold[0].length!==1 || snapshot.bold[1].length!==0 ||
    snapshot.bold[0][0].text!=='bold' || snapshot.bold[0][0].start!==6)
    throw Error(`text or marks incorrect: ${JSON.stringify(snapshot)}`);
  // note_list is read-only; note_binding would rotate the active page token.
  const rows=await until(id,`if(!window.__bhProbeRowsStarted){
    window.__bhProbeRowsStarted=true;
    window.__TAURI_INTERNALS__.invoke('note_list').then(rows=>{window.__bhProbeRows=rows;},
      error=>{window.__bhProbeRowsError=String(error);});
  } return {ok:!!window.__bhProbeRows,rows:window.__bhProbeRows,error:window.__bhProbeRowsError};`,30_000,'read-only native note list');
  if(rows.rows.length!==1 || rows.rows[0].title!==snapshot.title)throw Error(`current note does not match native note list: ${JSON.stringify(rows)}`);
  const note=rows.rows[0].note;
  if(!Array.isArray(note) || note.length!==32)throw Error(`unexpected native note ID: ${JSON.stringify(note)}`);
  if(!snapshot.cloud?.includes('Cloud sync not connected'))throw Error(`unexpected cloud status: ${snapshot.cloud}`);
  if(phase==='before')writeFileSync(record,JSON.stringify({note,paragraphs:snapshot.paragraphs,bold:snapshot.bold}));
  else {
    const prior=JSON.parse(readFileSync(record,'utf8'));
    if(JSON.stringify({note,paragraphs:snapshot.paragraphs,bold:snapshot.bold})!==JSON.stringify(prior))
      throw Error(`reopened note changed: ${JSON.stringify({note,paragraphs:snapshot.paragraphs,bold:snapshot.bold,prior})}`);
  }
  console.log(`PASS type_save_force_stop_reopen ${phase} (emulator evidence): ${JSON.stringify({note,paragraphs:snapshot.paragraphs,bold:snapshot.bold,status:snapshot.status})}`);
} finally {
  if(fingers)clearInterval(fingers);
  if(id)await call('DELETE',`/session/${id}`).catch(()=>{});
}
