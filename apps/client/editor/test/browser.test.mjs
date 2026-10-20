import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { editBound, LAST } from '../src/writer.mjs';
import { positionCost } from '../src/schema.mjs';

const NATIVE=2002468231004600;
const directory=dirname(fileURLToPath(import.meta.url));
const product=spawnSync('npm',['run','build'],{cwd:join(directory,'..'),encoding:'utf8'});
assert.equal(product.status,0,product.stderr);
const build=spawnSync('node',[join(directory,'../node_modules/esbuild/bin/esbuild'),join(directory,'entry.mjs'),'--bundle','--format=esm','--platform=browser','--external:/note-editor.js','--define:localStorage=undefined','--define:sessionStorage=undefined','--outfile='+join(directory,'browser.bundle.js')],{encoding:'utf8'});
assert.equal(build.status,0,build.stderr);
const server=http.createServer(async(req,res)=>{
  if (req.url !== '/harness.js' && req.url !== '/note-editor.js' && req.url !== '/note-editor.css' && req.url !== '/deny-storage.js' && req.url !== '/') {res.writeHead(404).end();return;}
  res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; frame-src 'none'; object-src 'none'");
  res.setHeader('Content-Type',req.url==='/'?'text/html':req.url==='/note-editor.css'?'text/css':'text/javascript');
  res.end(req.url==='/'?'<html><head><link rel="stylesheet" href="/note-editor.css"></head><body><div id="root"></div><script src="/deny-storage.js"></script><script type="module" src="/harness.js"></script></body></html>':
    req.url==='/deny-storage.js'?"window.storageReads=0;for(const key of ['localStorage','sessionStorage'])Object.defineProperty(window,key,{get(){window.storageReads++;throw Error('web storage forbidden')}});":
    await readFile(req.url==='/note-editor.js'?join(directory,'../../ui/note-editor.js'):req.url==='/note-editor.css'?join(directory,'../../ui/note-editor.css'):join(directory,'browser.bundle.js')));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
after(async()=>{await new Promise(resolve=>server.close(resolve));});

// The same ten cases run in Chromium and WebKit. Both engines use the browsers
// pinned by the product flake (PLAYWRIGHT_BROWSERS_PATH), so the versions match
// everywhere the ui check runs. Chromium approximates an Android WebView and
// WebKit the macOS WKWebView; neither is a real device.
for (const [browserName,engine] of [['chromium',chromium],['webkit',webkit]]) {
describe(`EditorView in ${browserName}`,()=>{
let browser;
before(async()=>{
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH) throw Error('PLAYWRIGHT_BROWSERS_PATH is unset; run via scripts/check.sh ui');
  browser=await engine.launch({headless:true});
});
after(async()=>{await browser?.close();});
async function page() {const p=await browser.newPage(); await p.goto(`http://127.0.0.1:${server.address().port}/`); await p.waitForFunction(()=>!!window.harness); return p;}

test('real EditorView types, formats and undoes local edits; incoming is not local',async()=>{
  const p=await page();
  const opened=await p.evaluate(()=>window.harness.open('rich'));
  assert.equal(opened.writes,0);
  assert.equal(await p.evaluate(()=>window.storageReads),0);
  await p.locator('.ProseMirror').click();
  await p.keyboard.type('hello');
  await p.waitForFunction(()=>window.harness.pending()===1);
  for(let i=0;i<12;i++) {
    if(await p.locator('[data-status]').textContent()==='Saved on this Mac') break;
    await p.waitForFunction(()=>window.harness.pending()>0);
    await p.evaluate(()=>window.harness.ack());
  }
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  await p.keyboard.press('ControlOrMeta+a');await p.keyboard.press('ControlOrMeta+b');
  assert.equal(await p.locator('.ProseMirror strong').count()>0,true);
  await p.evaluate(()=>window.harness.incoming('remote'));
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').textContent.includes('remote'));
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>document.querySelector('.ProseMirror strong')===null);
  assert.equal((await p.locator('.ProseMirror').textContent()).includes('remote'),true);
  assert.equal(await p.evaluate(()=>window.storageReads),0);
  await p.close();
});

test('auto-ID swap pauses real binding and preserves unsaved failed request bytes',async()=>{
  const p=await page();
  assert.equal((await p.evaluate(()=>window.harness.open('rich'))).writes,0);
  await p.locator('.ProseMirror').click();await p.keyboard.insertText('pending');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const first=await p.evaluate(()=>window.harness.inFlight());
  const changed=await p.evaluate(()=>window.harness.incomingOwnSuffix());
  assert.equal(changed.before,2002468231004600);assert.notEqual(changed.after,changed.before);
  assert.equal(changed.mode,'readonly');assert.equal(changed.pending,1);
  assert.equal(await p.locator('.ProseMirror').getAttribute('contenteditable'),'false');
  const text=await p.locator('.ProseMirror').textContent();assert.match(text,/pending/);assert.match(text,/same-writer incoming/);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first);
  await p.evaluate(()=>window.harness.reject());
  await p.getByRole('button',{name:'Retry save'}).waitFor({state:'visible'});
  await p.getByRole('button',{name:'Retry save'}).click();
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first);
  assert.equal(await p.locator('.ProseMirror').textContent(),text);
  assert.equal(await p.locator('.ProseMirror').getAttribute('contenteditable'),'false');
  await p.close();
});

test('an edit that does not fit pauses, saves accepted work, then applies on a fresh writer',async()=>{
  for(const action of ['paste','Enter']) {
    const p=await page();
    // Room for typing "z" (20 positions afterwards), not for anything larger.
    const room=editBound(20);
    assert.equal((await p.evaluate(room=>window.harness.open('rich',{writers:[{id:2002468231004600,room},{id:7}]}),room)).mode,'editable');
    await p.locator('.ProseMirror p').first().click();await p.keyboard.press('End');
    await p.keyboard.type('z');
    await p.waitForFunction(()=>window.harness.pending()===1);
    const queued=await p.evaluate(()=>window.harness.inFlight());
    assert.deepEqual(await p.evaluate(()=>window.harness.inFlightStructs()),[[NATIVE,LAST-room,1]]);
    if(action==='paste')await p.evaluate(()=>window.harness.paste('ab'));else await p.keyboard.press('Enter');
    await p.waitForFunction(()=>document.querySelector('.ProseMirror').getAttribute('contenteditable')==='false');
    // Nothing past the writer's capacity was accepted; accepted work drains first.
    assert.equal(await p.evaluate(()=>window.harness.pending()),1);
    assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),queued);
    assert.equal(await p.evaluate(()=>window.harness.opens()),1,'drain before reacquiring');
    assert.equal(await p.locator('.ProseMirror p').first().textContent(),'introz');
    assert.notEqual(await p.evaluate(()=>window.harness.status()),'Saved on this Mac');
    await p.evaluate(()=>window.harness.ack());
    await p.waitForFunction(()=>window.harness.opens()===2);
    assert.deepEqual(await p.evaluate(()=>window.harness.openOptions()),[null,{retire:true}]);
    // The same operation then applies once, on the fresh writer from clock 0.
    await p.waitForFunction(()=>window.harness.pending()===1);
    const structs=await p.evaluate(()=>window.harness.allStructs());
    if(action==='paste') assert.deepEqual(structs,[[7,0,2]]);
    else {assert.ok(structs.every(([client])=>client===7),JSON.stringify(structs));assert.equal(structs[0][1],0);}
    assert.deepEqual(await p.locator('.ProseMirror p').allTextContents(),action==='paste'?['introzab']:['introz','']);
    await p.evaluate(()=>window.harness.ack());
    await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
    assert.equal(await p.locator('.ProseMirror').getAttribute('contenteditable'),'true');
    // Normal editing continues on that lease, with no further rollover.
    await p.locator('.ProseMirror p').first().click();await p.keyboard.press('End');
    await p.keyboard.type('y');
    await p.waitForFunction(()=>window.harness.pending()===1);
    const next=await p.evaluate(()=>window.harness.allStructs());
    assert.equal(next.length,1);assert.equal(next[0][0],7);
    assert.equal(await p.evaluate(()=>window.harness.opens()),2);
    await p.close();
  }
});

test('one clock left: pasting "ab" is never emitted past the last clock',async()=>{
  const p=await page();
  await p.evaluate(()=>window.harness.open('rich',{writers:[{id:2002468231004600,room:1},{id:7}]}));
  await p.locator('.ProseMirror p').first().click();
  await p.evaluate(()=>window.harness.caret('intro'));await p.evaluate(()=>window.harness.paste('ab'));
  const early=await p.evaluate(()=>window.harness.allStructs());
  assert.ok(early.every(([client])=>client!==NATIVE),'overrun emitted: '+JSON.stringify(early));
  await p.waitForFunction(()=>window.harness.opens()===2);
  assert.deepEqual(await p.evaluate(()=>window.harness.openOptions()),[null,{retire:true}]);
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.allStructs()),[[7,0,2]]);
  assert.equal(await p.locator('.ProseMirror p').first().textContent(),'introab');
  await p.close();
});

test('a failed drain keeps the paused writer and its request; Retry completes the rollover',async()=>{
  const p=await page();
  const room=editBound(20);
  await p.evaluate(room=>window.harness.open('rich',{writers:[{id:2002468231004600,room},{id:7}]}),room);
  await p.locator('.ProseMirror p').first().click();await p.keyboard.press('End');
  await p.keyboard.type('z');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const queued=await p.evaluate(()=>window.harness.inFlight());
  await p.evaluate(()=>window.harness.paste('ab'));
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').getAttribute('contenteditable')==='false');
  await p.evaluate(()=>window.harness.reject());
  await p.getByRole('button',{name:'Retry save'}).waitFor({state:'visible'});
  assert.equal(await p.evaluate(()=>window.harness.status()),'Not saved');
  assert.equal(await p.evaluate(()=>window.harness.opens()),1,'no retirement or open after a failed drain');
  await p.getByRole('button',{name:'Retry save'}).click();
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),queued,'same request ID and bytes');
  assert.equal(await p.evaluate(()=>window.harness.opens()),1);
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.opens()===2);
  assert.deepEqual(await p.evaluate(()=>window.harness.openOptions()),[null,{retire:true}]);
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.allStructs()),[[7,0,2]]);
  assert.equal(await p.locator('.ProseMirror p').first().textContent(),'introzab');
  await p.close();
});

test('Undo and Redo restoring more than the writer can take roll over first and keep history',async()=>{
  const p=await page();
  const long='x'.repeat(1000);
  await p.evaluate(()=>window.harness.open('rich',{writers:[{id:2002468231004600},{id:8,room:500},{id:9},{id:10,room:500},{id:11}]}));
  const settle=async()=>{
    await p.waitForFunction(()=>window.harness.pending()===1);
    const structs=await p.evaluate(()=>window.harness.allStructs());
    await p.evaluate(()=>window.harness.ack());
    await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
    await p.waitForTimeout(600); // a separate Undo item
    return structs;
  };
  const key=async combo=>{await p.locator('.ProseMirror h2').click();await p.keyboard.press(combo);};
  await p.locator('.ProseMirror h2').click();
  await p.evaluate(()=>window.harness.caret('headline'));await p.evaluate(long=>window.harness.paste(long),long);
  await settle();
  await key('ControlOrMeta+z');
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline');
  await settle();
  // An ordinary reacquire hands out a reused writer with 500 clocks left.
  assert.equal(await p.evaluate(()=>window.harness.reacquire()),true);
  await key('ControlOrMeta+Shift+z');
  await p.waitForFunction(()=>window.harness.opens()===3);
  assert.deepEqual(await p.evaluate(()=>window.harness.openOptions()),[null,null,{retire:true}]);
  let structs=await settle();
  assert.ok(structs.every(([client])=>client===9),JSON.stringify(structs));
  assert.equal(structs.reduce((n,[,,length])=>n+length,0),1000);
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline'+long);
  await p.locator('.ProseMirror h2').click();
  await p.evaluate(long=>window.harness.select(long),long);await p.keyboard.press('Backspace');
  await settle();
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline');
  assert.equal(await p.evaluate(()=>window.harness.reacquire()),true);
  await key('ControlOrMeta+z');
  await p.waitForFunction(()=>window.harness.opens()===5);
  assert.deepEqual((await p.evaluate(()=>window.harness.openOptions())).slice(3),[null,{retire:true}]);
  structs=await settle();
  assert.ok(structs.every(([client])=>client===11),JSON.stringify(structs));
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline'+long);
  // History is intact: Redo deletes again, Undo restores again on writer 11.
  await key('ControlOrMeta+Shift+z');
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline');
  await settle();
  await key('ControlOrMeta+z');
  assert.equal(await p.evaluate(()=>window.harness.heading()),'headline'+long);
  assert.ok((await settle()).every(([client])=>client===11));
  assert.equal(await p.evaluate(()=>window.harness.opens()),5);
  await p.close();
});

test('the checked bound covers what supported edits actually write',async()=>{
  const p=await page();
  await p.evaluate(()=>window.harness.open('rich'));
  const rows=await p.evaluate(cost=>window.harness.measure(cost),positionCost);
  for(const row of rows) assert.ok(row.ran && row.used<=row.bound,JSON.stringify(row));
  assert.ok(rows.filter(row=>row.used>0).length>=8,JSON.stringify(rows));
  assert.equal(await p.locator('.ProseMirror').getAttribute('contenteditable'),'true');
  await p.close();
});

test('concurrent supported bold marks survive pending typing, failed retry, Undo and reopen',async()=>{
  for(const kind of ['concurrentBold','concurrentBoldReverse']) {
    const p=await page();
    assert.equal((await p.evaluate(kind=>window.harness.open(kind),kind)).mode,'editable');
    const marked=await p.locator('.ProseMirror strong').allTextContents();
    assert.deepEqual(marked,[kind==='concurrentBold'?'ab':'fg']);
    await p.locator('.ProseMirror p').click();await p.keyboard.press('End');await p.keyboard.type('x');
    await p.waitForFunction(()=>window.harness.pending()===1);
    const first=await p.evaluate(()=>window.harness.inFlight());
    const selection=await p.evaluate(()=>{const s=window.getSelection(),r=document.createRange();r.setStart(document.querySelector('.ProseMirror p'),0);r.setEnd(s.anchorNode,s.anchorOffset);return r.toString().length;});
    const incoming=await p.evaluate(()=>window.harness.incoming('bold'));
    assert.equal(incoming.writes,0,'remote marks must not be queued as local bytes');
    assert.deepEqual(await p.evaluate(()=>window.harness.hostDelta()),[{insert:'ab',attributes:{bold:{}}},{insert:'cde'},{insert:'fg',attributes:{bold:{}}},{insert:'h'}],'host must actually merge both bold ranges');
    assert.equal(incoming.mode,'editable','preflight must keep binding attached');
    await p.waitForFunction(()=>[...document.querySelectorAll('.ProseMirror strong')].map(el=>el.textContent).join('')==='abfg',null,{timeout:3000});
    assert.deepEqual(await p.locator('.ProseMirror strong').allTextContents(),['ab','fg']);
    assert.ok((await p.locator('.ProseMirror').textContent()).includes('x'),'pending text remains visible');
    assert.equal(await p.evaluate(()=>{const s=window.getSelection(),r=document.createRange();r.setStart(document.querySelector('.ProseMirror p'),0);r.setEnd(s.anchorNode,s.anchorOffset);return r.toString().length;}),selection,'selection survives remote marks');
    await p.evaluate(()=>window.harness.reject());
    await p.waitForFunction(()=>document.querySelector('[data-status]').textContent.includes('Not saved'));
    await p.getByRole('button',{name:'Retry save'}).click();
    assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first,'same request ID and exact update bytes');
    await p.evaluate(()=>window.harness.ack());
    await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
    await p.locator('.ProseMirror p').click();
    await p.keyboard.press('ControlOrMeta+z');
    await p.waitForFunction(()=>window.harness.pending()>0,null,{timeout:3000});
    assert.deepEqual(await p.locator('.ProseMirror strong').allTextContents(),['ab','fg']);
    assert.equal((await p.locator('.ProseMirror').textContent()).includes('x'),false,'Undo removes only local typing');
    await p.evaluate(()=>window.harness.ack());
    await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
    const before=await p.evaluate(()=>window.harness.hostBytes());
    await p.evaluate(()=>window.harness.open('existing'));
    assert.deepEqual(await p.locator('.ProseMirror strong').allTextContents(),['ab','fg']);
    assert.deepEqual(await p.evaluate(()=>window.harness.hostBytes()),before,'reopen must not change canonical bytes');
    assert.deepEqual(await p.evaluate(()=>window.harness.hostDelta()),[{insert:'ab',attributes:{bold:{}}},{insert:'cde'},{insert:'fg',attributes:{bold:{}}},{insert:'h'}]);
    await p.close();
  }
});

test('unsupported incoming suspends concurrent marks without dropping pending local bytes',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('concurrentBold'));
  await p.evaluate(()=>window.harness.incoming('bold'));
  await p.waitForFunction(()=>[...document.querySelectorAll('.ProseMirror strong')].map(el=>el.textContent).join('')==='abfg');
  await p.locator('.ProseMirror p').click();await p.keyboard.press('End');await p.keyboard.type('x');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const first=await p.evaluate(()=>window.harness.inFlight());
  const blocked=await p.evaluate(()=>window.harness.incoming('unknown'));
  assert.equal(blocked.mode,'readonly');assert.equal(blocked.writes,0);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first);
  assert.equal(await p.locator('.ProseMirror').count(),0);
  await p.evaluate(()=>window.harness.incoming('removeUnknown'));
  await p.waitForFunction(()=>document.querySelector('.ProseMirror')!==null);
  assert.deepEqual(await p.locator('.ProseMirror strong').allTextContents(),['ab','fg']);
  assert.ok((await p.locator('.ProseMirror').textContent()).includes('x'));
  await p.evaluate(()=>window.harness.reject());
  await p.getByRole('button',{name:'Retry save'}).click();
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first);
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  const before=await p.evaluate(()=>window.harness.hostBytes());
  await p.evaluate(()=>window.harness.open('existing'));
  assert.deepEqual(await p.locator('.ProseMirror strong').allTextContents(),['ab','fg']);
  assert.ok((await p.locator('.ProseMirror').textContent()).includes('x'));
  assert.deepEqual(await p.evaluate(()=>window.harness.hostBytes()),before);
  await p.close();
});

test('shipped CSS renders both repeated spaces in editable and inert known text',async()=>{
  const p=await page();
  for (const [kind,selector,mode] of [
    ['spacesUnknown','.note-content .note-paragraph','readonly'],
    ['spaces','.ProseMirror p','editable'],
  ]) {
    const opened=await p.evaluate(kind=>window.harness.open(kind),kind);
    assert.equal(opened.mode,mode);
    assert.equal(opened.writes,0);
    if (mode==='readonly') {
      assert.equal(await p.locator('.ProseMirror').count(),0);
      assert.equal(await p.locator('.note-placeholder').count(),1);
    }
    const widths=await p.locator(selector).evaluate(element=>{
      const walker=document.createTreeWalker(element,NodeFilter.SHOW_TEXT);
      let text;
      while ((text=walker.nextNode()) && !text.textContent.includes('a  b')) {}
      if(!text) throw Error('spaced text not found');
      const start=text.textContent.indexOf('a  b');
      return [1,2].map(offset=>{
        const range=document.createRange();
        range.setStart(text,start+offset);
        range.setEnd(text,start+offset+1);
        return range.getBoundingClientRect().width;
      });
    });
    assert.ok(widths[0]>0,`first space must be visible in ${mode}: ${widths}`);
    assert.ok(widths[1]>0,`second space must be visible in ${mode}: ${widths}`);
  }
  await p.close();
});

test('Undo is a local delta committed by the host and persists after reopen',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('undo');
  for(let i=0;i<24;i++) {
    if(await p.locator('[data-status]').textContent()==='Saved on this Mac') break;
    await p.waitForFunction(()=>window.harness.pending()>0);
    await p.evaluate(()=>window.harness.ack());
  }
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>window.harness.pending()>0,null,{timeout:3000});
  for(let i=0;i<24;i++) {
    if(await p.locator('[data-status]').textContent()==='Saved on this Mac') break;
    await p.waitForFunction(()=>window.harness.pending()>0);
    await p.evaluate(()=>window.harness.ack());
  }
  await p.evaluate(()=>window.harness.open('existing'));
  assert.ok(!(await p.locator('.ProseMirror').textContent()).includes('undo'));
  await p.close();
});

test('atomic host snapshot and subscription deliver an update during open',async()=>{
  const p=await page();
  const result=await p.evaluate(()=>window.harness.open('racing'));
  assert.equal(result.writes,0);
  assert.equal(result.mode,'editable');
  assert.ok((await p.locator('.ProseMirror').textContent()).includes('while opening'));
  await p.close();
});

test('initial unknown node, mark, attr or value is inert and never binds/writes',async()=>{
  const p=await page();
  for(const kind of ['node','mark','attr','value','textAttr','invalidStructure']) {
    const result=await p.evaluate(kind=>window.harness.open(kind),kind);
    assert.equal(result.mode,'readonly'); assert.equal(result.writes,0);
    assert.equal(await p.locator('.ProseMirror').count(),0);
    assert.equal(await p.getByRole('toolbar',{name:'Format',includeHidden:true}).isVisible(),false);
    assert.ok(await p.locator('.note-placeholder').count()>0);
    assert.equal(await p.getByText('Update BaseHero to edit').count(),1);
  }
  await p.close();
});

test('failed commit, typing in flight and stale ack retain unsaved text until matching serial ack',async()=>{
  const p=await page();const opened=await p.evaluate(()=>window.harness.open('empty'));
  assert.equal(opened.writes,0);
  await p.locator('.ProseMirror').click();await p.keyboard.type('a');
  await p.waitForFunction(()=>window.harness.pending()===1);
  await p.keyboard.type('b');
  const original=await p.evaluate(()=>window.harness.inFlight());
  assert.match(original.id,/^[0-9a-f]{32}$/);
  await p.evaluate(()=>window.harness.reject());
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent.includes('Not saved'));
  assert.equal((await p.locator('.ProseMirror').textContent()).includes('ab'),true);
  await p.getByRole('button',{name:'Retry save'}).click();
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),original);
  await p.evaluate(()=>window.harness.ack(-1));
  assert.notEqual(await p.locator('[data-status]').textContent(),'Saved on this Mac');
  await p.evaluate(()=>window.harness.retry());
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.equal(await p.locator('[data-status]').textContent(),'Saved on this Mac');
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  await p.close();
});

test('disposing a note clears local view and late ack cannot reappear',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('secret');
  await p.waitForFunction(()=>window.harness.pending()>0);
  const handedToHost=await p.evaluate(()=>window.harness.inFlight());
  await p.evaluate(()=>window.harness.close());
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),handedToHost,'closing must not corrupt bytes already handed to the host');
  assert.equal(await p.locator('#root').textContent(),'');
  await p.evaluate(()=>window.harness.ack());
  assert.equal(await p.locator('#root').textContent(),'');
  await p.close();
});

test('actual EditorView selection bubble creates rich headings, lists and checklists',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('title');
  const bubble=p.getByRole('toolbar',{name:'Format'});
  await p.keyboard.press('ControlOrMeta+a');
  await bubble.getByRole('button',{name:'Heading'}).click();
  assert.equal(await p.locator('.ProseMirror h2').textContent(),'title');
  await p.locator('.ProseMirror').press('End');await p.locator('.ProseMirror').press('Enter');
  await p.keyboard.type('item');await p.keyboard.press('Shift+Home');
  await bubble.getByRole('button',{name:'List',exact:true}).click();
  assert.ok(await p.locator('.ProseMirror ul').count()>0);
  await bubble.getByRole('button',{name:'Checklist'}).click();
  assert.ok(await p.locator('.ProseMirror ul[data-type="taskList"]').count()>0);
  await p.close();
});

test('supported link editing stays inert in WebView; unsafe URL does not become a mark',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('link me');await p.keyboard.press('ControlOrMeta+a');
  await p.keyboard.press('ControlOrMeta+k');
  await p.getByRole('textbox',{name:'Link URL'}).fill('https://example.org');
  await p.getByRole('button',{name:'Done'}).click();
  const anchor=p.locator('.ProseMirror a');
  assert.equal(await anchor.getAttribute('href'),'https://example.org');
  await anchor.click();
  assert.ok(p.url().startsWith('http://127.0.0.1:'));
  await p.keyboard.press('ControlOrMeta+a');await p.keyboard.press('ControlOrMeta+k');
  await p.getByRole('textbox',{name:'Link URL'}).fill('javascript:alert(1)');
  await p.getByRole('button',{name:'Done'}).click();
  assert.equal(await anchor.getAttribute('href'),'https://example.org');
  await p.close();
});

test('incoming unsupported content freezes before live binding; pending local text remains',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('unsaved');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const result=await p.evaluate(()=>window.harness.incoming('unknown'));
  assert.equal(result.mode,'readonly');assert.equal(await p.locator('.ProseMirror').count(),0);
  assert.ok(result.pending>0);assert.equal(result.writes,0);
  await p.evaluate(()=>window.harness.incoming('removeUnknown'));
  assert.equal(await p.locator('.ProseMirror').count(),1);
  assert.equal((await p.locator('.ProseMirror').textContent()).includes('unsaved'),true);
  await p.close();
});

// Inline code is stored as the inventory's plain `code` key, alone or with other
// marks, whether made by shortcut or input rule, through Undo and reopen.
test('inline code with bold stays a supported plain code mark through Undo and reopen',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.evaluate(()=>window.harness.autoAck());
  await p.locator('.ProseMirror').click();await p.keyboard.type('mark me');
  await p.keyboard.press('ControlOrMeta+a');await p.keyboard.press('ControlOrMeta+e');
  await p.keyboard.press('ControlOrMeta+b');
  // Past Undo's capture interval, so Undo takes back only the second line.
  await p.waitForTimeout(600);
  await p.evaluate(()=>window.harness.caret('mark me'));await p.keyboard.press('Enter');
  // Leave both stored marks, then let the input rule make code on its own.
  await p.keyboard.press('ControlOrMeta+e');await p.keyboard.press('ControlOrMeta+b');
  await p.keyboard.type('`rule` ');
  const settled=()=>p.waitForFunction(()=>window.harness.mode()!=='editable' ||
    document.querySelector('[data-status]').textContent==='Saved on this Mac' && !document.querySelector('.ProseMirror').textContent.includes('`'));
  await settled();
  assert.equal(await p.evaluate(()=>window.harness.mode()),'editable');
  assert.deepEqual(await p.evaluate(()=>window.harness.hostMarks()),[['bold','code'],['code'],[]]);
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>window.harness.hostMarks().length!==3);
  await settled();
  assert.deepEqual((await p.evaluate(()=>window.harness.hostMarks()))[0],["bold","code"]);
  await p.evaluate(()=>window.harness.open('existing'));
  assert.equal(await p.evaluate(()=>window.harness.mode()),'editable');
  assert.equal(await p.locator('.ProseMirror code').count()>=1,true);
  for(const marks of await p.evaluate(()=>window.harness.hostMarks()))
    for(const mark of marks) assert.ok(['bold','code'].includes(mark),`plain inventory key, not ${mark}`);
  await p.close();
});

// The approved editing limit: 1,000,000 ProseMirror positions (UTF-16 units and
// structure), checked before a local edit is accepted. Content is never cut.
const LIMIT=1_000_000;
const rendered=(p,positions)=>p.waitForFunction(n=>document.querySelector('.ProseMirror')?.editor?.state.doc.nodeSize===n,positions);
test('typing up to the size limit is accepted; the next character or emoji is refused with feedback',async()=>{
  const p=await page();
  await p.evaluate(positions=>window.harness.open('sized',{positions}),LIMIT-1);
  await rendered(p,LIMIT-1);
  await p.evaluate(()=>window.harness.autoAck());
  await p.locator('.ProseMirror').focus();await p.evaluate(()=>window.harness.caret('ssss'));
  await p.keyboard.insertText('a');
  await rendered(p,LIMIT);
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  assert.equal(await p.evaluate(()=>window.harness.notice()),'');
  const saved=await p.evaluate(()=>window.harness.hostBytes().length);
  for(const [text,keys] of [['b',false],['\u{1F600}',false],['c',true]]) {
    if(keys) await p.keyboard.type(text);else await p.keyboard.insertText(text);
    await p.waitForFunction(()=>window.harness.notice()!=='');
    assert.match(await p.evaluate(()=>window.harness.notice()),/size limit/);
    assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT);
    // The page shows what the editor holds: no refused character stays on screen.
    await p.waitForFunction(()=>document.querySelector('.ProseMirror p').textContent.startsWith('ssssas'));
  }
  assert.equal(await p.evaluate(()=>window.harness.hostBytes().length),saved,'nothing refused was saved');
  assert.equal(await p.evaluate(()=>window.harness.mode()),'editable');
  // Shrinking is always allowed and clears the explanation.
  await p.keyboard.press('Backspace');
  await p.waitForFunction(()=>window.harness.notice()==='');
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT-1);
  await p.close();
});

test('a paste past the limit is refused whole; one that fits is accepted',async()=>{
  const p=await page();
  await p.evaluate(positions=>window.harness.open('sized',{positions}),LIMIT-10);
  await rendered(p,LIMIT-10);
  await p.evaluate(()=>window.harness.autoAck());
  await p.locator('.ProseMirror').focus();await p.evaluate(()=>window.harness.caret('ssss'));
  await p.evaluate(()=>window.harness.paste('x'.repeat(11)));
  await p.waitForFunction(()=>window.harness.notice()!=='');
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT-10);
  await p.evaluate(()=>window.harness.paste('y'.repeat(10)));
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this Mac');
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT);
  await p.close();
});

test('an over-limit note opens read-only with an explanation and keeps every character',async()=>{
  const p=await page();
  const opened=await p.evaluate(positions=>window.harness.open('sized',{positions}),LIMIT+2);
  await rendered(p,LIMIT+2);
  assert.equal(opened.writes,0);
  // The binding renders the note after open; then it is read-only.
  await p.waitForFunction(()=>window.harness.mode()==='readonly');
  assert.equal(await p.locator('.ProseMirror').getAttribute('contenteditable'),'false');
  const explained=p.locator('.note-large');
  assert.equal(await explained.isVisible(),true);
  assert.match(await explained.textContent(),/^Read-only · Too large to edit\. This note is over about one million characters\./);
  assert.equal(await p.locator('[data-status]').textContent(),'Saved on this Mac');
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT+2);
  await p.locator('.ProseMirror').click();await p.keyboard.insertText('typed');
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT+2);
  assert.equal(await p.evaluate(()=>window.harness.pending()),0);
  // A peer's deletion bringing it within the limit makes it editable again.
  assert.equal((await p.evaluate(()=>window.harness.incomingSized(-2))).mode,'editable');
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').getAttribute('contenteditable')==='true');
  await p.close();
});

test('accepted pending writing still saves after a merge takes the note over the limit',async()=>{
  const p=await page();
  await p.evaluate(positions=>window.harness.open('sized',{positions}),LIMIT-10);
  await rendered(p,LIMIT-10);
  await p.locator('.ProseMirror').focus();await p.evaluate(()=>window.harness.caret('ssss'));
  await p.keyboard.insertText('abc');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const first=await p.evaluate(()=>window.harness.inFlight());
  const merged=await p.evaluate(()=>window.harness.incomingSized(40));
  assert.equal(merged.mode,'readonly');
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').getAttribute('contenteditable')==='false');
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first,'accepted request unchanged');
  await p.evaluate(()=>window.harness.ack());
  await p.evaluate(()=>window.harness.autoAck());
  await p.waitForFunction(()=>/Saved on this Mac/.test(document.querySelector('[data-status]').textContent));
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT-10+3+42);
  assert.ok((await p.evaluate(()=>window.harness.hostDeltaText())).includes('abc'));
  await p.close();
});

test('Undo that could restore past the limit is refused with feedback; history is kept',async()=>{
  const p=await page();
  await p.evaluate(positions=>window.harness.open('sized',{positions}),LIMIT-3);
  await rendered(p,LIMIT-3);
  await p.evaluate(()=>window.harness.autoAck());
  await p.locator('.ProseMirror').focus();await p.evaluate(()=>window.harness.select('ssssssssss'));
  await p.keyboard.press('Backspace');
  await rendered(p,LIMIT-13);
  // A peer's paragraph (10 units + 2) is not in this window's Undo history.
  await p.evaluate(()=>window.harness.incomingSized(10));
  await rendered(p,LIMIT-1);
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>window.harness.notice()!=='');
  assert.match(await p.evaluate(()=>window.harness.notice()),/size limit/);
  assert.equal(await p.evaluate(()=>window.harness.positions()),LIMIT-1);
  // Making room (a separate Undo step) lets the same history apply.
  await p.waitForTimeout(600);
  await p.evaluate(()=>window.harness.select('ssssssssssssssssssss'));
  await p.keyboard.press('Backspace');
  await rendered(p,LIMIT-21);
  await p.waitForTimeout(600);
  await p.keyboard.press('ControlOrMeta+z');
  await rendered(p,LIMIT-1);
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>/size limit/.test(window.harness.notice()));
  await p.close();
});

// Approved pause: at 4 MiB or 512 unsaved chunks, already accepted writing
// (including the paste that crossed) stays; new growth waits for saving.
const BIG=('\u{1F600}'.repeat(900)+'\n').repeat(500); // ~1.8 MB, 901,000 positions
async function fillQueue(p) {
  await p.locator('.ProseMirror').click();await p.keyboard.type('a');
  await p.waitForFunction(()=>window.harness.pending()===1);
  for(let round=0;round<2;round++) {
    await p.evaluate(text=>window.harness.paste(text),BIG);
    await p.evaluate(()=>window.harness.clearAll());
  }
  assert.equal(await p.evaluate(()=>window.harness.notice()),'','below the pause');
}
test('a large paste crossing the unsaved limit is kept; new typing waits until saving catches up',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await fillQueue(p);
  const first=await p.evaluate(()=>window.harness.inFlight());
  await p.evaluate(text=>window.harness.paste(text),BIG);
  await p.waitForFunction(()=>/paused until your writing is saved/.test(window.harness.notice()));
  const crossed=await p.evaluate(()=>window.harness.positions());
  assert.ok(crossed>900_000,'the crossing paste is accepted whole');
  await p.locator('.ProseMirror').focus();
  await p.keyboard.insertText('x');await p.keyboard.press('ControlOrMeta+z');
  assert.equal(await p.evaluate(()=>window.harness.positions()),crossed,'no growth or Undo after the pause');
  assert.equal(await p.evaluate(()=>window.harness.status()),'Saving…');
  // A failed save keeps the same request; Retry resends it unchanged.
  await p.evaluate(()=>window.harness.reject());
  await p.getByRole('button',{name:'Retry save'}).waitFor({state:'visible'});
  assert.equal(await p.evaluate(()=>window.harness.status()),'Not saved');
  await p.getByRole('button',{name:'Retry save'}).click();
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),first,'same ID and bytes');
  await p.evaluate(()=>window.harness.autoAck());
  await p.waitForFunction(()=>window.harness.status()==='Saved on this Mac' && window.harness.notice()==='');
  await p.locator('.ProseMirror').focus();await p.keyboard.insertText('x');
  await p.waitForFunction(n=>window.harness.positions()===n+1,crossed);
  // Undo history was never capped: the crossing paste itself can be undone.
  // How Undo groups these steps depends on timing; each press must apply one.
  for(let i=0;i<6 && await p.evaluate(()=>window.harness.positions())>=1000;i++) {
    const depth=await p.evaluate(()=>window.harness.undoDepth());
    await p.keyboard.press('ControlOrMeta+z');
    await p.waitForFunction(n=>window.harness.undoDepth()<n,depth);
  }
  assert.ok(await p.evaluate(()=>window.harness.positions())<1000);
  assert.equal(await p.evaluate(()=>window.harness.notice()),'');
  await p.close();
});

test('a composition that began before the pause finishes; the next one waits',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await fillQueue(p);
  await p.locator('.ProseMirror').focus();
  await p.locator('.ProseMirror').evaluate(el=>el.dispatchEvent(new CompositionEvent('compositionstart',{bubbles:true})));
  await p.evaluate(()=>window.harness.insertDOM('kana'));
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').textContent.includes('kana'));
  await p.evaluate(text=>window.harness.paste(text),BIG);
  await p.waitForFunction(()=>/paused/.test(window.harness.notice()));
  await p.evaluate(()=>window.harness.insertDOM('-done','kana'));
  await p.locator('.ProseMirror').evaluate(el=>el.dispatchEvent(new CompositionEvent('compositionend',{bubbles:true})));
  // The composition's final DOM read lands in the block it was typed in.
  await p.waitForFunction(()=>window.harness.text().includes('-done'));
  const after=await p.evaluate(()=>window.harness.positions());
  await p.keyboard.insertText('later');
  assert.equal(await p.evaluate(()=>window.harness.positions()),after);
  assert.ok(!(await p.evaluate(()=>window.harness.text())).includes('later'));
  await p.close();
});

test('a held edit whose note changed before its replay says to try again',async()=>{
  const p=await page();
  const room=editBound(20);
  await p.evaluate(room=>window.harness.open('rich',{writers:[{id:2002468231004600,room},{id:7}]}),room);
  await p.locator('.ProseMirror p').first().click();await p.keyboard.press('End');
  await p.keyboard.type('z');
  await p.waitForFunction(()=>window.harness.pending()===1);
  await p.evaluate(()=>window.harness.paste('ab'));
  await p.waitForFunction(()=>document.querySelector('.ProseMirror').getAttribute('contenteditable')==='false');
  await p.evaluate(()=>window.harness.incoming('remote'));
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.opens()===2);
  await p.waitForFunction(()=>/Try it again/.test(window.harness.notice()));
  assert.equal(await p.locator('.ProseMirror p').first().textContent(),'introz');
  assert.equal(await p.evaluate(()=>window.harness.mode()),'editable');
  await p.close();
});

// Per-view drain for navigation, close, Quit and update: finish composition,
// flush the DOM while editable, then hold new input while accepted work saves.
const drained=p=>p.waitForFunction(()=>window.drained!==undefined).then(()=>p.evaluate(()=>window.drained));
test('drain holds edits and Undo, keeps rendering incoming, and waits for the in-flight and later saves',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('a');
  await p.waitForFunction(()=>window.harness.pending()===1);
  await p.keyboard.type('b');
  await p.evaluate(()=>window.harness.drain(5000));
  await p.waitForFunction(()=>window.harness.editable()==='false');
  await p.keyboard.press('ControlOrMeta+z');
  await p.locator('.ProseMirror').press('c');
  assert.ok((await p.evaluate(()=>window.harness.text())).includes('ab'));
  assert.ok(!(await p.evaluate(()=>window.harness.text())).includes('c'));
  await p.evaluate(()=>window.harness.incoming('remote'));
  assert.ok((await p.evaluate(()=>window.harness.text())).includes('remote'));
  assert.equal(await p.evaluate(()=>window.drained),undefined,'the in-flight save is not yet done');
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.equal(await p.evaluate(()=>window.drained),undefined,'the later typing is not yet saved');
  await p.evaluate(()=>window.harness.ack());
  assert.equal(await drained(p),true);
  assert.equal(await p.evaluate(()=>window.harness.editable()),'false','held until resumed');
  await p.evaluate(()=>window.harness.resume());
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true');
  await p.close();
});

test('an update drain says so, and the view names its selection as relative bytes',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('rich'));
  await p.locator('.ProseMirror').click();await p.evaluate(()=>window.harness.select('headline'));
  await p.evaluate(()=>window.harness.drain(1000,'update'));
  assert.equal(await drained(p),true);
  assert.equal(await p.evaluate(()=>window.harness.status()),'Saving before update…');
  const view=await p.evaluate(()=>window.harness.view());
  assert.equal(view.version,1);
  assert.ok(view.anchor.length>0 && view.anchor.length<=1024 && view.head.length<=1024);
  assert.notDeepEqual(view.anchor,view.head);
  assert.ok(Number.isFinite(view.cursorOffset));
  await p.evaluate(()=>window.harness.resume());
  assert.equal(await p.evaluate(()=>window.harness.status()),'Saved on this Mac');
  await p.close();
});

async function peerAt(p,id) {return p.evaluate(id=>window.harness.peerAt(id),id);}
async function macCaret(p,text) {
  const range=await p.evaluate(text=>window.harness.relativeSelection(text),text);
  await p.evaluate(([anchor,head])=>window.harness.remote({type:'remote',id:'mac',label:'Mac',colour:0,anchor,head}),[range.anchor,range.head]);
}

// Test 6a: a remote device's caret is a relative position, so it stays on its
// words while this window types before it and a remote batch arrives around it.
test('remote caret stays on text while both type',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await macCaret(p,'fox');
  await p.waitForFunction(()=>!!window.harness.peerAt('mac'));
  assert.deepEqual(await peerAt(p,'mac'),{before:'The quick brown fox',selection:'fox',label:'Mac',colour:'#1b5fd9'});
  // Local typing before the caret: the words it covers do not move under it.
  await p.locator('.ProseMirror').focus();
  await p.evaluate(()=>window.harness.caretAtStart());
  await p.keyboard.type('Today ');
  await p.waitForFunction(()=>window.harness.peerAt('mac')?.before.startsWith('Today The '));
  await p.waitForFunction(()=>window.harness.peerAt('mac')?.selection==='fox');
  // A remote batch inserts before and after those words.
  await p.evaluate(()=>window.harness.incomingAtText('quick brown',0,'Big '));
  await p.waitForFunction(()=>window.harness.peerAt('mac')?.before.includes('Big quick brown'));
  await p.evaluate(()=>window.harness.incomingAtText('fox',3,' very'));
  await p.waitForFunction(()=>window.harness.peerAt('mac')?.before.endsWith('quick brown fox'));
  assert.deepEqual(await peerAt(p,'mac'),{before:'Today The Big quick brown fox',selection:'fox',label:'Mac',colour:'#1b5fd9'});
  await p.close();
});

// Test 6b: a position naming an item this copy has not received keeps the
// last caret; the batch carrying that item moves it.
test('unresolved position keeps last then moves',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await macCaret(p,'fox');
  await p.waitForFunction(()=>!!window.harness.peerAt('mac'));
  assert.equal((await peerAt(p,'mac')).selection,'fox');
  const future=await p.evaluate(()=>window.harness.futureRelative('future words'));
  await p.evaluate(future=>window.harness.remote({type:'remote',id:'mac',label:'Mac',colour:0,anchor:future.anchor,head:future.head}),future);
  assert.deepEqual(await peerAt(p,'mac'),{before:'The quick brown fox',selection:'fox',label:'Mac',colour:'#1b5fd9'},'the last caret stays while the item is missing');
  await p.evaluate(future=>window.harness.incomingBytes(future.update),future);
  await p.waitForFunction(()=>window.harness.peerAt('mac')?.before.endsWith('future words'));
  const moved=await peerAt(p,'mac');
  assert.equal(moved.selection,'');
  assert.ok(moved.before.endsWith('future words'));
  await p.close();
});

// Test 6c: the approved idle state is the same 2 px caret with only its label
// collapsed to a 6 px colour tab at 3 s. Hovering the tab, or tapping it, shows
// the label again for another 3 s. Playwright's fake clock drives the timer;
// every assertion reads geometry, never wall-clock time.
test('label hides after 3s to a tab',async()=>{
  const p=await browser.newPage();await p.clock.install();
  await p.goto(`http://127.0.0.1:${server.address().port}/`);
  await p.waitForFunction(()=>!!window.harness);
  await p.evaluate(()=>window.harness.open('sentence'));
  const range=await p.evaluate(()=>window.harness.relativeSelection('fox'));
  // The remote message draws synchronously; a locator wait here would advance
  // the fake clock before the 3 s timer starts.
  await p.evaluate(([anchor,head])=>window.harness.remote({type:'remote',id:'mac',label:'Mac',colour:0,anchor,head}),[range.anchor,range.head]);
  const cursor=p.locator('.bh-remote-cursor'),label=p.locator('.bh-remote-label');
  assert.equal(await label.textContent(),'Mac');
  const shown=await p.evaluate(()=>window.harness.caretBox('mac'));
  assert.ok(shown.label.width>6,'the label is full width while the caret moves');
  assert.equal(shown.cursor.width,2,'the caret is a 2 px line');
  // Playwright's own calls advance the fake clock by about a millisecond, so
  // the "before" check aims at 2 s rather than the exact boundary.
  await p.clock.fastForward(2000);
  assert.equal(await p.evaluate(()=>window.harness.caretBox('mac').label.width>6),true,'the label is still full before 3 s');
  await p.clock.fastForward(1000);
  const idle=await p.evaluate(()=>window.harness.caretBox('mac'));
  assert.deepEqual({width:idle.label.width,height:idle.label.height},{width:6,height:6},'the label alone is a 6 px tab at 3 s');
  assert.deepEqual(idle.cursor,shown.cursor,'only the label shrinks: the 2 px caret keeps its size');
  assert.equal(idle.textLeft,shown.textLeft,'collapsing the label moves no text');
  assert.equal(await cursor.getAttribute('data-collapsed'),'','the caret is in its idle state');
  // Hover on the tab shows the name again while the pointer is over it.
  await label.hover();
  assert.equal(await p.evaluate(()=>window.harness.caretBox('mac').label.width>6),true,'hovering the tab shows the label');
  assert.equal(await label.textContent(),'Mac');
  // A Fold tap shows it for another 3 s, then it collapses again.
  await label.click();
  await p.mouse.move(0,0);
  assert.equal(await cursor.getAttribute('data-collapsed'),null,'a tap leaves the label shown');
  assert.equal(await p.evaluate(()=>window.harness.caretBox('mac').label.width>6),true,'the tapped label is full width');
  await p.clock.fastForward(3000);
  assert.equal(await p.evaluate(()=>window.harness.caretBox('mac').label.width),6,'the tap restarts the 3 s hide');
  await p.close();
});

// A window on this same device keeps its integer-position path: the relayed
// caret draws grey and unlabelled beside another device's coloured one.
test('same-device window caret draws alongside a remote caret',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await p.evaluate(()=>window.harness.remote({type:'set',id:'window-2',anchor:5,head:9}));
  assert.equal(await p.locator('.bh-peer-cursor').count(),1);
  assert.equal(await p.locator('.bh-peer-selection').count(),1);
  await macCaret(p,'fox');
  await p.waitForFunction(()=>!!window.harness.peerAt('mac'));
  assert.equal(await p.locator('.bh-peer-cursor').count(),1,'the remote caret does not replace the window caret');
  assert.equal(await p.locator('.bh-remote-cursor').count(),1);
  assert.equal(await p.locator('.bh-remote-label').textContent(),'Mac');
  await p.evaluate(()=>window.harness.remote({type:'remove',id:'window-2'}));
  assert.equal(await p.locator('.bh-peer-cursor').count(),0);
  assert.equal(await p.locator('.bh-remote-cursor').count(),1,'removing the window caret leaves the remote one');
  await p.close();
});

// An approved label is at most 24 characters, with an ellipsis when longer.
test('a long device label shows 24 characters with an ellipsis',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  const long='Pixel 10 Pro Fold folded inner screen';
  const range=await p.evaluate(()=>window.harness.relativeSelection('fox'));
  await p.evaluate(([anchor,head,label])=>window.harness.remote({type:'remote',id:'fold',label,colour:1,anchor,head}),[range.anchor,range.head,long]);
  const shown=await p.locator('.bh-remote-label').textContent();
  assert.equal(Array.from(shown).length,24);
  assert.equal(shown,'Pixel 10 Pro Fold folde…');
  assert.equal(await p.locator('.bh-remote-cursor').getAttribute('data-label'),shown);
  await p.close();
});

// Every view update redraws the carets, so it must leave an unchanged label's
// text alone and measure every peer before writing any marker: a write between
// measures would make the next peer's coordsAtPos flush the layout it caused.
test('a redraw keeps an unchanged label node and measures every peer first',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await macCaret(p,'fox');
  const quick=await p.evaluate(()=>window.harness.relativeSelection('quick'));
  await p.evaluate(([anchor,head])=>window.harness.remote({type:'remote',id:'fold',label:'Fold',colour:1,anchor,head}),[quick.anchor,quick.head]);
  await p.waitForFunction(()=>document.querySelectorAll('.bh-remote-cursor').length===2);
  const drawn=await p.evaluate(()=>{
    const view=document.querySelector('.ProseMirror').editor.view;
    const label=document.querySelector('.bh-remote-cursor[data-peer="mac"] .bh-remote-label');
    const textNode=label.firstChild,order=[];
    for (const marker of document.querySelectorAll('.bh-remote-cursor')) {
      const style=marker.style,set=style.setProperty;
      style.setProperty=function(name,value,priority){if(name==='--peer')order.push('write');return set.call(this,name,value,priority);};
    }
    const coords=view.coordsAtPos.bind(view);
    view.coordsAtPos=(...args)=>{order.push('measure');return coords(...args);};
    view.dispatch(view.state.tr);
    return {sameNode:label.firstChild===textNode,text:label.textContent,order};
  });
  assert.equal(drawn.text,'Mac');
  assert.equal(drawn.sameNode,true,'an unchanged label keeps its text node');
  assert.equal(drawn.order.filter(step=>step==='measure').length,2,'both peers are measured');
  assert.ok(drawn.order.lastIndexOf('measure')<drawn.order.indexOf('write'),`every peer is measured before any marker is written: ${drawn.order.join(',')}`);
  await p.close();
});

// A long press on the label must not start a page text selection, which would
// take the selection out of the editable and could hide the keyboard. The
// label inherits it from the overlay it is drawn in.
test('a remote label takes no page text selection',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await macCaret(p,'fox');
  await p.waitForFunction(()=>!!window.harness.peerAt('mac'));
  const style=await p.evaluate(()=>{
    const label=getComputedStyle(document.querySelector('.bh-remote-label'));
    const overlay=getComputedStyle(document.querySelector('.bh-remote-carets'));
    return {label:label.webkitUserSelect,overlay:overlay.webkitUserSelect,standard:label.userSelect};
  });
  assert.equal(style.label,'none','the label starts no page text selection');
  assert.equal(style.overlay,'none','the overlay does not start one either');
  if (browserName==='chromium') assert.equal(style.standard,'none','the standard property agrees in Chromium');
  await p.close();
});

// An Android keyboard edits the note by offsets in the editable's own text.
// A remote caret drawn inside that text (its "Mac" label) let Gboard's
// double-space period land inside the label, which ended editing and hid
// the keyboard. The caret stays drawn while the editable holds only the
// note's text, before and after typing through it.
test('a remote caret adds no text to the editable note',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('sentence'));
  await p.evaluate(()=>window.harness.autoAck());
  const range=await p.evaluate(()=>window.harness.relativeSelection('The'));
  await p.evaluate(at=>window.harness.remote({type:'remote',id:'mac',label:'Mac',colour:0,anchor:at,head:at}),range.anchor);
  await p.locator('.ProseMirror').focus();
  await p.evaluate(()=>window.harness.caretAtStart());
  const sentence='The quick brown fox jumps over the lazy dog.';
  assert.deepEqual(await peerAt(p,'mac'),{before:'',selection:'',label:'Mac',colour:'#1b5fd9'});
  assert.deepEqual(await p.evaluate(()=>window.harness.editableText()),{all:sentence,before:''});
  await p.keyboard.type('Hi ');
  await p.waitForFunction(()=>window.harness.text().includes('Hi '));
  assert.deepEqual(await p.evaluate(()=>window.harness.editableText()),{all:'Hi '+sentence,before:'Hi '});
  assert.equal((await peerAt(p,'mac')).label,'Mac','the caret is still drawn');
  await p.close();
});

// A caret on an empty line has no text to anchor to. Made by Enter, as a
// person makes one, it shows on that line on the other device, both ways.
test('a caret on an empty line shows on that line',async()=>{
  const cases=[
    ['middle',async p=>{await p.evaluate(()=>window.harness.caret('dog.'));
      await p.keyboard.press('Enter');await p.keyboard.press('Enter');await p.keyboard.type('after');},1,3],
    ['first',async p=>{await p.evaluate(()=>window.harness.caretAtStart());await p.keyboard.press('Enter');},0,2],
    ['last',async p=>{await p.evaluate(()=>window.harness.caret('dog.'));await p.keyboard.press('Enter');},1,2],
  ];
  for (const [where,write,line,blocks] of cases) {
    const fold=await page();await fold.evaluate(()=>window.harness.open('sentence'));
    await fold.evaluate(()=>window.harness.autoAck());
    await fold.locator('.ProseMirror').focus();
    await write(fold);
    await fold.waitForFunction(blocks=>window.harness.hostDeltaText().split('\n').length===blocks,blocks);
    const mac=await page();
    await mac.evaluate(bytes=>window.harness.open('bytes',{bytes,writers:[{id:7}]}),await fold.evaluate(()=>window.harness.hostBytes()));
    // Each device puts its own caret on the empty line; the other draws it.
    for (const [from,to] of [[fold,mac],[mac,fold]]) {
      assert.equal(await from.locator('.ProseMirror > *').count(),blocks,where);
      assert.equal(await from.locator('.ProseMirror > *').nth(line).textContent(),'',where);
      await from.evaluate(line=>{const e=document.querySelector('.ProseMirror').editor;let at=0;
        e.state.doc.forEach((node,offset,index)=>{if(index===line)at=offset+1;});e.commands.setTextSelection(at);},line);
      const {anchor,head}=await from.evaluate(()=>window.harness.view());
      await to.evaluate(([anchor,head])=>window.harness.remote({type:'remote',id:'peer',label:'Peer',colour:0,anchor,head}),[anchor,head]);
      assert.equal(await to.evaluate(()=>window.harness.peerBlock('peer')),line,`${where} empty line, ${from===fold?'Fold to Mac':'Mac to Fold'}`);
    }
    await fold.close();await mac.close();
  }
});

test('drain reads the last DOM change into the note before it stops editing',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').evaluate(el=>{
    el.querySelector('p').append(document.createTextNode('late character'));
    window.harness.drain(2000);
  });
  await p.waitForFunction(()=>window.harness.pending()===1);
  await p.evaluate(()=>window.harness.ack());
  assert.equal(await drained(p),true);
  assert.match(await p.evaluate(()=>window.harness.text()),/late character/);
  await p.close();
});

test('drain waits out a composition, its final DOM read, and one that starts right after',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.evaluate(()=>window.harness.autoAck());
  const compose=(type,text)=>p.locator('.ProseMirror').evaluate((el,[type,text])=>{
    if(text)el.querySelector('p').append(document.createTextNode(text));
    el.dispatchEvent(new CompositionEvent(type,{bubbles:true}));
  },[type,text]);
  await compose('compositionstart');
  await p.evaluate(()=>window.harness.insertDOM('first'));
  await p.evaluate(()=>window.harness.drain(3000));
  await p.waitForTimeout(60);
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true','composition keeps the editor live');
  await compose('compositionend');
  // A second composition begins inside the recheck interval.
  await p.waitForTimeout(5);
  await compose('compositionstart','');
  await p.evaluate(()=>window.harness.insertDOM('-second'));
  await p.waitForTimeout(60);
  assert.equal(await p.evaluate(()=>window.drained),undefined);
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true');
  await compose('compositionend');
  assert.equal(await drained(p),true);
  assert.match(await p.evaluate(()=>window.harness.text()),/first-second/);
  assert.match(await p.evaluate(()=>window.harness.hostDeltaText()),/first-second/);
  await p.close();
});

test('a failed save is retried once unchanged; then the drain fails and still holds',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('a');
  await p.waitForFunction(()=>window.harness.pending()===1);
  const original=await p.evaluate(()=>window.harness.inFlight());
  await p.evaluate(()=>window.harness.drain(5000));
  await p.evaluate(()=>window.harness.reject());
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.deepEqual(await p.evaluate(()=>window.harness.inFlight()),original);
  await p.evaluate(()=>window.harness.reject());
  assert.equal(await drained(p),false);
  assert.equal(await p.evaluate(()=>window.harness.status()),'Not saved');
  assert.equal(await p.evaluate(()=>window.harness.editable()),'false');
  assert.match(await p.evaluate(()=>window.harness.text()),/a/);
  await p.evaluate(()=>window.harness.resume());
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true');
  await p.close();
});

test('a drain that cannot finish by its deadline reports failure; a late ack still saves',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('a');
  await p.waitForFunction(()=>window.harness.pending()===1);
  await p.evaluate(()=>window.harness.drain(200));
  assert.equal(await drained(p),false);
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.status()==='Saved on this Mac');
  await p.close();
});

test('a held editor refuses programmatic local edits but still renders incoming',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('rich'));
  await p.evaluate(()=>window.harness.drain(1000));
  assert.equal(await drained(p),true);
  await p.evaluate(()=>document.querySelector('.ProseMirror').editor.commands.insertContent('typed while held'));
  await p.evaluate(()=>window.harness.incoming('remote'));
  assert.ok(!(await p.evaluate(()=>window.harness.text())).includes('typed while held'));
  assert.ok((await p.evaluate(()=>window.harness.text())).includes('remote'));
  assert.equal(await p.evaluate(()=>window.harness.pending()),0,'nothing to save');
  // An editor held from the start (created after its page claimed drained).
  await p.evaluate(()=>window.harness.open('rich'));
  await p.evaluate(()=>window.harness.hold('update'));
  assert.equal(await p.evaluate(()=>window.harness.editable()),'false');
  assert.equal(await p.evaluate(()=>window.harness.status()),'Saving before update…');
  await p.evaluate(()=>document.querySelector('.ProseMirror').editor.commands.insertContent('x'));
  assert.equal(await p.evaluate(()=>window.harness.pending()),0);
  await p.evaluate(()=>window.harness.resume());
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true');
  await p.close();
});

test('a held editor stays held across an unsupported rebuild; resume keeps a writer pause',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.evaluate(()=>window.harness.drain(1000));
  assert.equal(await drained(p),true);
  await p.evaluate(()=>window.harness.incoming('unknown'));
  assert.equal(await p.locator('.ProseMirror').count(),0);
  await p.evaluate(()=>window.harness.incoming('removeUnknown'));
  assert.equal(await p.evaluate(()=>window.harness.editable()),'false');
  await p.evaluate(()=>window.harness.resume());
  assert.equal(await p.evaluate(()=>window.harness.editable()),'true');
  await p.close();
  // An unsafe writer change pauses authoring; resuming a drain must not lift
  // it. (This fresh writer is spent, so the pause cannot end on its own.)
  const q=await page();
  await q.evaluate(()=>window.harness.open('empty',{writers:[{id:2002468231004600},{id:7,room:0}]}));
  await q.evaluate(()=>window.harness.drain(1000));
  assert.equal(await drained(q),true);
  await q.evaluate(()=>window.harness.incomingOwnSuffix());
  await q.waitForFunction(()=>window.harness.opens()===2);
  await q.evaluate(()=>window.harness.resume());
  assert.equal(await q.evaluate(()=>window.harness.editable()),'false');
  assert.equal(await q.evaluate(()=>window.harness.mode()),'readonly');
  await q.close();
});

// The reading position is where the cursor sat in the visible area, not an
// absolute scrollTop: an update's layout or a peer's text above moves that.
async function restartView(p,select,offset) {
  await p.evaluate(()=>window.harness.open('lines'));
  await p.waitForFunction(()=>!!document.querySelector('.ProseMirror')?.editor);
  await p.locator('.ProseMirror').focus();
  await p.evaluate(text=>window.harness.select(text),select);
  const placed=await p.evaluate(offset=>window.harness.placeHead(offset),offset);
  const top=await p.evaluate(()=>window.harness.area().scrollTop);
  await p.evaluate(()=>window.harness.drain(1000));
  assert.equal(await drained(p),true);
  const view=await p.evaluate(()=>window.harness.view());
  assert.ok(Math.abs(view.cursorOffset-placed)<1,`captured ${view.cursorOffset} for ${placed}`);
  return {view,placed,top};
}
async function reopenAt(p,{view,placed,top},select) {
  await p.evaluate(()=>{window.harness.hostInsertAbove(25);window.harness.area().scrollTop=0;});
  await p.evaluate(view=>window.harness.open('existing',{view}),view);
  await p.waitForFunction(text=>window.harness.selectedText()===text,select);
  await p.waitForFunction(placed=>Math.abs(window.harness.headOffset()-placed)<=2,placed);
  assert.notEqual(await p.evaluate(()=>window.harness.area().scrollTop),top,'not the old scrollTop');
}
test('a restart view puts the cursor back at its place in the window after layout and text above change',async()=>{
  const p=await page();
  await p.setViewportSize({width:900,height:320});
  const captured=await restartView(p,'line 150 ',140);
  await p.setViewportSize({width:520,height:320});
  await reopenAt(p,captured,'line 150 ');
  await p.close();
});

test('a restart view in a nested scroll area keeps a cursor above its visible top there',async()=>{
  const p=await page();
  await p.setViewportSize({width:900,height:600});
  await p.evaluate(()=>Object.assign(document.querySelector('#root').style,
    {height:'260px',overflowY:'auto',border:'9px solid',marginTop:'45px',width:'760px'}));
  const captured=await restartView(p,'line 120 ',-60);
  assert.ok(captured.view.cursorOffset<0);
  await p.evaluate(()=>{document.querySelector('#root').style.width='420px';});
  await reopenAt(p,captured,'line 120 ');
  await p.close();
});

test('a restart view gives way to new input or a newer load; a bad one is ignored',async()=>{
  const p=await page();
  await p.setViewportSize({width:900,height:320});
  const {view}=await restartView(p,'line 150 ',140);
  // A key pressed before the view applies keeps the fresh selection and scroll.
  await p.evaluate(async view=>{
    document.scrollingElement.scrollTop=0;
    await window.harness.open('existing',{view});
    window.dispatchEvent(new KeyboardEvent('keydown',{key:'a'}));
  },view);
  await p.waitForTimeout(200);
  assert.notEqual(await p.evaluate(()=>window.harness.selectedText()),'line 150 ');
  assert.equal(await p.evaluate(()=>document.scrollingElement.scrollTop),0);
  // A newer load replaces the view before its hint applies.
  await p.evaluate(async view=>{
    await window.harness.open('existing',{view});
    await window.harness.open('existing');
  },view);
  await p.waitForTimeout(200);
  assert.notEqual(await p.evaluate(()=>window.harness.selectedText()),'line 150 ');
  assert.equal(await p.evaluate(()=>document.scrollingElement.scrollTop),0);
  for (const bad of [{version:1,anchor:[255,255,255],head:[1],cursorOffset:5},{...view,cursorOffset:'x'},{...view,cursorOffset:1e12}]) {
    await p.evaluate(view=>window.harness.open('existing',{view}),bad);
    await p.waitForFunction(()=>!!document.querySelector('.ProseMirror')?.editor);
    await p.waitForTimeout(100);
    assert.equal(await p.evaluate(()=>window.harness.mode()),'editable');
    assert.equal(await p.evaluate(()=>document.scrollingElement.scrollTop),0,'nothing scrolled');
  }
  await p.close();
});
});
}
