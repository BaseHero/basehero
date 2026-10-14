import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

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
    if(await p.locator('[data-status]').textContent()==='Saved on this device') break;
    await p.waitForFunction(()=>window.harness.pending()>0);
    await p.evaluate(()=>window.harness.ack());
  }
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this device');
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
    if(await p.locator('[data-status]').textContent()==='Saved on this device') break;
    await p.waitForFunction(()=>window.harness.pending()>0);
    await p.evaluate(()=>window.harness.ack());
  }
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this device');
  await p.keyboard.press('ControlOrMeta+z');
  await p.waitForFunction(()=>window.harness.pending()>0,null,{timeout:3000});
  for(let i=0;i<24;i++) {
    if(await p.locator('[data-status]').textContent()==='Saved on this device') break;
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
    assert.equal(await p.getByRole('button',{name:'Undo',hidden:true}).isVisible(),false);
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
  assert.notEqual(await p.locator('[data-status]').textContent(),'Saved on this device');
  await p.evaluate(()=>window.harness.retry());
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>window.harness.pending()===1);
  assert.notEqual(await p.locator('[data-status]').textContent(),'Saved on this device');
  await p.evaluate(()=>window.harness.ack());
  await p.waitForFunction(()=>document.querySelector('[data-status]').textContent==='Saved on this device');
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

test('actual EditorView toolbar creates rich headings, lists and checklists',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('title');
  await p.getByRole('button',{name:'Heading'}).click();
  assert.equal(await p.locator('.ProseMirror h2').textContent(),'title');
  await p.locator('.ProseMirror').press('End');await p.locator('.ProseMirror').press('Enter');
  await p.getByRole('button',{name:'List',exact:true}).click();
  assert.ok(await p.locator('.ProseMirror ul').count()>0);
  await p.getByRole('button',{name:'Checklist'}).click();
  assert.ok(await p.locator('.ProseMirror ul[data-type="taskList"]').count()>0);
  await p.close();
});

test('supported link editing stays inert in WebView; unsafe URL does not become a mark',async()=>{
  const p=await page();await p.evaluate(()=>window.harness.open('empty'));
  await p.locator('.ProseMirror').click();await p.keyboard.type('link me');await p.keyboard.press('ControlOrMeta+a');
  await p.getByRole('textbox',{name:'Link URL'}).fill('https://example.org');
  await p.getByRole('button',{name:'Set link'}).click();
  const anchor=p.locator('.ProseMirror a');
  assert.equal(await anchor.getAttribute('href'),'https://example.org');
  await anchor.click();
  assert.ok(p.url().startsWith('http://127.0.0.1:'));
  await p.getByRole('textbox',{name:'Link URL'}).fill('javascript:alert(1)');
  await p.getByRole('button',{name:'Set link'}).click();
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
});
}
