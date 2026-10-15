import test from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {chromium} from 'playwright';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';

const output=await mkdtemp(join(tmpdir(),'bh-nontype-'));
let server,browser;
try {
  await build({entryPoints:[new URL('non-type-entry.mjs',import.meta.url).pathname],bundle:true,
    format:'esm',platform:'browser',target:'es2022',outfile:join(output,'entry.js'),
    define:{localStorage:'undefined',sessionStorage:'undefined'},plugins:[{
      name:'observe-real-binding',setup(builder){builder.onLoad({filter:/\/src\/(editor|schema)\.mjs$/},async({path})=>{
        let source=(await readFile(path,'utf8')).replaceAll('Y.encodeStateAsUpdate(', 'globalThis.__countEncode(Y,');
        if(path.endsWith('/schema.mjs')) {
          if(process.env.BH_INJECT_MIRROR_COPY) source=source.replace("      fragment.observeDeep(capture);", "      globalThis.__countEncode(Y,doc);fragment.observeDeep(capture);");
          return {loader:'js',contents:source};
        }
        return {loader:'js',contents:source
          .replace("  let fragment=doc.getXmlFragment(inventory.fragment);",
            "  window.__nonTypeLive=()=>Y.encodeStateAsUpdate(doc);let fragment=doc.getXmlFragment(inventory.fragment);")
          .replace("  doc.on('update',(bytes,origin)=>{",
            "  window.__queuePending=()=>pending.items.slice(pending.head).map(item=>({id:item.id,bytes:item.bytes?[...item.bytes]:undefined,rawBytes:item.rawBytes}));window.__queueRetained=()=>pending.retainedBytes;doc.on('update',(bytes,origin)=>{if(origin===ySyncPluginKey)window.__nonTypeBindingWrites++;")};});},
    }]});
  server=createServer(async(req,res)=>{
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'");
    res.setHeader('Content-Type',req.url==='/'?'text/html':'text/javascript');
    res.end(req.url==='/'?'<html><body><script type="module" src="/entry.js"></script></body></html>':
      req.url==='/entry.js'?await readFile(join(output,'entry.js')):'');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  browser=await chromium.launch({headless:true,...(process.env.BH_TEST_CHROMIUM ? {executablePath:process.env.BH_TEST_CHROMIUM} : {})});
} catch(error){if(browser)await browser.close();if(server)await new Promise(resolve=>server.close(resolve));await rm(output,{recursive:true,force:true});throw error;}
async function openPage(){
  const page=await browser.newPage();
  await page.addInitScript(()=>{window.__copyCount=0;window.__countEncode=(Y,doc,...rest)=>{
    if(!rest.length)window.__copyCount++;return Y.encodeStateAsUpdate(doc,...rest);
  };});
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  return page;
}
test.after(async()=>{await browser.close();await new Promise(resolve=>server.close(resolve));await rm(output,{recursive:true,force:true});});
test('warm local, incoming and read-only updates never encode whole state',async()=>{
  const page=await openPage();
  try {
    await page.waitForFunction(()=>!!window.queueHarness);
    await page.evaluate(()=>queueHarness.open());
    await page.evaluate(()=>{window.__copyCount=0;queueHarness.incoming();});
    assert.equal(await page.evaluate(()=>window.__copyCount),0,'incoming update');
    await page.locator('.ProseMirror').click();
    await page.evaluate(()=>{window.__copyCount=0;});
    await page.keyboard.insertText('local');
    assert.equal(await page.evaluate(()=>window.__copyCount),0,'local update');
    await page.evaluate(()=>queueHarness.close());
    await page.evaluate(()=>readonlyHarness.open());
    await page.evaluate(()=>{window.__copyCount=0;readonlyHarness.edit('nested');});
    assert.equal(await page.evaluate(()=>window.__copyCount),0,'read-only nested update');
    await page.evaluate(()=>readonlyHarness.close());
  }finally{await page.close();}
});
test('read-only nested edit, insert, delete and recovery reuse unaffected DOM blocks',async()=>{
  const page=await openPage();
  try {
    await page.waitForFunction(()=>!!window.readonlyHarness);
    assert.equal((await page.evaluate(()=>readonlyHarness.open())).mode,'readonly');
    for (const action of ['nested','insert','delete']) {
      const result=await page.evaluate(action=>readonlyHarness.edit(action),action);
      assert.equal(result.state.mode,'readonly');assert.equal(result.state.saved,false);
      assert.equal(result.placeholders,1);
      assert.equal(result.stableSame,true,`unaffected block must survive ${action}`);
    }
    assert.match((await page.evaluate(()=>readonlyHarness.edit('nested'))).text,/new new before/);
    const combined=await page.evaluate(()=>readonlyHarness.edit('combined'));
    assert.match(combined.text,/combined new new before/);
    assert.equal(combined.stableSame,true);
    const recovered=await page.evaluate(()=>readonlyHarness.edit('recover'));
    assert.equal(recovered.state.mode,'editable');assert.equal(recovered.placeholders,0);
    await page.evaluate(()=>readonlyHarness.close());
  }finally{await page.close();}
});
test('failed attempted bytes and ID remain exact while unsent edits merge into one tail',async()=>{
  const page=await openPage();
  try {
    await page.waitForFunction(()=>!!window.queueHarness);
    await page.evaluate(()=>queueHarness.open());
    await page.locator('.ProseMirror').click();
    await page.keyboard.insertText('a');
    const first=await page.evaluate(()=>queueHarness.items()[0]);
    assert.ok(first?.id);
    for(const text of ['b','c','d','e']) await page.keyboard.insertText(text);
    const queued=await page.evaluate(()=>window.__queuePending());
    assert.equal(queued.length,2,'one immutable attempted head and one unsent tail');
    assert.equal(queued[0].id,first.id);
    assert.deepEqual(queued[0].bytes,first.bytes);
    assert.equal(queued[1].id,undefined,'do not allocate a request ID before submission');
    await page.evaluate(()=>queueHarness.reject());
    await page.waitForFunction(()=>queueHarness.state().pending>0 && document.querySelector('[data-status]').textContent.includes('Retry'));
    const failed=await page.evaluate(()=>window.__queuePending()[0]);
    assert.equal(failed.id,first.id);assert.deepEqual(failed.bytes,first.bytes,'failure cannot mutate attempted bytes');
    await page.evaluate(()=>queueHarness.retry());
    await page.waitForFunction(()=>queueHarness.items().length===1);
    assert.deepEqual(await page.evaluate(()=>queueHarness.items()[0]),first);
    await page.evaluate(()=>queueHarness.ack());
    await page.waitForFunction(()=>queueHarness.items().length===1);
    assert.notEqual((await page.evaluate(()=>queueHarness.items()[0])).id,first.id);
    await page.evaluate(()=>queueHarness.ack());
    await page.waitForFunction(()=>queueHarness.state().saved);
    assert.equal(await page.evaluate(()=>queueHarness.storedText()),await page.locator('.ProseMirror').innerText(),
      'merged unsent tail must survive durable commit intact');
    assert.equal(await page.evaluate(()=>window.__queueRetained()),0,'ack releases consumed payload');
    await page.evaluate(()=>queueHarness.close());
  }finally{await page.close();}
});
test('a Yjs redoItem TypeError does not escape editor commands',async()=>{
  const page=await openPage();
  try {await page.waitForFunction(()=>!!window.historyFailureHarness);
    const result=await page.evaluate(()=>historyFailureHarness());
    assert.equal(result.failed,false);assert.equal(result.mode,'editable');
  }finally{await page.close();}
});
for(const phase of ['open','apply']) test(`Yjs read failure during ${phase} remains inert read-only`,async()=>{
  const page=await openPage();
  try {
    await page.waitForFunction(()=>!!window.readFailureHarness);
    const result=await page.evaluate(phase=>readFailureHarness(phase),phase);
    assert.equal(result.error,undefined,JSON.stringify(result));
    assert.equal(result.mode,'readonly');assert.ok(result.placeholder>0);
  } finally {await page.close();}
});
for(const kind of ['json','string','binary','subdoc'])for(const location of ['root','paragraph'])
  test(`real binding does not edit or claim Saved after ${kind} at ${location}`,async()=>{
    const page=await openPage();
    try {
      await page.waitForFunction(()=>!!window.nonTypeHarness);
      const result=await page.evaluate(([k,l])=>nonTypeHarness(k,l),[kind,location]);
      assert.equal(result.before.mode,'editable');
      assert.equal(result.after.mode,'readonly');
      assert.equal(result.after.saved,false);
      assert.equal(result.editor,0);
      assert.equal(result.placeholders,1);
      assert.equal(result.commits,0);
      assert.equal(result.bindingWrites,0);
      assert.equal(result.preserved,true,'live state matches writer byte-for-byte');
      assert.match(result.status,/Read-only · Update BaseHero to edit/);
      assert.doesNotMatch(result.visible,/unknown|raw/);
    } finally {await page.close();}
  });
