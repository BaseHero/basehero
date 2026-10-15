// Test-only esbuild transforms expose the two Y.Docs and fallback ordering.
// No test seam or instrumentation is present in shipped source or bundle.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {build} from 'esbuild';
import {chromium,webkit} from 'playwright';

const directory=await mkdtemp(join(tmpdir(),'editor-fallback-'));
let server;
try {
  await build({entryPoints:[new URL('mirror-fallback-entry.mjs',import.meta.url).pathname],bundle:true,
    format:'esm',platform:'browser',target:'es2022',outfile:join(directory,'entry.js'),
    define:{localStorage:'undefined',sessionStorage:'undefined'},plugins:[{
      name:'test-only-fallback-seam',setup(builder){
        builder.onLoad({filter:/\/src\/(editor|schema)\.mjs$/},async({path})=>{
          let contents=await readFile(path,'utf8');
          if(path.endsWith('/editor.mjs')){
            contents=contents.replace("  doc.on('update',(bytes,origin)=>{", "  doc.on('update',(bytes,origin)=>{if(origin===ySyncPluginKey)globalThis.__bindingWrites++;")
              .replace('function rebuildMirror() {',
              "function rebuildMirror() {globalThis.__fallbackEvents.push({phase:'suspend',bound:!!editor,pending:pending.items.slice(pending.head).map(item=>item.id)});")
              .replace('try {mirror=createPreflightMirror(doc);} catch {mirror=null;}\n    refresh(mirror?.supported??false);',
                "try {mirror=createPreflightMirror(doc);} catch {mirror=null;}globalThis.__fallbackEvents.push({phase:'checked',bound:!!editor,supported:mirror?.supported});\n    refresh(mirror?.supported??false);")
              .replace('    retry:retrySave,',
                "    __testDiverge(bytes){Y.applyUpdate(mirror.doc,bytes,'test-only');},\n    __testLiveWrite(kind){doc.transact(()=>{const f=doc.getXmlFragment('default');if(kind==='insert'){const p=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,'external');p.insert(0,[t]);f.insert(1,[p]);}else f.delete(1,1);},'external');},\n    __testMirror(){return {content:mirror.doc.getXmlFragment('default').toString(),vector:[...Y.encodeStateVector(mirror.doc)],liveVector:[...Y.encodeStateVector(doc)]};},\n    retry:retrySave,");
          }else contents=contents.replace('export function inspectDisposable(fragment) {',
            'export function inspectDisposable(fragment) {globalThis.__fullChecks++;')
            .replace('    projected.check();',
              "    projected.check();if(globalThis.__forceProjectionWrite)fragment.doc.getXmlFragment('default').insert(0,[new Y.XmlElement('paragraph')]);");
          return {contents,loader:'js'};
        });
      },
    }]});
  server=createServer(async(req,res)=>{
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'");
    res.setHeader('Content-Type',req.url==='/'?'text/html':'text/javascript');
    res.end(req.url==='/'?'<html><body><div id="root"></div><script type="module" src="/entry.js"></script></body></html>':
      req.url==='/entry.js'?await readFile(join(directory,'entry.js')):'');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
} catch(error){if(server)await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});throw error;}

test.after(async()=>{await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});});
for(const [name,engine] of [['Chromium',chromium],['WebKit',webkit]])test(`unexpected-origin live writes (including delete-only) suspend binding and rebuild in ${name}`,async()=>{
  const browser=await engine.launch({headless:true});
  try{
    const page=await browser.newPage();
    await page.addInitScript(()=>{window.__fullChecks=0;window.__bindingWrites=0;window.__fallbackEvents=[];window.__forceProjectionWrite=false;});
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForFunction(()=>!!window.fallbackHarness);
    assert.deepEqual(await page.evaluate(()=>window.fallbackHarness.open()),{mode:'editable',fullChecks:1});
    await page.locator('.ProseMirror').click();await page.keyboard.insertText('local');
    const prior=await page.evaluate(()=>window.fallbackHarness.state());
    assert.equal(prior.jobs.length,1);
    assert.ok(prior.bindingWrites>0,'local typing exercised the actual ySync binding');
    // An unexpected live writer is not mirrored, so it must suspend and
    // rebuild before a subsequent incoming update can bind.
    const divergent=await page.evaluate(()=>window.fallbackHarness.liveWrite('insert'));
    assert.deepEqual(divergent.events.slice(0,2),[
      {phase:'suspend',bound:true,pending:prior.jobs},
      {phase:'checked',bound:false,supported:true},
    ]);
    const unsupported=await page.evaluate(()=>window.fallbackHarness.incoming('unsupported'));
    assert.equal(unsupported.mode,'readonly');
    assert.deepEqual(unsupported.jobs,prior.jobs,'pending commit and request ID survive fallback');
    assert.equal(unsupported.bindingWrites,prior.bindingWrites,'unsupported bytes cause no binding write');
    assert.deepEqual(unsupported.events.slice(0,2),[
      {phase:'suspend',bound:true,pending:prior.jobs},
      {phase:'checked',bound:false,supported:true},
    ]);
    assert.equal(unsupported.fullChecks,2,'initial load + unexpected-origin full disposable preflight');
    const rebuilt=await page.evaluate(()=>window.fallbackHarness.mirror());
    assert.deepEqual(rebuilt.vector,rebuilt.liveVector,'mirror rebuilt from live copy');
    assert.ok(rebuilt.content.includes('external'),'unexpected live write retained');
    assert.equal(await page.locator('.ProseMirror').count(),0,'unsupported update never binds');
    assert.equal(await page.locator('.note-placeholder').count(),1);
    const stillUnsupported=await page.evaluate(()=>window.fallbackHarness.incoming('while-unsupported'));
    assert.equal(stillUnsupported.mode,'readonly');
    assert.equal(stillUnsupported.fullChecks,unsupported.fullChecks,
      'incoming updates while unsupported do not copy and project the whole note');
    const restored=await page.evaluate(()=>window.fallbackHarness.incoming('remove'));
    assert.equal(restored.mode,'editable','rebind only after support returns');
    assert.deepEqual(restored.jobs,prior.jobs);
    const beforeDelete=await page.evaluate(()=>window.fallbackHarness.mirror());
    const deleted=await page.evaluate(()=>window.fallbackHarness.liveWrite('delete'));
    assert.equal(deleted.mode,'editable');
    assert.deepEqual(deleted.events.slice(-2).map(item=>item.phase),['suspend','checked']);
    const afterDelete=await page.evaluate(()=>window.fallbackHarness.mirror());
    assert.deepEqual(afterDelete.vector,beforeDelete.vector,'delete-only update does not change a state vector');
    assert.ok(!afterDelete.content.includes('external'),'delete-only write reflected in rebuilt mirror');
    await page.evaluate(()=>window.fallbackHarness.ack());
    await page.waitForFunction(()=>window.fallbackHarness.state().pending===0);
    await page.evaluate(()=>window.fallbackHarness.close());
    await page.close();
  } finally {await browser.close();}
});

for(const [name,engine] of [['Chromium',chromium],['WebKit',webkit]])test(`projection writes cannot alter the persistent mirror in ${name}`,async()=>{
  const browser=await engine.launch({headless:true});
  try {
    const page=await browser.newPage();
    await page.addInitScript(()=>{window.__fullChecks=0;window.__bindingWrites=0;window.__fallbackEvents=[];window.__forceProjectionWrite=false;});
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForFunction(()=>!!window.fallbackHarness);
    await page.evaluate(()=>window.fallbackHarness.open());
    assert.equal((await page.evaluate(()=>window.fallbackHarness.incoming('unsupported'))).mode,'readonly');
    const checked=await page.evaluate(()=>{
      window.__forceProjectionWrite=true;
      window.fallbackHarness.incoming('remove');
      return {mirror:window.fallbackHarness.mirror(),state:window.fallbackHarness.state()};
    });
    assert.equal(checked.state.mode,'readonly','a mutating projection cannot make the note editable');
    assert.deepEqual(checked.mirror.vector,checked.mirror.liveVector,'persistent mirror never receives projection writes');
    await page.evaluate(()=>window.fallbackHarness.close());
    await page.close();
  } finally {await browser.close();}
});
