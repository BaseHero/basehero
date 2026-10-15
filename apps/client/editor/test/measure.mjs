// Comparative browser workload; MEASURE_REFERENCE must name a supplied fixed ref.
// Browser assets are test-only; scratch files use exclusive creation and are removed.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import * as Y from 'yjs';
const {chromium,webkit}=await import(process.env.MEASURE_PLAYWRIGHT??'playwright');
const reference=process.env.MEASURE_REFERENCE;
if(!reference)throw new Error('Supply fixed MEASURE_REFERENCE (not a moving branch)');
const productRoot=new URL('../../../../',import.meta.url);
const run=(command,args,opts={})=>{const p=spawnSync(command,args,{encoding:'utf8',...opts});assert.equal(p.status,0,p.stderr);return p.stdout;};
const prefix=run('git',['rev-parse','--show-prefix'],{cwd:productRoot}).trim();
const referenceHead=run('git',['rev-parse',`${reference}^{commit}`],{cwd:productRoot}).trim();
const source=new URL('../src/',import.meta.url),ui=new URL('../../ui/',import.meta.url);
const scratch=await mkdtemp(new URL('.measure-',source).pathname);
const output=await mkdtemp(join(tmpdir(),'bh-editor-measure-'));
const esbuild=new URL('../node_modules/esbuild/bin/esbuild',import.meta.url).pathname;
const instrument=src=>src.replaceAll('Y.encodeStateAsUpdate(', 'globalThis.__measureEncode(Y,')
  .replace('    state() {return {mode:', '    snapshotForMeasure() {return Y.encodeStateAsUpdate(doc);},\n    state() {return {mode:')

  .replace('editor=new Editor({element:content,extensions:[...extensions,binding],content:\'\',injectCSS:false});',
    `editor=new Editor({element:content,extensions:[...extensions,binding],content:'',injectCSS:false});
    const originalDispatch=editor.view.dispatch.bind(editor.view);
    editor.view.dispatch=tr=>{const start=performance.now();try{return originalDispatch(tr);}finally{
      if(globalThis.__measureLocalActive)globalThis.__measureLocalTimes.push(performance.now()-start);
    }};`);
const instrumentSchema=src=>instrument(src)
  .replace('      if (supported) {\n        supported=!nonTypeInXml',
    '      const validationStart=performance.now();if (supported) {\n        supported=!nonTypeInXml')
  .replace('      return {supported,uncertain:false};',
    '      if (typeof validationStart!=="undefined")globalThis.__measureTiming.validation.push(performance.now()-validationStart);return {supported,uncertain:false};');
const instrumentEditor=src=>instrument(src)
  .replace('  function showReadonly(changes=null) {',
    '  function showReadonly(changes=null) {const renderStart=performance.now();')
  .replace('    setStatus();\n  }\n  function showEditable() {',
    '    setStatus();if(typeof renderStart!=="undefined")globalThis.__measureTiming.render.push(performance.now()-renderStart);\n  }\n  function showEditable() {');
const build=(input,name)=>run(esbuild,[input,'--bundle','--external:/note-editor.js','--format=esm','--platform=browser','--target=es2022','--define:localStorage=undefined','--define:sessionStorage=undefined',`--outfile=${join(output,name)}`]);
const wordText=length=>('small words with spaces and wrapping. ').repeat(Math.ceil(length/38)).slice(0,length);
function block(name,text){const node=new Y.XmlElement(name),inner=new Y.XmlText();inner.insert(0,text);node.insert(0,[inner]);return node;}
function fixture(shape,target){
  const doc=new Y.Doc();doc.clientID=200;const frag=doc.getXmlFragment('default');
  if(shape==='blocks') {
    const count=Math.ceil(target/1024);
    for(let i=0;i<count;i+=64)frag.insert(frag.length,Array.from({length:Math.min(64,count-i)},(_,j)=>block('paragraph',`${i+j} ${wordText(990)}`)));
  }else {
    frag.insert(0,[block('paragraph',wordText(Math.floor(target/2)))]);
    const list=new Y.XmlElement('bulletList'),item=new Y.XmlElement('listItem');
    item.insert(0,[block('paragraph',wordText(Math.floor(target/2)))]);list.insert(0,[item]);frag.insert(1,[list]);
  }
  const state=Y.encodeStateAsUpdate(doc),writers=Array.from({length:20},(_,i)=>{const writer=new Y.Doc();writer.clientID=1000+i;Y.applyUpdate(writer,state);return writer;});
  const updates=[];
  for(let i=0;i<100;i++){
    const writer=writers[i%20],before=Y.encodeStateVector(writer),f=writer.getXmlFragment('default');
    const top=f.get(i%2===0?0:f.length-1);
    const text=shape==='blocks'||i%2===0?top.get(0):top.get(0).get(0).get(0);
    text.insert(0,String.fromCharCode(97+i%26));
    const update=Y.encodeStateAsUpdate(writer,before);updates.push([...update]);
    for(const other of writers)if(other!==writer)Y.applyUpdate(other,update);
  }
  writers.forEach(writer=>writer.destroy());doc.destroy();return {state:[...state],updates};
}
const q=(items,p)=>items.length?[...items].sort((a,b)=>a-b)[Math.min(items.length-1,Math.floor(items.length*p))]:null;
let server;const browsers=[];
try {
  const refEditor=run('git',['show',`${referenceHead}:${prefix}apps/client/editor/src/editor.mjs`],{cwd:productRoot});
  const refSchema=run('git',['show',`${referenceHead}:${prefix}apps/client/editor/src/schema.mjs`],{cwd:productRoot});
  const unique=scratch.split('/').at(-1);
  // Files must live beside production imports, but exclusive unique names never
  // clobber another run's scratch; remove this run's directory only.
  const refSchemaName=`schema.${unique}.reference.mjs`,shippedSchemaName=`schema.${unique}.shipped.mjs`;
  await writeFile(join(scratch,'noop'),'',{flag:'wx'});
  await writeFile(new URL(refSchemaName,source),instrumentSchema(refSchema),{flag:'wx'});
  await writeFile(new URL(shippedSchemaName,source),instrumentSchema(await readFile(new URL('../src/schema.mjs',import.meta.url),'utf8')),{flag:'wx'});
  const versions={current:refEditor.replace("'./schema.mjs'",`'./${refSchemaName}'`),
    mirror:(await readFile(new URL('../src/editor.mjs',import.meta.url),'utf8')).replace("'./schema.mjs'",`'./${shippedSchemaName}'`)};
  for(const [name,content] of Object.entries(versions)){
    const file=new URL(`editor.${unique}.${name}.mjs`,source);
    await writeFile(file,instrumentEditor(content),{flag:'wx'});
    build(file.pathname,`${name}.js`);
    await rm(file);
  }
  await rm(new URL(refSchemaName,source));await rm(new URL(shippedSchemaName,source));
  build(new URL('measure-entry.mjs',import.meta.url).pathname,'entry.js');
  server=createServer(async(req,res)=>{
    const pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'");
    if(pathname==='/'){
      res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><head><link rel="stylesheet" href="/tokens.css"><link rel="stylesheet" href="/shell.css"><link rel="stylesheet" href="/note-editor.css"></head><body><main><div id="root0"></div><div id="root1"></div></main><script type="module" src="/entry.js"></script></body></html>');return;
    }
    let file,type;
    if(['current.js','mirror.js','entry.js'].includes(pathname.slice(1))){file=join(output,pathname.slice(1));type='text/javascript';}
    else if(['tokens.css','shell.css','note-editor.css'].includes(pathname.slice(1))){file=new URL(pathname.slice(1),ui);type='text/css';}
    else if(/^\/fonts\/[a-z0-9-]+\.woff2$/.test(pathname)){file=new URL(pathname.slice(1),ui);type='font/woff2';}
    else{res.writeHead(404).end();return;}
    try{res.setHeader('Content-Type',type);res.end(await readFile(file));}catch{res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  for(const [engine,driver] of [['chromium',chromium],['webkit',webkit]]){
    if(process.env.MEASURE_ENGINE&&process.env.MEASURE_ENGINE!==engine)continue;
    const browser=await driver.launch({headless:true,timeout:30000});browsers.push(browser);
    for(const shape of ['blocks','paragraph-list'].filter(name=>!process.env.MEASURE_SHAPE||process.env.MEASURE_SHAPE===name))for(const target of [16384,262144,1048576,10485760].filter(n=>!process.env.MEASURE_TARGET||Number(process.env.MEASURE_TARGET)===n))for(const version of ['current','mirror']){
      const {state,updates}=fixture(shape,target);
      const page=await browser.newPage();const errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      await page.route('**/note-editor.js',route=>route.continue({url:`http://127.0.0.1:${server.address().port}/${version}.js`}));
      await page.addInitScript(()=>{window.__measureCounts={calls:0,bytes:0};window.__measureTiming={validation:[],render:[]};window.__measureEncode=(Y,doc,...rest)=>{
        const encoded=Y.encodeStateAsUpdate(doc,...rest);
        // Only whole-state copies (one-argument calls) count, not delta encodes.
        if(!rest.length){window.__measureCounts.calls++;window.__measureCounts.bytes+=encoded.length;}
        return encoded;
      };});
      await page.goto(`http://127.0.0.1:${server.address().port}/`);
      const cdp=engine==='chromium'?await page.context().newCDPSession(page):null;
      if(cdp)await cdp.send('Performance.enable');
      const emptyHeap=cdp?(await cdp.send('Runtime.getHeapUsage')).usedSize:null;
      const setup=await page.evaluate(state=>measure.setup(state),state);
      const setupHeap=cdp?(await cdp.send('Runtime.getHeapUsage')).usedSize:null;
      assert.deepEqual(setup.modes,['editable','editable']);
      const before=await page.evaluate(()=>measure.heap);
      const countsBefore=await page.evaluate(()=>({...window.__measureCounts}));
      const metricsBefore=cdp?(await cdp.send('Performance.getMetrics')).metrics:null;
      const traceThis=!!(cdp && process.env.MEASURE_TRACE && shape==='paragraph-list' && target===1048576 && version==='mirror');
      if(traceThis)await cdp.send('Tracing.start',{categories:'devtools.timeline,disabled-by-default-devtools.timeline',transferMode:'ReturnAsStream'});
      const sustained=await page.evaluate(updates=>measure.sustained(updates),updates.slice(0,60));
      let traceSummary=null;
      if(traceThis){
        const completed=new Promise(resolve=>cdp.once('Tracing.tracingComplete',resolve));
        await cdp.send('Tracing.end');const {stream}=await completed;let raw='';
        for(;;){const chunk=await cdp.send('IO.read',{handle:stream});raw+=chunk.base64Encoded?Buffer.from(chunk.data,'base64').toString():chunk.data;if(chunk.eof)break;}
        await cdp.send('IO.close',{handle:stream});
        const names=['FunctionCall','EvaluateScript','Layout','UpdateLayoutTree','Paint','CompositeLayers','PrePaint'];
        traceSummary=Object.fromEntries(names.map(name=>[name,{ms:0,events:0}]));
        for(const event of JSON.parse(raw).traceEvents){
          if(event.ph!=='X'||!Object.hasOwn(traceSummary,event.name))continue;
          traceSummary[event.name].events++;traceSummary[event.name].ms+=event.dur/1000;
        }
      }
      const metricsAfter=cdp?(await cdp.send('Performance.getMetrics')).metrics:null;
      const metricDelta=metricsBefore?Object.fromEntries(['TaskDuration','ScriptDuration','LayoutDuration','RecalcStyleDuration'].map(name=>[name,Math.round(1000*((metricsAfter.find(m=>m.name===name)?.value??0)-(metricsBefore.find(m=>m.name===name)?.value??0)))])):null;
      const countsAfter=await page.evaluate(()=>({...window.__measureCounts}));
      const timings=await page.evaluate(()=>({...window.__measureTiming}));
      assert.deepEqual(sustained.modes,['editable','editable']);
      const burst=await page.evaluate(updates=>measure.burst(updates),updates.slice(60)); // separately labeled burst
      assert.deepEqual(await page.evaluate(()=>measure.convergence),[true,true],
        'both editing copies converge after remote writers');
      assert.deepEqual(burst.modes,['editable','editable']);
      const localStart=await page.evaluate(()=>{window.__measureLocalTimes=[];window.__measureLocalActive=true;return performance.now();});
      await page.locator('#root0 .ProseMirror').click();await page.keyboard.type('typed');
      await page.keyboard.insertText('pasted words');
      await page.evaluate(updates=>measure.burst(updates),updates.slice(80)); // concurrent writer tail between paste and Undo
      await page.locator('#root0 button').first().click();
      await page.locator('#root1 .ProseMirror').click();await page.keyboard.insertText('second view');
      const localEnd=await page.evaluate(()=>{window.__measureLocalActive=false;return performance.now();});
      assert.deepEqual(await page.evaluate(()=>measure.unknown()),['readonly','readonly']);
      const skewBefore=await page.evaluate(()=>({counts:{...window.__measureCounts},
        validation:window.__measureTiming.validation.length,render:window.__measureTiming.render.length}));
      const skew=await page.evaluate(()=>measure.readonlyEdits());
      const skewAfter=await page.evaluate(before=>({counts:{...window.__measureCounts},
        validation:window.__measureTiming.validation.slice(before.validation),
        render:window.__measureTiming.render.slice(before.render)}),skewBefore);
      assert.deepEqual(skew.modes,['readonly','readonly']);
      assert.deepEqual(await page.evaluate(()=>measure.resolveUnknown()),['editable','editable']);
      assert.deepEqual(await page.evaluate(()=>measure.dependencyResolution()),['editable','editable']);
      await page.waitForFunction(()=>measure.commits.length>0&&measure.states.every(state=>state.saved));
      const result=await page.evaluate(()=>({convergence:measure.convergence,commits:measure.commits,
        text:[...document.querySelectorAll('.ProseMirror')].map(el=>el.textContent),heap:measure.heap,
        modes:measure.modes}));
      assert.equal(errors.length,0,errors.join('\n'));
      assert.equal(result.text.length,2);
      assert.deepEqual(result.convergence,[true,true],
        'both editing copies converge in content and state vector after local, remote, Undo and dependency updates');
      assert.equal(result.text[0],result.text[1],'both views converge after local fanout');
      assert.ok(result.text[0].includes('second view'),'peer edit reached first view');
      assert.ok(result.commits.length>0,'local writes committed');
      const external=new Y.Doc();Y.applyUpdate(external,new Uint8Array(state));
      for(const update of updates)Y.applyUpdate(external,new Uint8Array(update));
      for(const commit of result.commits)Y.applyUpdate(external,new Uint8Array(commit));
      // Unknown insert/delete and unresolved dependency are tested for modes;
      // compare visible remote/local text here (those tombstones add metadata).
      assert.equal(external.getXmlFragment('default').toString().includes('second view'),true);
      external.destroy();
      const row={engine,shape,target,version,referenceHead,encoded:setup.encoded,
        arrivalIntervalMs:50,updates:60,achievedHz:60/(sustained.elapsed/1000),
        completionLagMs:sustained.completionLag,arrivalLagP95:q(sustained.arrival,.95),
        transactionP50:q(sustained.times,.5),transactionP95:q(sustained.times,.95),
        validationP50:q(timings.validation,.5),validationP95:q(timings.validation,.95),
        renderP50:q(timings.render,.5),renderP95:q(timings.render,.95),
        readonlyTransactionP50:q(skew.times,.5),readonlyTransactionP95:q(skew.times,.95),
        readonlyValidationP50:q(skewAfter.validation,.5),readonlyValidationP95:q(skewAfter.validation,.95),
        readonlyRenderP50:q(skewAfter.render,.5),readonlyRenderP95:q(skewAfter.render,.95),
        readonlyFullCopies:skewAfter.counts.calls-skewBefore.counts.calls,
        frameP95:q(sustained.frames,.95),frameMax:Math.max(0,...sustained.frames),frames:sustained.frames.length,
        fullCopies:countsAfter.calls-countsBefore.calls,fullCopyBytes:countsAfter.bytes-countsBefore.bytes,
        wireMean:sustained.wire.reduce((a,b)=>a+b,0)/sustained.wire.length,
        burst20Ms:burst.elapsed,localRoundtripMs:localEnd-localStart,
        localSyncDispatchP95:q(await page.evaluate(()=>window.__measureLocalTimes),.95),
        heapBefore:before,heapAfter:result.heap,emptyHeap,setupHeap,metricDelta,traceSummary,commits:result.commits.length};
      console.log(JSON.stringify(row));await page.close();
    }
    await browser.close();browsers.pop();
  }
}finally{
  for(const browser of browsers)await browser.close();
  if(server)await new Promise(resolve=>server.close(resolve));
  for(const kind of ['reference','shipped'])await rm(new URL(`schema.${scratch.split('/').at(-1)}.${kind}.mjs`,source),{force:true});
  await rm(scratch,{recursive:true,force:true});await rm(output,{recursive:true,force:true});
}
