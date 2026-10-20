// Disposable API 36 Pixel Fold only. Native device transitions, not DOM resize simulations.
import {execFileSync} from 'node:child_process';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';

const [phase, record] = process.argv.slice(2);
const serial = process.env.ANDROID_SERIAL;
if (!/^emulator-\d+$/.test(serial ?? '') || !['live','reopen'].includes(phase) || !record)
  throw Error('usage: ANDROID_SERIAL=emulator-N node continuity.spec.mjs live|reopen record.json');
const adb = (...args) => execFileSync('adb',['-s',serial,...args],{encoding:'utf8',timeout:30000}).trim();
const sleep = ms => new Promise(resolve=>setTimeout(resolve,ms));
// The Fold has an inner and an outer display; capture whichever the posture uses.
const displays=()=>[...adb('shell','dumpsys','display').matchAll(/uniqueId="local:(\d+)", (\d+) x (\d+)/g)]
  .map(([,display,w,h])=>({display,area:w*h})).sort((a,b)=>b.area-a.area);
const screenshot = name => {
  const dir=process.env.CONTINUITY_SCREENSHOTS;
  if (!dir) return;
  mkdirSync(dir,{recursive:true});
  const [inner,outer]=displays();
  const display=foldState().includes('CLOSED') && outer ? outer : inner;
  adb('shell','screencap','-d',display.display,'-p','/sdcard/bh-continuity.png');
  execFileSync('adb',['-s',serial,'pull','/sdcard/bh-continuity.png',`${dir}/${name}.png`],{stdio:'pipe'});
};
const base='http://127.0.0.1:4445';
async function call(method,path,body) {
  const response=await fetch(base+path,{method,headers:{'content-type':'application/json'},
    body:body===undefined?undefined:JSON.stringify(body)});
  const json=await response.json();
  if(!response.ok)throw Error(`${method} ${path}: ${JSON.stringify(json.value??json)}`);
  return json.value;
}
const open=async()=> (await call('POST','/session',{capabilities:{}})).sessionId;
const run=(id,script)=>call('POST',`/session/${id}/execute/sync`,{script,args:[]});
async function until(id,script,label,timeout=30000) {
  let last;
  for(const end=Date.now()+timeout;Date.now()<end;await sleep(400)) {
    try {last=await run(id,script);if(last?.ok)return last;}catch(error){last=String(error);}
  }
  throw Error(`${label}: ${JSON.stringify(last)}`);
}
const editorReady="return {ok: !!document.querySelector('section[aria-label=Note] .ProseMirror')};";
const state=`const e=document.querySelector('section[aria-label=Note] .ProseMirror');
  const ps=[...e?.querySelectorAll(':scope > p')??[]];
  const nav=document.querySelector('nav[aria-label=Notes] [aria-current=true]');
  const sel=window.getSelection();
  const range=sel?.rangeCount?sel.getRangeAt(0):null;
  const caret=range?.getBoundingClientRect();
  const pane=e?.closest('.note-pane'),viewport=pane?.getBoundingClientRect();
  return {ok:!!e&&!!nav,paragraphs:ps.map(p=>p.textContent),bold:ps.map(p=>[...p.querySelectorAll('strong,b')].map(b=>b.textContent)),
    title:nav?.textContent,selected:!!sel&&e?.contains(sel.anchorNode),selection:sel?.toString(),
    anchor:sel?.anchorOffset,head:sel?.focusOffset,anchorText:sel?.anchorNode?.textContent,
    headText:sel?.focusNode?.textContent,caretY:caret?.top,viewportTop:viewport?.top,viewportBottom:viewport?.bottom,
    caretBottom:caret?.bottom,viewportWidth:viewport?.width,screenHeight:innerHeight,
    lineHeight:parseFloat(e?getComputedStyle(e).lineHeight:'0'),scrollTop:pane?.scrollTop,
    scrollHeight:pane?.scrollHeight,clientHeight:pane?.clientHeight,
    status:document.querySelector('footer [data-status]')?.textContent};`;
const sample=id=>run(id,state);
const assert=(ok,message,detail)=>{if(!ok)throw Error(`${message}: ${JSON.stringify(detail)}`);};
const orientation=()=>adb('shell','dumpsys','window').match(/mRotation=ROTATION_(\d+)/)?.[1];
const ime=()=>adb('shell','dumpsys','input_method').match(/mInputShown=(true|false)/)?.[1];
// Top edge of the shown keyboard, in device pixels, from Android's IME inset.
const imeTop=()=>{
  const tops=[...adb('shell','dumpsys','window').matchAll(/InsetsSource id=\S+ type=ime frame=\[\d+,(\d+)\]\[\d+,\d+\] visibleFrame=\S+ visible=true/g)]
    .map(match=>Number(match[1]));
  return tops.length?Math.min(...tops):undefined;
};
const foldState=()=>adb('shell','cmd','device_state','state');
async function waitDevice(read,desired,label) {
  let value;
  for(let i=0;i<30;i++){value=read();if(desired(value))return value;await sleep(250);}
  throw Error(`${label}: ${JSON.stringify(value)}`);
}
const activity=()=>adb('shell','dumpsys','activity','activities').split('\n')
  .find(line=>line.includes('ActivityRecord{') && line.includes('app.basehero.client/.MainActivity') && !line.includes('isExiting'))
  ?.match(/ActivityRecord\{([0-9a-f]+)/)?.[1];
const pid=()=>adb('shell','pidof','app.basehero.client');
const focus=()=>adb('shell','dumpsys','window').match(/mCurrentFocus=([^\n]+)/)?.[1];
async function unlock() {
  if(focus()?.includes('app.basehero.client'))return;
  adb('shell','input','keyevent','82');
  if(!focus()?.includes('app.basehero.client')) {
    adb('shell','input','text','1234');
    adb('shell','input','keyevent','66');
  }
  adb('shell','wm','dismiss-keyguard');
  await waitDevice(focus,value=>value?.includes('app.basehero.client'),'app foreground after transition/unlock');
}
const nativeRows=async id=> {
  const key='__bhContinuityRows';
  return (await until(id,`if(!window.${key})window.${key}={};
    if(!window.${key}.started){window.${key}.started=true;window.__TAURI_INTERNALS__.invoke('note_list').then(rows=>window.${key}.rows=rows,error=>window.${key}.error=String(error));}
    return {ok:!!window.${key}.rows,rows:window.${key}.rows,error:window.${key}.error};`,'native note_list')).rows;
};
let id,fingers;
try {
  id=await open();
  if(phase==='reopen') {
    await until(id,"return {ok:!!document.querySelector('section[aria-label=Note] .ProseMirror'),body:document.body?.innerText?.slice(0,600)};",'reopened note',120000);
    const prior=JSON.parse(readFileSync(record,'utf8'));
    const s=await sample(id),rows=await nativeRows(id);
    assert(JSON.stringify({note:rows[0]?.note,paragraphs:s.paragraphs,bold:s.bold,title:s.title})===JSON.stringify({note:prior.note,paragraphs:prior.paragraphs,bold:prior.bold,title:prior.title}),
      'process_death_restores_current_note: acknowledged content/current note changed',{s,rows,prior});
    console.log(`PASS process_death_restores_current_note (emulator evidence): ${JSON.stringify({pid:pid(),note:rows[0].note,title:s.title})}`);
    if(prior.unexercised?.length){console.error(`BLOCKED scenarios: ${prior.unexercised.join('; ')}`);process.exitCode=1;}
  } else {
    await until(id,"return {ok:document.querySelector('main .label')?.textContent==='WELCOME'};",'welcome',60000);
    const button=await call('POST',`/session/${id}/element`,{using:'css selector',value:'#bh-emulator-fixture button'});
    await call('POST',`/session/${id}/element/${Object.values(button)[0]}/click`,{});
    fingers=setInterval(()=>{try{adb('emu','finger','touch','1');}catch{}},1500);
    await until(id,editorReady,'created note',300000);
    clearInterval(fingers);fingers=undefined;
    const setup=await run(id,`const e=document.querySelector('.ProseMirror');e.focus();
      const a=document.execCommand('insertText',false,'Kept in bold');
      const p=e.querySelector('p'),t=p.firstChild,s=window.getSelection();
      s.setBaseAndExtent(t,8,t,12);
      return {ok:a&&s.toString()==='bold',html:e.innerHTML};`);
    assert(setup.ok,'could not prepare editor',setup);
    const formatted=await run(id,`document.querySelector('.note-bubble button[aria-label=Bold]')?.click();
      return {ok:!!document.querySelector('.ProseMirror p strong'),html:document.querySelector('.ProseMirror')?.innerHTML};`);
    assert(formatted.ok,'could not format bold',formatted);
    const finished=await run(id,`const e=document.querySelector('.ProseMirror'),p=e.querySelector('p'),s=window.getSelection();
      e.focus();s.collapse(p,p.childNodes.length);
      const b=document.execCommand('insertParagraph'),c=document.execCommand('insertText',false,'A second paragraph for continuity');
      s.collapse(p,p.childNodes.length);
      const d=document.execCommand('insertText',false,'!');
      return {ok:b&&c&&d,html:e.innerHTML};`);
    assert(finished.ok,'could not finish title',finished);
    await until(id,`const s=(()=>{${state}})();return {...s,ok:s.title==='Kept in bold!' && s.bold[0]?.[0]==='bold!' && s.bold[1]?.[0]==='A second paragraph for continuity' && s.paragraphs[1]==='A second paragraph for continuity'};`,'native acknowledged initial save',120000);
    const baseline=await sample(id);
    const rows=await nativeRows(id);
    assert(rows.length===1 && rows[0].title===baseline.title && rows[0].note.length===32,'native current note',rows);
    const note=rows[0].note;
    const select=async()=> {
      const result=await run(id,`const e=document.querySelector('.ProseMirror');e.focus();
        const p=e.querySelectorAll(':scope > p')[1],t=p.querySelector('strong')?.firstChild??p.firstChild,s=window.getSelection();
        s.setBaseAndExtent(t,2,t,5);return {ok:s.toString()==='sec',text:s.toString()};`);
      assert(result.ok,'could not select second paragraph',result);
      return sample(id);
    };
    const verify=async(label,before,title)=> {
      await until(id,`const s=(()=>{${state}})();return {...s,ok:s.ok && s.title===${JSON.stringify(title)} && s.status==='Saved on this device'};`,`${label} native acknowledged title`,120000);
      await run(id,"document.querySelector('.ProseMirror')?.focus();return {ok:true};");
      const after=await sample(id);
      assert(after.paragraphs[0]===title && after.paragraphs[1]==='A second paragraph for continuity' &&
        after.bold[0]?.[0]===title.slice(8) && after.bold[1]?.[0]==='A second paragraph for continuity',`${label}: text/marks`,after);
      assert(after.selected && after.anchor===before.anchor && after.head===before.head &&
        after.anchorText===before.anchorText && after.headText===before.headText &&
        after.selection===before.selection,`${label}: selection`,{before,after});
      assert(Math.abs(after.caretY-before.caretY)<=Math.max(before.lineHeight,after.lineHeight),
        `${label}: scroll anchor moved more than one line`,{before,after});
      assert(after.title===title,`${label}: navigation`,after);
      console.log(`PASS ${label} (emulator evidence): ${JSON.stringify({title,anchor:after.anchor,head:after.head,scrollDelta:after.caretY-before.caretY,fold:foldState(),orientation:orientation(),ime:ime(),pid:pid()})}`);
    };
    const appendTitle=async suffix=> {
      const result=await run(id,`const e=document.querySelector('.ProseMirror'),p=e.querySelector('p');
        e.focus();window.getSelection().collapse(p,p.childNodes.length);
        return {ok:document.execCommand('insertText',false,${JSON.stringify(suffix)})};`);
      assert(result.ok,'could not queue pending native save',result);
      return select();
    };
    let before=await appendTitle('F');
    screenshot('01-unfolded');
    const opened=foldState();
    adb('emu','fold');
    const closed=await waitDevice(foldState,value=>value.includes('CLOSED'),'fold device state');
    assert(opened.includes('OPENED') && closed.includes('CLOSED'),'fold command did not change actual device state',{opened,closed});
    await unlock();
    screenshot('02-folded');
    await verify('fold_unfold_preserves_editing',before,'Kept in bold!F');
    before=await appendTitle('U');
    adb('emu','unfold');
    await waitDevice(foldState,value=>value.includes('OPENED'),'unfold device state');
    await unlock();
    screenshot('03-unfolded-again');
    await verify('fold_unfold_preserves_editing',before,'Kept in bold!FU');
    before=await appendTitle('R');
    const oldOrientation=orientation();

    adb('shell','settings','put','system','accelerometer_rotation','0');
    adb('shell','settings','put','system','user_rotation',oldOrientation==='1'?'0':'1');
    const newOrientation=await waitDevice(orientation,value=>!!value && value!==oldOrientation,'rotation display orientation');
    assert(newOrientation && newOrientation!==oldOrientation,'rotation did not occur',{oldOrientation,newOrientation});
    await unlock();
    await sleep(2500);
    screenshot('04-rotated');
    await verify('rotate_preserves_editing',before,'Kept in bold!FUR');
    // A real tap focuses the installed Android input method; DOM focus alone
    // does not establish an IME transition or an active composition.
    before=await appendTitle('K');
    const bounds=await run(id,`const r=document.querySelectorAll('.ProseMirror p')[1].getBoundingClientRect();
      return {x:Math.round((r.left+Math.min(r.width/2,110))*devicePixelRatio),y:Math.round((r.top+r.height/2)*devicePixelRatio),dpr:devicePixelRatio};`);
    console.log('installed IMEs:',adb('shell','ime','list','-s'));
    adb('shell','settings','put','secure','show_ime_with_hard_keyboard','1');
    await run(id,"document.querySelector('.ProseMirror')?.blur();return {ok:true};");
    adb('shell','input','tap',String(bounds.x),String(bounds.y));
    await sleep(1500);
    const shown=ime();
    assert(shown==='true','installed Android IME did not show',{shown,bounds,imeDump:adb('shell','dumpsys','input_method').split('\n').filter(line=>/inputshown|mShowRequested|mCurMethod|mCurFocusedWindow|mInputEditorInfo/i.test(line)).slice(0,18)});
    screenshot('05-ime-shown');
    const focused=await sample(id),keyboardTop=imeTop();
    assert(focused.selected && focused.caretY>=focused.viewportTop && focused.caretY<=focused.viewportBottom &&
      keyboardTop && focused.caretBottom*bounds.dpr<keyboardTop,
      'keyboard_show_hide_keeps_caret_visible: caret outside note viewport or under the keyboard',{focused,keyboardTop});
    // Tap the system IME dismiss affordance (bottom left), not Activity Back:
    // on this AVD Back may exit the app instead of consuming the IME first.
    adb('shell','input','tap','110','2110');
    await sleep(1000);
    const hidden=ime();
    assert(hidden==='false','installed Android IME did not hide',{shown,hidden});
    screenshot('06-ime-hidden');
    const afterKeyboard=await sample(id);
    assert(afterKeyboard.title==='Kept in bold!FURK' && afterKeyboard.paragraphs[1]===focused.paragraphs[1] &&
      afterKeyboard.selected && afterKeyboard.anchor===focused.anchor && afterKeyboard.head===focused.head &&
      afterKeyboard.selection===focused.selection && afterKeyboard.caretY>=afterKeyboard.viewportTop &&
      afterKeyboard.caretY<=afterKeyboard.viewportBottom,
      'keyboard_show_hide_keeps_caret_visible: note/selection/caret changed',afterKeyboard);
    console.log(`PASS keyboard_show_hide_keeps_caret_visible (emulator evidence): ${JSON.stringify({shown,hidden,focused,afterKeyboard})}`);
    adb('shell','settings','put','secure','show_ime_with_hard_keyboard','0');
    // Hoisted below: run before the composing IME takes over the display.
    await deepScroll();
    adb('shell','settings','put','secure','show_ime_with_hard_keyboard','1');
    // This is a separately installed InputMethodService using Android's
    // InputConnection, not adb input text, execCommand or DOM event injection.
    const stockIme=adb('shell','settings','get','secure','default_input_method');
    const fixtureIme='app.basehero.continuityime/.ContinuityIme';
    const availableIme=adb('shell','ime','list','-a');
    assert(availableIme.includes('app.basehero.continuityime'),'fixture IME APK missing',availableIme);
    adb('shell','ime','enable',fixtureIme);
    adb('shell','ime','set',fixtureIme);
    await run(id,`const e=document.querySelector('.ProseMirror');window.__bhContinuityIme={starts:0,ends:0};
      e.addEventListener('compositionstart',()=>window.__bhContinuityIme.starts++);
      e.addEventListener('compositionend',()=>window.__bhContinuityIme.ends++);
      e.blur();return {ok:true};`);
    const firstBounds=await run(id,`const r=document.querySelector('.ProseMirror p').getBoundingClientRect();
      return {x:Math.round((r.right-20)*devicePixelRatio),y:Math.round((r.top+r.height/2)*devicePixelRatio)};`);
    adb('shell','input','tap',String(firstBounds.x),String(firstBounds.y));
    await run(id,`const e=document.querySelector('.ProseMirror'),p=e.querySelector('p'),last=p.lastChild,t=last.nodeType===Node.TEXT_NODE?last:last.lastChild;
      e.focus();window.getSelection().collapse(t,t.textContent.length);return {ok:t.nodeType===Node.TEXT_NODE};`);
    const imeLog=()=>adb('shell','logcat','-d','-s','BhContinuityIme:I','*:S');
    await waitDevice(imeLog,log=>log.includes('input-ready connected=true'),'fixture IME InputConnection');
    console.log('IME compose broadcast:',adb('shell','am','broadcast','-a','app.basehero.continuityime.COMPOSE','--es','text','C'));
    console.log('IME service:',imeLog());
    await until(id,`return {ok:window.__bhContinuityIme?.starts===1 && window.__bhContinuityIme?.ends===0 &&
      document.querySelector('.ProseMirror p')?.textContent==='Kept in bold!FURKC',
      events:window.__bhContinuityIme,title:document.querySelector('.ProseMirror p')?.textContent};`,
      'real InputConnection compositionstart and one pending character');
    const composingBefore=foldState();
    adb('emu','fold');
    const composingFold=await waitDevice(foldState,value=>value.includes('CLOSED'),'fold during active composition');
    assert(composingBefore.includes('OPENED'),'composition began in opened posture',composingBefore);
    // Whether the fold itself ended the composition, or it lasted until the IME finished it.
    await sleep(2000);
    const beforeFinish=await run(id,'return {...window.__bhContinuityIme};');
    adb('shell','am','broadcast','-a','app.basehero.continuityime.FINISH');
    assert(/compose=true/.test(adb('shell','logcat','-d','-s','BhContinuityIme:I','*:S')) &&
      /finish=true/.test(adb('shell','logcat','-d','-s','BhContinuityIme:I','*:S')),
      'fixture IME did not complete both InputConnection calls',adb('shell','logcat','-d','-s','BhContinuityIme:I','*:S'));
    await unlock();
    await until(id,`const s=(()=>{${state}})();return {...s,ok:s.title==='Kept in bold!FURKC' &&
      s.paragraphs[0]==='Kept in bold!FURKC' && window.__bhContinuityIme?.starts===1 && window.__bhContinuityIme?.ends===1};`,
      'real composition finished exactly once and native acknowledged title',120000);
    await run(id,'delete window.__bhContinuityRows;return {ok:true};');
    const composedRows=await nativeRows(id);
    assert(composedRows.length===1 && composedRows[0].title==='Kept in bold!FURKC' &&
      JSON.stringify(composedRows[0].note)===JSON.stringify(note),
      'fold_during_composition: native catalogue missing composed text or note ID',composedRows);
    console.log(`PASS fold_during_composition (emulator evidence): ${JSON.stringify({composingBefore,composingFold,beforeFinish,
      composition:beforeFinish.ends===0?'survived the fold':'ended by the fold',
      events:await run(id,'return window.__bhContinuityIme;'),nativeTitle:composedRows[0].title})}`);
    adb('emu','unfold');
    await waitDevice(foldState,value=>value.includes('OPENED'),'unfold after composition');
    await unlock();
    // Restore the installed keyboard and dismiss it before screen-visible checks.
    await run(id,"document.querySelector('.ProseMirror')?.blur();return {ok:true};");
    adb('shell','ime','set',stockIme);
    adb('shell','settings','put','secure','show_ime_with_hard_keyboard','0');
    await waitDevice(ime,value=>value==='false','hide fixture IME before deep scroll');
    await unlock();
    // System settings a person may change while writing. Tauri on Android
    // binds its plugins (this WebDriver included) and every native reply to
    // the first WebView, so a recreated MainActivity would orphan this page
    // and load a second copy. Each change must keep the same Activity
    // instance, the same page and its native acknowledgements.
    const instrumentation=()=>adb('shell','logcat','-d','-s','BhContinuityActivity:I','*:S');
    const instances=()=>[...new Set([...instrumentation().matchAll(/resumed activity=(\d+)/g)].map(m=>m[1]))];
    const livePid=pid();
    assert(instrumentation().includes(`ready pid=${livePid}`),'instrumentation not in before-state process',instrumentation());
    const text="const p=document.querySelector('.ProseMirror p');return {page:window.__bhContinuityPage,visible:document.visibilityState,"+
      "fontSize:parseFloat(getComputedStyle(p).fontSize),width:innerWidth*devicePixelRatio,dpr:devicePixelRatio,"+
      "mode:document.documentElement.dataset.mode};";
    await run(id,'window.__bhContinuityPage=String(performance.timeOrigin);return {ok:true};');
    const palette=`'{"android.theme.customization.system_palette":"B3261E","android.theme.customization.theme_style":"TONAL_SPOT"}'`;
    const changes=[
      ['night mode','N','cmd uimode night yes','cmd uimode night no'],
      ['font size','S','settings put system font_scale 1.3','settings put system font_scale 1.0'],
      ['display size','D','wm density 300','wm density reset'],
      ['bold text','W','settings put secure font_weight_adjustment 300','settings delete secure font_weight_adjustment'],
      ['right-to-left app language','L','cmd locale set-app-locales app.basehero.client --locales ar-EG',
        'cmd locale set-app-locales app.basehero.client --locales en-US'],
      ['wallpaper colours','P',`settings put secure theme_customization_overlay_packages ${palette}`,
        'settings delete secure theme_customization_overlay_packages'],
    ];
    let title='Kept in bold!FURKC';
    for (const [label,suffix,change,restore] of changes) {
      const scenario=`system_settings_keep_editing (${label})`;
      before=await appendTitle(suffix);title+=suffix;
      const known=instances(),prior=await run(id,text);
      adb('shell',change);
      await sleep(4000);
      await unlock();
      const now=await run(id,text);
      assert(JSON.stringify(instances())===JSON.stringify(known) && pid()===livePid,
        `${scenario}: MainActivity was recreated`,{known,now:instances(),livePid,pid:pid()});
      assert(now.page===prior.page && now.visible==='visible',`${scenario}: page replaced or hidden`,{prior,now});
      // The page still fills the same window in device pixels, at any density.
      assert(Math.abs(now.width-prior.width)<=2*now.dpr,`${scenario}: page no longer fills the window`,{prior,now});
      if(suffix==='S')assert(now.fontSize>=prior.fontSize*1.2,`${scenario}: text ignored the system font size`,{prior,now});
      if(suffix==='D')assert(now.dpr<prior.dpr,`${scenario}: display density did not change`,{prior,now});
      if(suffix==='N')assert(prior.mode==='light' && now.mode==='dark',`${scenario}: page did not follow night mode`,{prior,now});
      await verify(scenario,before,title);
      adb('shell',restore);
      await sleep(3000);
      await unlock();
      assert(JSON.stringify(instances())===JSON.stringify(known),`${scenario}: restoring recreated MainActivity`,
        {known,now:instances()});
      if(suffix==='N') {
        const restored=await run(id,text);
        assert(restored.mode==='light' && restored.page===prior.page,`${scenario}: page did not return to day mode`,{prior,restored});
        console.log(`PASS night_mode_round_trip: ${JSON.stringify({page:prior.page,modes:[prior.mode,now.mode,restored.mode]})}`);
      }
    }
    async function deepScroll() {
    assert(ime()==='false','deep_scroll: IME obscures app before fixture',ime());
    // A lower selection in a genuinely scrollable note catches continuity
    // failures that the short, scrollTop=0 fixture cannot expose.
    const tallLines=Array.from({length:48},(_,index)=>
      `Deep scroll paragraph ${String(index+1).padStart(2,'0')}: Every device posture must keep this selected line visible while the note stays long enough to scroll.`);
    const tallSetup=await run(id,`const e=document.querySelector('.ProseMirror'),s=window.getSelection();e.focus();
      s.collapse(e.lastElementChild,e.lastElementChild.childNodes.length);
      let ok=true;
      for(const line of ${JSON.stringify(tallLines)}){
        ok=document.execCommand('insertParagraph')&&ok;
        ok=document.execCommand('insertText',false,line)&&ok;
      }
      const pane=e.closest('.note-pane'),p=e.querySelectorAll(':scope > p')[38];
      const walker=document.createTreeWalker(p,NodeFilter.SHOW_TEXT);let t;
      while(walker.nextNode())if(walker.currentNode.textContent.includes('paragraph')){t=walker.currentNode;break;}
      if(t?.textContent.startsWith('Deep scroll paragraph'))s.setBaseAndExtent(t,12,t,21);
      p.scrollIntoView({block:'center'});
      return {ok:ok&&s.toString()==='paragraph',count:e.querySelectorAll(':scope > p').length,
        target:p.innerHTML,selected:s.toString(),scrollTop:pane.scrollTop,
        scrollHeight:pane.scrollHeight,clientHeight:pane.clientHeight};`);
    assert(tallSetup.ok && tallSetup.count===50,'could not prepare tall note and lower selection',tallSetup);
    const tallTitle='Kept in bold!FURK';
    await until(id,`const s=(()=>{${state}})();return {...s,ok:s.title===${JSON.stringify(tallTitle)} &&
      s.paragraphs.length===50 && s.paragraphs[38]===${JSON.stringify(tallLines[36])} && s.status==='Saved on this device'};`,
      'deep_scroll native acknowledged tall note',120000);
    const tallBefore=await sample(id);
    const caretVisible=s=>s.caretY>=s.viewportTop && s.caretBottom<=s.viewportBottom &&
      s.caretY>=0 && s.caretBottom<=s.screenHeight;
    assert(tallBefore.scrollHeight>tallBefore.clientHeight && tallBefore.scrollTop>tallBefore.lineHeight*3 &&
      caretVisible(tallBefore),'deep_scroll: selection must begin below the fold and on screen',tallBefore);
    const verifyTall=async(label,prior)=>{
      // Each of these transitions changes the pane width; wait until the page
      // has relaid out rather than sample it before (or behind the keyguard).
      for (const end=Date.now()+20000;Date.now()<end;await sleep(500)) {
        await unlock();
        if (Math.abs((await sample(id)).viewportWidth-prior.viewportWidth)>1) break;
      }
      await sleep(500);
      await run(id,"document.querySelector('.ProseMirror')?.focus();return {ok:true};");
      const next=await sample(id);
      assert(JSON.stringify(next.paragraphs)===JSON.stringify(tallBefore.paragraphs) &&
        JSON.stringify(next.bold)===JSON.stringify(tallBefore.bold) && next.title===tallTitle,
        `${label}: deep-scroll text/marks/current note changed`,{prior,next});
      assert(next.selected && next.anchor===tallBefore.anchor && next.head===tallBefore.head &&
        next.anchorText===tallBefore.anchorText && next.headText===tallBefore.headText &&
        next.selection===tallBefore.selection,`${label}: deep-scroll selection changed`,{prior,next});
      assert(ime()==='false' && next.scrollTop>0 && caretVisible(next),
        `${label}: selected line or caret left the unobscured viewport`,{ime:ime(),prior,next});
      // Rewrapping changes line geometry; require actual reflow and an
      // in-view caret rather than an absolute screen-Y match.
      const reflow=Math.abs(next.viewportWidth-prior.viewportWidth)>1;
      assert(reflow,`${label}: pane width did not change`,{prior,next});
      await run(id,'delete window.__bhContinuityRows;return {ok:true};');
      const current=await nativeRows(id);
      assert(current.length===1 && JSON.stringify(current[0].note)===JSON.stringify(note) && current[0].title===tallTitle,
        `${label}: native current note changed`,current);
      console.log(`PASS ${label} (emulator evidence): ${JSON.stringify({scrollTop:next.scrollTop,
        scrollHeight:next.scrollHeight,clientHeight:next.clientHeight,caretY:next.caretY,
        viewportTop:next.viewportTop,viewportBottom:next.viewportBottom,reflow,
        anchor:next.anchor,head:next.head,fold:foldState(),orientation:orientation()})}`);
      return next;
    };
    screenshot('08-deep-opened');
    adb('emu','fold');
    await waitDevice(foldState,value=>value.includes('CLOSED'),'deep_scroll fold device state');
    let tallPrior=await verifyTall('deep_scroll_fold',tallBefore);
    screenshot('09-deep-folded');
    // Also exercise the outer display's short landscape viewport, where
    // a line close to the clipping edge needs a little clearance.
    const foldedOrientation=orientation();
    adb('shell','settings','put','system','user_rotation',foldedOrientation==='90'?'0':'1');
    await waitDevice(orientation,value=>!!value && value!==foldedOrientation,'deep_scroll rotate folded display');
    tallPrior=await verifyTall('deep_scroll_folded_rotate',tallPrior);
    screenshot('16-deep-folded-rotated');
    adb('emu','unfold');
    await waitDevice(foldState,value=>value.includes('OPENED'),'deep_scroll unfold device state');
    tallPrior=await verifyTall('deep_scroll_unfold',tallPrior);
    screenshot('10-deep-unfolded');
    const deepOrientation=orientation();
    adb('shell','settings','put','system','user_rotation',deepOrientation==='90'?'0':'1');
    await waitDevice(orientation,value=>!!value && value!==deepOrientation,'deep_scroll rotate display orientation');
    await sleep(2500);
    await verifyTall('deep_scroll_rotate',tallPrior);
    screenshot('11-deep-rotated');
    // Return to the orientation/short selection expected by the keyboard and
    // composition probes, without altering the tall note's saved content.
    adb('shell','settings','put','system','user_rotation',deepOrientation==='90'?'1':'0');
    await waitDevice(orientation,value=>value===deepOrientation,'restore orientation after deep scroll');
    await unlock();
    await deepScrollReader();
    await keyboardLowCaret();
    const shortSelection=await select();
    await run(id,"document.querySelector('.note-pane').scrollTop=0;return {ok:true};");
    assert(shortSelection.selected && shortSelection.selection==='sec','restore short selection after deep scroll',shortSelection);
    }
    // A person who scrolled away from the caret to read keeps their place
    // when the pane rewraps; only a caret that was on screen is brought back.
    async function deepScrollReader() {
      const reading=`const pane=document.querySelector('.note-pane'),r=pane.getBoundingClientRect();
        const ps=[...document.querySelectorAll('.ProseMirror > p')],s=window.getSelection();
        const top=ps.findIndex(p=>p.getBoundingClientRect().bottom>r.top+1);
        const c=s.rangeCount?s.getRangeAt(0).getBoundingClientRect():null;
        return {top,offset:ps[top]?.getBoundingClientRect().top-r.top,scrollTop:pane.scrollTop,
          paneTop:r.top,paneBottom:r.bottom,width:r.width,x:r.left+r.width/2,dpr:devicePixelRatio,
          caretVisible:!!c && c.bottom>r.top && c.top<r.bottom,anchor:s.anchorOffset,head:s.focusOffset,
          selection:s.toString()};`;
      const refocus="document.querySelector('.ProseMirror')?.focus({preventScroll:true});return {ok:true};";
      // Start this independent reading scenario with the selected paragraph
      // centred after restoring orientation; then scroll it off screen ourselves.
      await sleep(1500);
      await run(id,refocus);
      await run(id,"document.querySelectorAll('.ProseMirror > p')[38].scrollIntoView({block:'center'});return {ok:true};");
      await sleep(500);
      let start=await run(id,reading);
      assert(start.caretVisible && start.selection==='paragraph','deep_scroll_reader: caret must start on screen',start);
      // Real touch scrolls toward the top of the note until the caret is off screen.
      for (let i=0;i<3 && start.caretVisible;i++) {
        const x=String(Math.round(start.x*start.dpr)),height=start.paneBottom-start.paneTop;
        adb('shell','input','swipe',x,String(Math.round((start.paneTop+height*0.2)*start.dpr)),
          x,String(Math.round((start.paneTop+height*0.8)*start.dpr)),'800');
        await sleep(1500);
        start=await run(id,reading);
      }
      assert(!start.caretVisible && start.selection==='paragraph','deep_scroll_reader: swipe must leave the caret off screen',start);
      screenshot('12-reader-scrolled');
      let prior=start;
      for (const [label,command,desired] of [['deep_scroll_reader_fold','fold','CLOSED'],['deep_scroll_reader_unfold','unfold','OPENED']]) {
        adb('emu',command);
        await waitDevice(foldState,value=>value.includes(desired),`${label} device state`);
        // The keyguard may appear a moment after the posture changes; the
        // page relayouts only once the app is in front again.
        let after;
        for (const end=Date.now()+20000;Date.now()<end;await sleep(500)) {
          await unlock();
          after=await run(id,reading);
          if (Math.abs(after.width-prior.width)>1) break;
        }
        assert(Math.abs(after.width-prior.width)>1,`${label}: pane width did not change`,{prior,after});
        await sleep(1000);
        await run(id,refocus);
        after=await run(id,reading);
        assert(after.anchor===start.anchor && after.head===start.head && after.selection==='paragraph',
          `${label}: selection changed`,{prior,after});
        assert(Math.abs(after.top-start.top)<=1 && !after.caretVisible,
          `${label}: reading position jumped instead of staying near paragraph ${start.top}`,{start,prior,after});
        console.log(`PASS ${label} (emulator evidence): ${JSON.stringify({readingParagraph:[start.top,after.top],
          scrollTop:after.scrollTop,width:[prior.width,after.width],caretVisible:after.caretVisible,fold:foldState()})}`);
        prior=after;
      }
      screenshot('13-reader-unfolded');
    }
    // The installed keyboard must not cover a caret placed low in the note,
    // nor the lines typed after it; Android draws this app edge to edge.
    async function keyboardLowCaret() {
      // The editor keeps its selection when it regains focus, so put the
      // caret on the low line first; the real tap then brings up the keyboard there.
      const target=await run(id,`const e=document.querySelector('.ProseMirror'),pane=e.closest('.note-pane'),r=pane.getBoundingClientRect();
        const line=parseFloat(getComputedStyle(e).lineHeight);
        const ps=[...e.querySelectorAll(':scope > p')];
        const p=ps.find(p=>{const b=p.getBoundingClientRect();return b.top>r.top && b.top<r.bottom-line*2 && b.top>r.top+(r.bottom-r.top)*0.75;});
        const b=p?.getBoundingClientRect(),t=p&&document.createTreeWalker(p,NodeFilter.SHOW_TEXT).nextNode();
        if(t){e.focus({preventScroll:true});window.getSelection().collapse(t,4);}
        return {ok:!!t,index:ps.indexOf(p),x:Math.round((b?.left+40)*devicePixelRatio),
          y:Math.round((b?.top+line/2)*devicePixelRatio),dpr:devicePixelRatio,paneBottom:r.bottom};`);
      assert(target.ok,'keyboard_low_caret: no line in the lower quarter of the pane',target);
      await sleep(300);
      await run(id,"document.querySelector('.ProseMirror').blur();return {ok:true};");
      adb('shell','settings','put','secure','show_ime_with_hard_keyboard','1');
      adb('shell','input','tap',String(target.x),String(target.y));
      await waitDevice(()=>ime()==='true' && imeTop(),value=>!!value,'keyboard_low_caret: installed IME shown');
      await sleep(1500);
      const caret=`const s=window.getSelection(),c=s.rangeCount?s.getRangeAt(0).getBoundingClientRect():null;
        const r=document.querySelector('.note-pane').getBoundingClientRect();
        return {ok:!!c && c.height>0,top:c?.top,bottom:c?.bottom,paneTop:r.top,paneBottom:r.bottom,
          inner:innerHeight,dpr:devicePixelRatio,text:s.anchorNode?.textContent?.slice(0,24),
          paragraph:[...document.querySelectorAll('.ProseMirror > p')].findIndex(p=>p.contains(s.anchorNode))};`;
      const check=async label=>{
        const at=await until(id,caret,`${label}: caret rectangle`),keyboardTop=imeTop();
        assert(keyboardTop && at.bottom*at.dpr<keyboardTop && at.top>=at.paneTop && at.bottom<=at.paneBottom,
          `${label}: caret hidden by the keyboard or outside the note pane`,{at,keyboardTop,target});
        console.log(`PASS ${label} (emulator evidence): ${JSON.stringify({caretBottomPx:Math.round(at.bottom*at.dpr),
          keyboardTop,paragraph:at.paragraph,paneBottom:at.paneBottom,innerHeight:at.inner,orientation:orientation()})}`);
        return at;
      };
      const tapped=await check('keyboard_low_caret_visible');
      assert(tapped.paragraph===target.index,'keyboard_low_caret: tap did not place the caret in the low line',{tapped,target});
      screenshot('14-ime-low-caret');
      // Each new line moves the caret further down; typing must keep it in view.
      for (let i=0;i<4;i++) {
        adb('shell','input','keyevent','KEYCODE_ENTER');
        adb('shell','input','text','Low');
      }
      await sleep(1000);
      const typed=await check('keyboard_typing_low_caret_visible');
      assert(typed.paragraph===target.index+4 && typed.text.startsWith('Low'),
        'keyboard_low_caret: typing did not land at the caret',{typed,target});
      screenshot('15-ime-typed-low');
      // Leaving the editor hides the keyboard in any orientation.
      await run(id,"document.querySelector('.ProseMirror').blur();return {ok:true};");
      await waitDevice(ime,value=>value==='false','keyboard_low_caret: installed IME hidden');
      adb('shell','settings','put','secure','show_ime_with_hard_keyboard','0');
    }
    // Activity.recreate() itself stays unsupported by Tauri: it loads a new
    // page in a second WebView while plugins keep the first. Prove only that
    // it loses no acknowledged work: the new page on screen shows it, and the
    // reopen phase compares durable content with this acknowledged state.
    before=await appendTitle('A');title+='A';
    await verify('forced_recreate_keeps_saved_work (acknowledged before)',before,title);
    const acked=await sample(id);
    writeFileSync(record,JSON.stringify({note,paragraphs:acked.paragraphs,bold:acked.bold,title:acked.title}));
    adb('shell','am','broadcast','-a','app.basehero.continuitytest.RECREATE');
    const lifecycle=await waitDevice(instrumentation,value=>/recreated before=\d+ after=\d+ pid=\d+/.test(value),
      'instrumentation Activity.recreate completion');
    const [,beforeInstance,afterInstance,instrumentPid]=lifecycle.match(/recreated before=(\d+) after=(\d+) pid=(\d+)/);
    assert(beforeInstance!==afterInstance && instrumentPid===livePid && pid()===livePid,
      'Activity.recreate did not replace instance in the same live process',{beforeInstance,afterInstance,livePid,pid:pid()});
    const onScreen=await waitDevice(()=>{
      try {adb('shell','uiautomator','dump','/sdcard/bh-continuity.xml');return adb('shell','cat','/sdcard/bh-continuity.xml');}
      catch {return '';}
    },xml=>xml.includes(`text="${title}"`) && /saved on this device/i.test(xml),'forced recreation: new page shows acknowledged note');
    screenshot('07-forced-recreate-new-page');
    console.log(`PASS forced_recreate_keeps_saved_work (emulator evidence): ${JSON.stringify({beforeInstance,afterInstance,pid:livePid,title,onScreen:onScreen.length})}`);
  }
} finally {
  if(fingers)clearInterval(fingers);
  if(id)await call('DELETE',`/session/${id}`).catch(()=>{});
}
