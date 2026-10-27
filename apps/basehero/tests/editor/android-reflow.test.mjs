import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Exercise the actual editor closures with deterministic layout and animation frames.
const source=readFileSync(new URL('../../src/lib/editor/editor.mjs',import.meta.url),'utf8');
const implementation=source.slice(source.indexOf('  const android=/Android/i.test(navigator.userAgent);'),source.indexOf('  const pointerDown=event=>'));
assert.match(implementation,/const relayout=/);
function setup(android=true) {
  let blockHeight=100, width=400, scrollTop=2800, writes=0;
  const frames=[];
  const bounds={top:80,bottom:680,height:600};
  const blocks=Array.from({length:50},(_,index)=>({isConnected:true,getBoundingClientRect(){const top=80+index*blockHeight-scrollTop;return {top,bottom:top+blockHeight,height:blockHeight};}}));
  const area={get scrollTop(){return scrollTop;},set scrollTop(value){scrollTop=value;writes++;},getBoundingClientRect(){return bounds;}};
  const editor={state:{selection:{head:5}},view:{dom:{children:blocks},coordsAtPos(){const top=80+5*blockHeight-scrollTop;return {top,bottom:top+20};}}};
  const context={navigator:{userAgent:android?'Android':'Macintosh'},innerWidth:width,innerHeight:800,editor,closed:false,
    scroller:()=>area,placeBubble(){},placeLink(){},queueMicrotask:cb=>queueMicrotask(cb),requestAnimationFrame:cb=>frames.push(cb)};
  const {noteView,relayout,onScroll,onUserIntent,onSelectionIntent}=vm.runInNewContext(`(()=>{${implementation}\nreturn {noteView,relayout,onScroll,onUserIntent:typeof onUserIntent==='function'?onUserIntent:()=>{},onSelectionIntent};})()`,context);
  const frame=()=>{assert.ok(frames.length,'expected frame');frames.shift()();};
  noteView();
  return {context,frame,frames,relayout,get scrollTop(){return scrollTop;},get writes(){return writes;},resize(w,height){width=w;blockHeight=height;context.innerWidth=width;relayout();},scroll(value){onUserIntent();scrollTop=value;onScroll();},layoutScroll(value){scrollTop=value;onScroll();},select(){onSelectionIntent();}};
}

test('newer Android scroll during two-frame restoration wins over old reading anchor',()=>{
  const h=setup();h.resize(350,150);h.frame();h.scroll(3000);h.frame();
  assert.equal(h.scrollTop,3000);
  assert.equal(h.frames.length,0);
});

test('layout-triggered scroll during resize does not discard the pre-reflow anchor',()=>{
  const h=setup();h.resize(350,150);h.frame();h.layoutScroll(2800);h.frame();
  assert.equal(h.scrollTop,4200);
});

test('selection intent during two-frame restoration discards old reading anchor',()=>{
  const h=setup();h.resize(350,150);h.frame();h.select();h.frame();
  assert.equal(h.scrollTop,2800);
});

test('second resize keeps original pre-reflow anchor through intermediate layout',()=>{
  const h=setup();h.resize(350,150);h.frame();h.resize(300,180);
  while(h.frames.length)h.frame();
  assert.equal(h.scrollTop,28*180);
  assert.equal(h.writes,1,'only the latest restoration may write to the scroller');
});

test('desktop UA never schedules restoration frames',()=>{
  const h=setup(false);h.resize(350,150);assert.equal(h.frames.length,0);
});
