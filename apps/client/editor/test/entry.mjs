import * as Y from 'yjs';
import {createNoteEditor} from '/note-editor.js';
let view,doc,listener,jobs=[],boldUpdate,opens=0,writers=[],openOptions=[],autoAck=false,peersCb=null;
const NATIVE=2002468231004600, LAST=2**32-1;
const varUint=(n,out)=>{while(n>=128){out.push(n%128+128);n=Math.floor(n/128);}out.push(n);return out;};
function element(name,text,attrs={}) {
  const el=new Y.XmlElement(name);for(const [key,value] of Object.entries(attrs))el.setAttribute(key,value);
  if(text!==null) {const inner=new Y.XmlText();inner.insert(0,text);el.insert(0,[inner]);}
  return el;
}
// Paragraphs of 998 units (1,000 positions each) filling a document of exactly
// `positions` ProseMirror positions, including the document's own two.
function sized(fragment,positions) {
  let rest=positions-2;const blocks=[];
  while(rest>=1000+1002) {blocks.push(998);rest-=1000;}
  blocks.push(rest-2);
  fragment.insert(0,blocks.map(units=>element('paragraph',units?'s'.repeat(units):null)));
}
function initial(kind,options={}) {
  doc=new Y.Doc();boldUpdate=null; const fragment=doc.getXmlFragment('default');
  if(kind==='sized') sized(fragment,options.positions);
  if(kind==='concurrentBold'||kind==='concurrentBoldReverse') {
    fragment.insert(0,[element('paragraph','abcdefgh')]);
    const base=Y.encodeStateAsUpdate(doc),before=Y.encodeStateVector(doc);
    const peer=new Y.Doc();Y.applyUpdate(peer,base);
    fragment.get(0).get(0).format(kind==='concurrentBold'?0:5,2,{bold:{}});
    peer.getXmlFragment('default').get(0).get(0).format(kind==='concurrentBold'?5:0,2,{bold:{}});
    boldUpdate=Y.encodeStateAsUpdate(peer,before);
    peer.destroy();
  }
  // Distinct paragraphs long enough to wrap differently at another width.
  if(kind==='lines') fragment.insert(0,Array.from({length:options.count??300},(_,i)=>
    element('paragraph',`line ${i} `+'words to wrap across a narrower window '.repeat(i%3+1))));
  if(kind==='rich') fragment.insert(0,[element('paragraph','intro'),element('heading','headline',{level:2})]);
  if(kind==='sentence') fragment.insert(0,[element('paragraph','The quick brown fox jumps over the lazy dog.')]);
  // Another device's copy of a note: exactly the host bytes it was given.
  if(kind==='bytes') Y.applyUpdate(doc,Uint8Array.from(options.bytes));
  if(kind==='spaces'||kind==='spacesUnknown') fragment.insert(0,[element('paragraph','a  b')]);
  if(kind==='spacesUnknown') fragment.insert(1,[element('futureWidget','private',{payload:'keep'})]);
  if(kind==='racing') fragment.insert(0,[element('paragraph','before')]);
  if(kind==='node') fragment.insert(0,[element('futureWidget','private',{payload:'keep'})]);
  if(kind==='attr') fragment.insert(0,[element('paragraph','private',{futureAttr:'keep'})]);
  if(kind==='value') fragment.insert(0,[element('heading','private',{level:4})]);
  if(kind==='invalidStructure') {const list=element('bulletList',null);list.insert(0,[element('listItem',null)]);fragment.insert(0,[list]);}
  if(kind==='mark'||kind==='textAttr') {const p=element('paragraph',null);const t=new Y.XmlText();t.insert(0,'private',kind==='mark'?{futureMark:{secret:'keep'}}:{});if(kind==='textAttr')t.setAttribute('futureTextAttr','keep');p.insert(0,[t]);fragment.insert(0,[p]);}
}
window.harness={
  // Each native open hands out the next writer; `room` makes it a reused
  // writer whose earlier clocks are already durable (one GC run).
  async open(kind,options={}) {
    view?.close();jobs=[];listener=null;opens=0;openOptions=[];peersCb=null;if(kind!=='existing')initial(kind,options);
    writers=options.writers??[{id:NATIVE}];
    view=await createNoteEditor(document.querySelector('#root'),{
      open:async (callback,requested)=>{
        listener=callback;openOptions.push(requested??null);
        const writer=writers[Math.min(opens++,writers.length-1)];
        if(writer.room!==undefined && Y.getState(doc.store,writer.id)===0)
          Y.applyUpdate(doc,new Uint8Array([1,1,...varUint(writer.id,[]),0,0,...varUint(LAST-writer.room,[]),0]));
        const state=Y.encodeStateAsUpdate(doc);
        if(kind==='racing') {
          const before=Y.encodeStateVector(doc);
          doc.getXmlFragment('default').insert(1,[element('paragraph','while opening')]);
          callback(Y.encodeStateAsUpdate(doc,before));
        }
        return {clientId:writer.id,state,unsubscribe:()=>{listener=null;}};
      },
      commit:(bytes,id)=>{
        if(autoAck){Y.applyUpdate(doc,bytes);return Promise.resolve({requestId:id});}
        return new Promise((resolve,reject)=>jobs.push({bytes,id,resolve,reject}));
      },
      onPeers(callback){peersCb=callback;return ()=>{peersCb=null;};},
    },options.view?{view:options.view}:undefined);
    return {...view.state(),writes:jobs.length};
  },
  pending:()=>jobs.length,
  // Every later commit is durably applied to the host and acknowledged at once.
  autoAck(on=true){autoAck=on;while(on&&jobs.length)this.ack();},
  // Exact text attribute keys the host holds, block by block.
  hostMarks:()=>doc.getXmlFragment('default').toArray().flatMap(block=>block.toArray()
    .filter(node=>node instanceof Y.XmlText).flatMap(text=>text.toDelta().map(run=>Object.keys(run.attributes??{}).sort()))),
  mode:()=>view.state().mode,
  text:()=>document.querySelector('.ProseMirror').textContent,
  undoDepth(){const e=document.querySelector('.ProseMirror').editor;
    return e.state.plugins.map(pl=>pl.getState(e.state)).find(st=>st?.undoManager)?.undoManager.undoStack.length;},
  clearAll(){const editor=document.querySelector('.ProseMirror').editor;editor.chain().selectAll().deleteSelection().run();},
  // Composition text arrives as a DOM mutation, as an IME's does.
  insertDOM(text,after){
    const blocks=[...document.querySelectorAll('.ProseMirror p')];
    (blocks.find(p=>after && p.textContent.includes(after))??blocks.at(-1)).append(document.createTextNode(text));
  },
  positions:()=>document.querySelector('.ProseMirror').editor.state.doc.nodeSize,
  notice:()=>{const el=document.querySelector('#root [role=alert]');return el&&!el.hidden?el.textContent:'';},
  // A peer's paragraph of `units` characters, or deletion of `units` from the end.
  incomingSized(units){
    const before=Y.encodeStateVector(doc),frag=doc.getXmlFragment('default');
    if(units>0) frag.insert(frag.length,[element('paragraph','r'.repeat(units))]);
    else {const text=frag.get(frag.length-1).get(0);text.delete(text.length+units,-units);}
    listener(Y.encodeStateAsUpdate(doc,before));return view.state();
  },
  opens:()=>opens,
  openOptions:()=>openOptions,
  reacquire:()=>view.reacquire(),
  status:()=>document.querySelector('[data-status]').textContent,
  // The real paste pipeline (transforms, slices), minus the clipboard event.
  paste(text){document.querySelector('.ProseMirror').editor.view.pasteText(text);},
  select(text){
    const editor=document.querySelector('.ProseMirror').editor;let from=-1;
    editor.state.doc.descendants((node,pos)=>{if(from<0&&node.isText&&node.text.includes(text))from=pos+node.text.indexOf(text);});
    editor.commands.setTextSelection({from,to:from+text.length});
  },
  // PM's own selection, not the asynchronously observed DOM selection.
  caret(text){
    const editor=document.querySelector('.ProseMirror').editor;let at=-1;
    editor.state.doc.descendants((node,pos)=>{if(at<0&&node.isText&&node.text.includes(text))at=pos+node.text.indexOf(text)+text.length;});
    editor.commands.setTextSelection(at);
  },
  // The start of the first paragraph's text, as a caret.
  caretAtStart(){document.querySelector('.ProseMirror').editor.commands.setTextSelection(1);},
  heading:()=>document.querySelector('.ProseMirror h2').textContent,
  // Clocks one supported edit actually used, against the bound checked first.
  measure(cost){
    const editor=document.querySelector('.ProseMirror').editor;
    const live=editor.state.plugins.map(p=>p.getState(editor.state)).find(s=>s?.type?.doc)?.type.doc;
    const steps={
      pasteHTML:e=>e.view.pasteHTML('<p>one <strong>two</strong> <em>three</em></p><ul><li><p>a</p><ul><li><p>b</p></li></ul></li></ul><h3>head</h3><blockquote><p>q<br>r</p></blockquote>'),
      bold:e=>e.chain().selectAll().toggleBold().run(),
      link:e=>e.chain().selectAll().setLink({href:'https://example.com'}).run(),
      unmark:e=>e.chain().selectAll().unsetAllMarks().run(),
      split:e=>e.chain().setTextSelection(3).splitBlock().run(),
      join:e=>e.chain().setTextSelection(e.state.doc.child(0).nodeSize+1).joinBackward().run(),
      bullet:e=>e.chain().selectAll().toggleBulletList().run(),
      task:e=>e.chain().selectAll().toggleTaskList().run(),
      heading:e=>e.chain().setTextSelection(2).toggleHeading({level:1}).run(),
      quote:e=>e.chain().selectAll().toggleBlockquote().run(),
      ordered:e=>e.chain().selectAll().toggleOrderedList().run(),
      hardBreak:e=>e.chain().setTextSelection(3).setHardBreak().run(),
      clear:e=>e.chain().selectAll().deleteSelection().run(),
    };
    return Object.entries(steps).map(([name,step])=>{
      const before=Y.getState(live.store,live.clientID),ran=step(editor)!==false;
      return {name,ran,used:Y.getState(live.store,live.clientID)-before,bound:3*cost*editor.state.doc.nodeSize+1};
    });
  },
  allStructs:()=>jobs.flatMap(job=>Y.decodeUpdate(job.bytes).structs.map(s=>[s.id.client,s.id.clock,s.length])),
  inFlightStructs:()=>Y.decodeUpdate(jobs[0].bytes).structs.map(s=>[s.id.client,s.id.clock,s.length]),
  inFlight:()=>jobs[0]?{id:jobs[0].id,bytes:Array.from(jobs[0].bytes)}:null,
  close(){view.close();},
  ack(id) {const job=jobs.shift();if(!job)throw Error('no pending commit');if(id===undefined)Y.applyUpdate(doc,job.bytes);job.resolve({requestId:id??job.id});},
  reject(){const job=jobs.shift();if(!job)throw Error('no pending commit');job.reject(Error('disk full'));},
  retry(){view.retry();},
  drain(ms=1000,reason){window.drained=undefined;const done=view.drain(Date.now()+ms,reason);
    done.then(result=>{window.drained=result;});return true;},
  resume(){view.resume();},
  hold(reason){view.hold(reason);},
  view(){return view.view();},
  // A remote device's message, exactly as the native peer path delivers it.
  remote(message){if(!peersCb)throw Error('no peer listener');peersCb(message);return true;},
  // The production encoder for a selection covering `text`.
  relativeSelection(text){
    this.select(text);
    const {anchor,head}=this.view();
    return {anchor,head};
  },
  // The text position a remote caret is drawn over: the point in the middle
  // of its 2 px line, as the reader sees it.
  peerPoint(id){
    const cursor=document.querySelector(`.bh-remote-cursor[data-peer="${id}"]`);
    if(!cursor)return null;
    const box=cursor.getBoundingClientRect();
    return {cursor,at:document.caretRangeFromPoint(box.left+1,box.top+box.height/2)};
  },
  // Where a remote caret actually renders: text before the caret and the
  // words its selection covers.
  peerAt(id){
    const root=document.querySelector('.ProseMirror'),drawn=this.peerPoint(id);
    if(!root || !drawn?.at)return null;
    const {cursor,at}=drawn;
    const before=document.createRange();before.setStart(root,0);before.setEnd(at.startContainer,at.startOffset);
    const covered=root.querySelector(`.bh-remote-selection[data-peer="${id}"]`);
    return {before:before.toString(),selection:covered?.textContent??'',label:cursor.querySelector('.bh-remote-label')?.textContent??'',colour:cursor.style.getPropertyValue('--peer')};
  },
  // The note's block (top-level index) a remote caret is drawn on.
  peerBlock(id){
    const root=document.querySelector('.ProseMirror'),at=this.peerPoint(id)?.at;
    return at?[...root.children].findIndex(block=>block.contains(at.startContainer)):null;
  },
  // The geometry a remote caret actually renders: the caret's own box, its
  // label's box, and where the text after it starts on the line. The text
  // position proves a collapsed label does not move the line under it.
  caretBox(id='mac'){
    const root=document.querySelector('.ProseMirror'),drawn=this.peerPoint(id);
    if(!root || !drawn?.at)return null;
    const {cursor,at}=drawn;
    const label=cursor.querySelector('.bh-remote-label');
    const box=element=>{const {width,height}=element.getBoundingClientRect();return {width:Math.round(width*100)/100,height:Math.round(height*100)/100};};
    const after=document.createRange();after.setStart(at.startContainer,at.startOffset);after.setEnd(root,root.childNodes.length);
    return {cursor:box(cursor),label:box(label),textLeft:Math.round(after.getBoundingClientRect().left)};
  },
  // The note text an Android keyboard reads: the editable's own text, and
  // the text before this window's caret.
  editableText(){
    const root=document.querySelector('.ProseMirror'),selection=getSelection();
    const before=document.createRange();before.setStart(root,0);before.setEnd(selection.focusNode,selection.focusOffset);
    return {all:root.textContent,before:before.toString()};
  },
  // A peer's batch insertion into a paragraph's text, delivered as an update.
  incomingText(index,offset,text){
    const before=Y.encodeStateVector(doc);
    doc.getXmlFragment('default').get(index).get(0).insert(offset,text);
    listener(Y.encodeStateAsUpdate(doc,before));
  },
  // A peer's insertion at an offset around text this copy already has.
  incomingAtText(match,offset,text){
    const before=Y.encodeStateVector(doc);
    const frag=doc.getXmlFragment('default');
    for(let index=0;index<frag.length;index++){
      const inner=frag.get(index)?.get?.(0);
      const value=inner?.toString?.()??'';
      if(!value.includes(match))continue;
      inner.insert(value.indexOf(match)+offset,text);
      listener(Y.encodeStateAsUpdate(doc,before));
      return index;
    }
    throw Error('text not found: '+match);
  },
  incomingBytes(bytes){listener(Uint8Array.from(bytes));return view.state();},
  // Relative positions that name an item this copy has not received yet,
  // plus the update that carries it: a remote device's newest paragraph.
  futureRelative(text){
    const peer=new Y.Doc();peer.clientID=424242;
    Y.applyUpdate(peer,Y.encodeStateAsUpdate(doc));
    const fragment=peer.getXmlFragment('default');
    fragment.insert(fragment.length,[element('paragraph',text)]);
    const inner=fragment.get(fragment.length-1).get(0);
    const relative=Y.encodeRelativePosition(Y.createRelativePositionFromTypeIndex(inner,text.length));
    const update=Y.encodeStateAsUpdate(peer,Y.encodeStateVector(doc));
    peer.destroy();
    return {anchor:Array.from(relative),head:Array.from(relative),update:Array.from(update)};
  },
  editable:()=>document.querySelector('.ProseMirror')?.getAttribute('contenteditable'),
  selection(){const e=document.querySelector('.ProseMirror').editor;return [e.state.selection.anchor,e.state.selection.head];},
  scroller:()=>document.scrollingElement.scrollTop,
  // The note's scroll area: #root when a test makes it the overflow box.
  area(){const root=document.querySelector('#root');
    return getComputedStyle(root).overflowY==='auto'?root:document.scrollingElement;},
  // The selection head's distance below the visible top of that area.
  headOffset(){const e=document.querySelector('.ProseMirror').editor,area=this.area();
    const top=area===document.scrollingElement?0:area.getBoundingClientRect().top+area.clientTop;
    return e.view.coordsAtPos(e.state.selection.head).top-top;},
  // Scroll so the selection head sits `offset` below the area's visible top.
  placeHead(offset){const area=this.area();area.scrollTop+=this.headOffset()-offset;return this.headOffset();},
  selectedText(){const e=document.querySelector('.ProseMirror').editor;
    return e.state.doc.textBetween(e.state.selection.from,e.state.selection.to);},
  // Host-side paragraphs added at the top before the next open, as a peer's
  // writing would be between Quit and relaunch.
  hostInsertAbove(count){doc.getXmlFragment('default').insert(0,Array.from({length:count},(_,i)=>
    element('paragraph',`added ${i} `+'more words above the cursor '.repeat(3))));},
  hostBytes:()=>Array.from(Y.encodeStateAsUpdate(doc)),
  hostDelta:()=>doc.getXmlFragment('default').get(0)?.get(0)?.toDelta(),
  hostDeltaText:()=>doc.getXmlFragment('default').toArray().map(block=>block.get(0)?.toString()??'').join('\n'),
  incomingOwnSuffix(){
    const editor=document.querySelector('.ProseMirror').editor;
    const live=editor.state.plugins.map(p=>p.getState(editor.state)).find(s=>s?.type?.doc)?.type.doc;
    if(!live)throw Error('real binding document missing');
    const before=live.clientID;
    const peer=new Y.Doc();Y.applyUpdate(peer,Y.encodeStateAsUpdate(live));peer.clientID=before;
    peer.getXmlFragment('default').insert(peer.getXmlFragment('default').length,[element('paragraph','same-writer incoming')]);
    listener(Y.encodeStateAsUpdate(peer));peer.destroy();
    return {before,after:live.clientID,...view.state()};
  },
  incoming(kind){
    const beforeJobs=jobs.length;
    const before=Y.encodeStateVector(doc);
    const frag=doc.getXmlFragment('default');
    if(kind==='remote') frag.insert(frag.length,[element('paragraph','remote')]);
    if(kind==='bold') Y.applyUpdate(doc,boldUpdate);
    if(kind==='unknown') frag.insert(frag.length,[element('futureWidget','future',{payload:'keep'})]);
    if(kind==='removeUnknown') {const index=frag.toArray().findIndex(el=>el.nodeName==='futureWidget');frag.delete(index,1);}
    listener(Y.encodeStateAsUpdate(doc,before));
    return {...view.state(),writes:jobs.length-beforeJobs};
  },
};
