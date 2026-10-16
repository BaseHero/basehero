import * as Y from 'yjs';
import {createNoteEditor} from '../src/editor.mjs';
const f=doc=>doc.getXmlFragment('default');
const p=()=>{const node=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,'before');node.insert(0,[t]);return node;};
window.readonlyHarness={
  async open(){
    this.writer=new Y.Doc();f(this.writer).insert(0,[p(),p(),new Y.XmlElement('future')]);
    const state=Y.encodeStateAsUpdate(this.writer);
    this.view=await createNoteEditor(document.body,{open:async callback=>{this.receive=callback;return {clientId:2002468231004600,state,unsubscribe(){}};},
      commit:async()=>{throw Error('read-only must not save');}});
    this.stable=document.querySelectorAll('.note-content > div')[1];
    return this.view.state();
  },
  edit(kind){
    const before=Y.encodeStateVector(this.writer),root=f(this.writer);
    if(kind==='nested')root.get(0).get(0).insert(0,'new ');
    else if(kind==='insert')root.insert(1,[p()]);
    else if(kind==='delete')root.delete(1,1);
    else if(kind==='recover')root.delete(root.length-1,1);
    else if(kind==='combined'){root.insert(1,[p()]);root.get(0).get(0).insert(0,'combined ');}
    this.receive(Y.encodeStateAsUpdate(this.writer,before));
    return {state:this.view.state(),stableAttached:this.stable.isConnected,
      stableSame:[...document.querySelectorAll('.note-content > div')].includes(this.stable),
      placeholders:document.querySelectorAll('.note-placeholder').length,
      text:document.querySelector('.note-content').textContent};
  },
  close(){this.view.close();this.writer.destroy();},
};
window.queueHarness={
  async open(){
    const initial=new Y.Doc();f(initial).insert(0,[p()]);
    const jobs=[];let view;
    view=await createNoteEditor(document.body,{open:async callback=>{this.receive=callback;return {clientId:2002468231004600,state:Y.encodeStateAsUpdate(initial),unsubscribe(){}};},
      commit:(bytes,id)=>new Promise((resolve,reject)=>jobs.push({bytes:[...bytes],id,resolve,reject}))});
    this.jobs=jobs;this.view=view;this.initial=initial;
    return view.state();
  },
  incoming(){const before=Y.encodeStateVector(this.initial);f(this.initial).get(0).get(0).insert(0,'remote');this.receive(Y.encodeStateAsUpdate(this.initial,before));return this.view.state();},
  state(){return this.view.state();},
  items(){return this.jobs.map(({bytes,id})=>({bytes,id}));},
  reject(){this.jobs[0].reject(Error('offline'));this.jobs.shift();},
  ack(){const job=this.jobs.shift();Y.applyUpdate(this.initial,new Uint8Array(job.bytes));job.resolve({requestId:job.id});},
  storedText(){return f(this.initial).get(0).get(0).toString();},
  retry(){this.view.retry();},
  close(){this.view.close();this.initial.destroy();},
};
window.historyFailureHarness=async()=>{
  const writer=new Y.Doc();f(writer).insert(0,[p()]);
  const root=document.createElement('div');document.body.append(root);
  const view=await createNoteEditor(root,{open:async()=>({clientId:2002468231004600,state:Y.encodeStateAsUpdate(writer),unsubscribe(){}}),
    commit:async(_bytes,id)=>({requestId:id})});
  const original=Y.UndoManager.prototype.redo;
  Y.UndoManager.prototype.redo=()=>{throw new TypeError('redoItem');};
  let failed=false;
  const onError=event=>{failed=true;event.preventDefault();};
  window.addEventListener('error',onError);
  root.querySelector('.ProseMirror').dispatchEvent(new InputEvent('beforeinput',{inputType:'historyRedo',bubbles:true,cancelable:true}));
  window.removeEventListener('error',onError);
  Y.UndoManager.prototype.redo=original;
  const status={failed,mode:view.state().mode};
  view.close();writer.destroy();root.remove();return status;
};
window.readFailureHarness=async phase=>{
  const writer=new Y.Doc();f(writer).insert(0,[p()]);
  const root=document.createElement('div');document.body.append(root);
  let receive, view, error;
  const original=Y.XmlFragment.prototype.toArray;
  try {
    if(phase==='open') Y.XmlFragment.prototype.toArray=()=>{throw Error('bad XML read');};
    view=await createNoteEditor(root,{open:async cb=>{receive=cb;return {clientId:2002468231004600,state:Y.encodeStateAsUpdate(writer),unsubscribe(){}};},
      commit:async()=>{throw Error('unexpected commit');}});
    if(phase==='apply') {
      Y.XmlFragment.prototype.toArray=()=>{throw Error('bad XML read');};
      const before=Y.encodeStateVector(writer);f(writer).insert(1,[new Y.XmlElement('future')]);
      receive(Y.encodeStateAsUpdate(writer,before));
    }
    return {mode:view.state().mode,placeholder:root.querySelectorAll('.note-placeholder').length};
  }catch(caught){error=String(caught);return {error};}
  finally{Y.XmlFragment.prototype.toArray=original;view?.close();writer.destroy();root.remove();}
};
window.nonTypeHarness=async(kind,location)=>{
  const initial=new Y.Doc(),writer=new Y.Doc();f(initial).insert(0,[p()]);
  const state=Y.encodeStateAsUpdate(initial);Y.applyUpdate(writer,state);
  let incoming,commits=0;window.__nonTypeBindingWrites=0;
  const host={open:async callback=>{incoming=callback;return {clientId:2002468231004600,state,unsubscribe(){}};},commit:async(_bytes,id)=>{commits++;return {requestId:id};}};
  const root=document.createElement('div');document.body.append(root);
  const view=await createNoteEditor(root,host);
  const before=Y.encodeStateVector(writer);
  const value={json:{unknown:true},string:'raw',binary:new Uint8Array([1,2]),subdoc:new Y.Doc()}[kind];
  (location==='root'?f(writer):f(writer).get(0)).insert(1,[value]);
  const bytes=Y.encodeStateAsUpdate(writer,before);
  const verdictBefore=view.state();
  incoming(bytes);
  const result={before:verdictBefore,after:view.state(),status:root.querySelector('[data-status]').textContent,
    placeholders:root.querySelectorAll('.note-placeholder').length,editor:root.querySelectorAll('.ProseMirror').length,
    commits,bindingWrites:window.__nonTypeBindingWrites,
    preserved:JSON.stringify([...window.__nonTypeLive()])===JSON.stringify([...Y.encodeStateAsUpdate(writer)]),
    visible:root.querySelector('.note-content').textContent};
  view.close();initial.destroy();writer.destroy();root.remove();return result;
};
