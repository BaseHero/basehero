import * as Y from 'yjs';
import {createNoteEditor} from '../src/editor.mjs';

let live,view,receive;
const jobs=[];
const paragraph=text=>{const p=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,text);p.insert(0,[t]);return p;};
window.fallbackHarness={
  async open(){
    live=new Y.Doc();live.getXmlFragment('default').insert(0,[paragraph('start')]);
    view=await createNoteEditor(document.querySelector('#root'),{
      open:async listener=>{receive=listener;return {state:Y.encodeStateAsUpdate(live),unsubscribe:()=>{}};},
      commit:(bytes,id)=>new Promise(resolve=>jobs.push({bytes,id,resolve})),
    });
    return {mode:view.state().mode,fullChecks:window.__fullChecks};
  },
  incoming(kind){
    const before=Y.encodeStateVector(live),fragment=live.getXmlFragment('default');
    if(kind==='supported')fragment.insert(fragment.length,[paragraph('remote')]);
    else if(kind==='while-unsupported')fragment.get(0).get(0).insert(0,'remote');
    else if(kind==='unsupported')fragment.insert(fragment.length,[new Y.XmlElement('futureWidget')]);
    else fragment.delete(fragment.length-1,1);
    receive(Y.encodeStateAsUpdate(live,before));
    return this.state();
  },
  mirror(){return view.__testMirror();},
  liveWrite(kind){view.__testLiveWrite(kind);return this.state();},
  divergeMirror(){
    const writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(live));
    const before=Y.encodeStateVector(writer);writer.getXmlFragment('default').insert(1,[paragraph('mirror-only')]);
    view.__testDiverge(Y.encodeStateAsUpdate(writer,before));writer.destroy();
  },
  state(){return {...view.state(),jobs:jobs.map(job=>job.id),events:window.__fallbackEvents,fullChecks:window.__fullChecks,bindingWrites:window.__bindingWrites};},
  ack(){const job=jobs.shift();if(!job)throw Error('missing job');job.resolve({requestId:job.id});},
  close(){view?.close();live?.destroy();},
};
