// Browser half of the repeatable editor comparison. Remote writers live in Node.
import * as Y from 'yjs';
import {createNoteEditor} from '/note-editor.js';
let canonical,views,listeners,commits;
const modes=()=>views.map(view=>view.state().mode);
function deliver(update) {Y.applyUpdate(canonical,update);listeners.forEach(receive=>receive(update));}
window.measure={
  async setup(state) {
    canonical=new Y.Doc();Y.applyUpdate(canonical,new Uint8Array(state));
    listeners=[];views=[];commits=[];
    for(let i=0;i<2;i++)views.push(await createNoteEditor(document.querySelector(`#root${i}`),{
      open:async callback=>{listeners.push(callback);return {state:Y.encodeStateAsUpdate(canonical),unsubscribe:()=>{}};},
      commit:async(update,id)=>{
        const bytes=new Uint8Array(update);commits.push([...bytes]);
        deliver(bytes); // The host fans out locally committed updates to every view.
        return {requestId:id};
      },
    }));
    return {modes:modes(),encoded:Y.encodeStateAsUpdate(canonical).length};
  },
  async sustained(updates,intervalMs=50) {
    const times=[],wire=[],frames=[];let active=true,last=performance.now();
    const frame=now=>{if(!active)return;frames.push(now-last);last=now;requestAnimationFrame(frame);};
    requestAnimationFrame(frame);
    const started=performance.now(),arrival=[],count=updates.length;
    // Scheduled at 20/s, with no artificial yield after each delivery. Record
    // lag to the scheduled arrival as well as actual completion/backlog.
    for(let i=0;i<count;i++) {
      const due=started+i*intervalMs;
      await new Promise(resolve=>setTimeout(resolve,Math.max(0,due-performance.now())));
      const arrived=performance.now();arrival.push(arrived-due);
      const update=new Uint8Array(updates[i]);
      Y.applyUpdate(canonical,update);
      for(const receive of listeners){const t=performance.now();receive(update);times.push(performance.now()-t);}
      wire.push(update.length);
    }
    const finished=performance.now();
    await new Promise(resolve=>setTimeout(resolve,200));active=false;
    return {times,wire,frames,arrival,elapsed:finished-started,
      completionLag:finished-(started+(count-1)*intervalMs),modes:modes()};
  },
  burst(updates) {
    const times=[];const started=performance.now();
    for(const raw of updates){const update=new Uint8Array(raw);Y.applyUpdate(canonical,update);
      for(const receive of listeners){const t=performance.now();receive(update);times.push(performance.now()-t);}}
    return {times,elapsed:performance.now()-started,modes:modes()};
  },
  unknown() {
    const before=Y.encodeStateVector(canonical);
    canonical.getXmlFragment('default').insert(1,[new Y.XmlElement('futureWidget')]);
    const update=Y.encodeStateAsUpdate(canonical,before);listeners.forEach(receive=>receive(update));return modes();
  },
  readonlyEdits(count=20) {
    const times=[];
    for(let i=0;i<count;i++) {
      const before=Y.encodeStateVector(canonical);
      canonical.getXmlFragment('default').get(0).get(0).insert(0,'x');
      const bytes=Y.encodeStateAsUpdate(canonical,before);
      for(const receive of listeners){const start=performance.now();receive(bytes);times.push(performance.now()-start);}
    }
    return {times,modes:modes()};
  },
  resolveUnknown() {
    const before=Y.encodeStateVector(canonical);canonical.getXmlFragment('default').delete(1,1);
    const update=Y.encodeStateAsUpdate(canonical,before);listeners.forEach(receive=>receive(update));return modes();
  },
  dependencyResolution() {
    const writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(canonical));
    const frag=writer.getXmlFragment('default'),before=Y.encodeStateVector(writer);
    frag.insert(1,[new Y.XmlElement('futureWidget')]);const add=Y.encodeStateAsUpdate(writer,before);
    const next=Y.encodeStateVector(writer);frag.delete(1,1);const remove=Y.encodeStateAsUpdate(writer,next);
    for(const update of [remove,add])deliver(update);
    writer.destroy();return modes();
  },
  get snapshot(){return [...Y.encodeStateAsUpdate(canonical)];},
  get convergence(){return views.map(view=>{
    const other=new Y.Doc();Y.applyUpdate(other,view.snapshotForMeasure());
    const equal=JSON.stringify([...Y.encodeStateVector(other)])===JSON.stringify([...Y.encodeStateVector(canonical)])&&
      JSON.stringify(other.getXmlFragment('default').toJSON())===JSON.stringify(canonical.getXmlFragment('default').toJSON());
    other.destroy();return equal;
  });},
  get commits(){return commits;},
  get heap(){return performance.memory?.usedJSHeapSize??null;},
  get modes(){return modes();},
  get states(){return views.map(view=>view.state());},
};
