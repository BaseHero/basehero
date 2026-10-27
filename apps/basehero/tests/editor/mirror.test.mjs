import test from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import {createPreflightMirror, inventory} from '../../src/lib/editor/schema.mjs';
import {oldFullPreflight} from './preflight-oracle.mjs';

const f=doc=>doc.getXmlFragment(inventory.fragment);
const paragraph=(value='text')=>{const p=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,value);p.insert(0,[t]);return p;};
const vector=doc=>[...Y.encodeStateVector(doc)];

test('mirror agrees with independent full oracle across seeded remote, local, deletion and dependency sequences',()=>{
  for(let seed=1;seed<=8;seed++){
    let random=seed;const next=()=>((random=Math.imul(random,1664525)+1013904223|0)>>>0);
    const canonical=new Y.Doc(),live=new Y.Doc();f(canonical).insert(0,[paragraph()]);
    const initial=Y.encodeStateAsUpdate(canonical);Y.applyUpdate(live,initial);
    const mirror=createPreflightMirror(live);
    for(let step=0;step<90;step++){
      const writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(canonical));
      const before=Y.encodeStateVector(writer),fragment=f(writer),op=next()%9;
      if(op===0)fragment.insert(fragment.length,[paragraph('paste')]);
      else if(op===1)fragment.insert(fragment.length,[new Y.XmlElement('future')]);
      else if(op===2 && fragment.length>1)fragment.delete(1+next()%(fragment.length-1),1);
      else if(op===3)fragment.get(0).setAttribute('future',next());
      else if(op===4)fragment.get(0).removeAttribute('future');
      else if(op===5)fragment.get(0).get(0).insert(0,'undo');
      else if(op===6)fragment.get(0).get(0).format(0,1,{bold:{}});
      else if(op===7)fragment.get(0).get(0).format(0,1,{future:{}});
      else fragment.get(0).get(0).format(0,1,{future:null});
      const update=Y.encodeStateAsUpdate(writer,before);Y.applyUpdate(canonical,update);
      const result=mirror.apply(update);
      assert.equal(result.supported,oldFullPreflight(f(canonical)),`seed ${seed} step ${step} op ${op}`);
      Y.applyUpdate(live,update);assert.deepEqual(vector(mirror.doc),vector(live));
      writer.destroy();
    }
    mirror.destroy();canonical.destroy();live.destroy();
  }
});

test('supported-heavy seeded structural, mark and text edits use incremental validation and agree with independent oracle',t=>{
  const stats={incremental:0,full:0,unsupported:0,steps:0};
  for(let seed=1;seed<=6;seed++){
    let random=seed;
    const next=()=>((random=Math.imul(random,1664525)+1013904223|0)>>>0);
    const pick=items=>items[next()%items.length];
    const container=()=>{
      const choice=next()%7;
      if(choice===0)return paragraph('new words');
      if(choice===1){const h=new Y.XmlElement('heading');h.setAttribute('level',1+next()%3);const text=new Y.XmlText();text.insert(0,'heading');h.insert(0,[text]);return h;}
      if(choice===2){const quote=new Y.XmlElement('blockquote');quote.insert(0,[paragraph('quoted')]);return quote;}
      const list=new Y.XmlElement(choice===3?'bulletList':choice===4?'orderedList':'taskList');
      if(list.nodeName==='orderedList')list.setAttribute('start',1+next()%100000);
      const item=new Y.XmlElement(list.nodeName==='taskList'?'taskItem':'listItem');
      if(item.nodeName==='taskItem')item.setAttribute('checked',!!(next()%2));
      item.insert(0,[paragraph('nested')]);
      if(choice===6){const nested=new Y.XmlElement('bulletList'),child=new Y.XmlElement('listItem');child.insert(0,[paragraph('deep')]);nested.insert(0,[child]);item.insert(1,[nested]);}
      list.insert(0,[item]);return list;
    };
    const canonical=new Y.Doc(),live=new Y.Doc();f(canonical).insert(0,[paragraph('start')]);
    Y.applyUpdate(live,Y.encodeStateAsUpdate(canonical));const mirror=createPreflightMirror(live);
    let prematureWrites=0;live.on('update',()=>prematureWrites++);
    let unknown=false;
    for(let step=0;step<130;step++){
      const writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(canonical));
      const fragment=f(writer),before=Y.encodeStateVector(writer),op=next()%12;
      if(unknown){fragment.delete(fragment.length-1,1);unknown=false;}
      else if(step%27===26){fragment.insert(fragment.length,[new Y.XmlElement('futureWidget')]);unknown=true;}
      else if(op<=2){fragment.insert(next()%(fragment.length+1),[container()]);}
      else if(op===3 && fragment.length>1){fragment.delete(1+next()%(fragment.length-1),1);}
      else if(op===4 && fragment.length>1){ // Yjs move is delete + insertion of an equivalent new type.
        fragment.delete(1+next()%(fragment.length-1),1);fragment.insert(1+next()%fragment.length,[container()]);
      }else{
        const nodes=[];const visit=node=>{if(node instanceof Y.XmlElement){nodes.push(node);for(const child of node.toArray())visit(child);}};
        for(const child of fragment.toArray())visit(child);
        const texts=nodes.flatMap(node=>node.toArray().filter(child=>child instanceof Y.XmlText));
        if(op===5){const headings=nodes.filter(node=>node.nodeName==='heading');if(headings.length)pick(headings).setAttribute('level',1+next()%3);else fragment.insert(fragment.length,[container()]);}
        else if(op===6){const items=nodes.filter(node=>node.nodeName==='taskItem');if(items.length)pick(items).setAttribute('checked',!!(next()%2));else fragment.insert(fragment.length,[container()]);}
        else if(op===7){const lists=nodes.filter(node=>node.nodeName==='orderedList');if(lists.length)pick(lists).setAttribute('start',1+next()%100000);else fragment.insert(fragment.length,[container()]);}
        else if(texts.length){const text=pick(texts);if(op===8)text.insert(next()%(text.length+1),'x');
          else if(op===9 && text.length>1)text.delete(next()%text.length,1);
          else if(op===10)text.format(0,Math.min(1,text.length),{[pick(['bold','italic','underline','strike','code'])]:{}});
          else text.format(0,Math.min(1,text.length),{link:{href:'https://example.org/'+(next()%100)}});
        }
      }
      // Keep later oracle steps cheap without constraining the production note.
      if(fragment.length>12)fragment.delete(1,fragment.length-12);
      const update=Y.encodeStateAsUpdate(writer,before);
      Y.applyUpdate(canonical,update);
      const incremental=mirror.supported;
      const result=mirror.apply(update),expected=oldFullPreflight(f(canonical));
      assert.equal(result.supported,expected,`seed ${seed}, step ${step}, op ${op}`);
      if(incremental)stats.incremental++;else stats.full++;
      if(!result.supported)stats.unsupported++;
      assert.equal(prematureWrites,0,'preflight never writes to the live copy before the host applies bytes');
      Y.applyUpdate(live,update);prematureWrites=0;
      assert.deepEqual(vector(mirror.doc),vector(live),`seed ${seed}, step ${step} vectors`);
      stats.steps++;writer.destroy();
    }
    mirror.destroy();canonical.destroy();live.destroy();
  }
  assert.ok(stats.incremental>650,JSON.stringify(stats));
  assert.ok(stats.full>0 && stats.unsupported>0,JSON.stringify(stats));
  t.diagnostic(JSON.stringify(stats));
});

test('paste, local Undo, out-of-order remote dependencies and unsupported values match oracle at every step',()=>{
  const live=new Y.Doc(),remote=new Y.Doc();f(live).insert(0,[paragraph('initial')]);
  Y.applyUpdate(remote,Y.encodeStateAsUpdate(live));
  const mirror=createPreflightMirror(live),undo=new Y.UndoManager(f(live),{trackedOrigins:new Set(['local'])});
  const expect=(bytes,label,local=false)=>{
    const result=mirror.apply(bytes);
    if(!local)Y.applyUpdate(live,bytes);
    assert.equal(result.supported,oldFullPreflight(f(live)),label);
    assert.deepEqual(vector(mirror.doc),vector(live),label);
  };
  const edit=(mutate,label)=>{
    const before=Y.encodeStateVector(remote);mutate(f(remote));
    const bytes=Y.encodeStateAsUpdate(remote,before);expect(bytes,label);return bytes;
  };
  edit(fragment=>fragment.insert(1,[paragraph('pasted words')]),'paste');
  const start=Y.encodeStateVector(remote);
  f(remote).insert(2,[new Y.XmlElement('future')]);const add=Y.encodeStateAsUpdate(remote,start);
  const later=Y.encodeStateVector(remote);f(remote).delete(2,1);const remove=Y.encodeStateAsUpdate(remote,later);
  expect(remove,'unresolved delete');expect(add,'late inserted dependency already deleted');
  edit(fragment=>fragment.get(0).setAttribute('future','unsupported'),'unknown attribute');
  edit(fragment=>fragment.get(0).removeAttribute('future'),'restored attribute');
  edit(fragment=>fragment.get(0).get(0).format(0,1,{link:{href:'javascript:alert(1)'}}),'unsafe link');
  edit(fragment=>fragment.get(0).get(0).format(0,1,{link:null}),'remove unsafe link');
  let update=null;live.on('update',(bytes,origin)=>{if(origin==='local'||origin===undo)update=bytes;});
  live.transact(()=>f(live).get(0).get(0).insert(0,'typed'),'local');
  assert.ok(update);expect(update,'local insert',true);
  update=null;undo.undo();assert.ok(update,'Undo emits a local delta');expect(update,'local Undo',true);
  undo.destroy();mirror.destroy();remote.destroy();live.destroy();
});

test('concurrent overlapping code and italic merge remains editable',()=>{
  const initial=new Y.Doc();f(initial).insert(0,[paragraph('abcdefgh')]);
  const left=new Y.Doc(),right=new Y.Doc(),live=new Y.Doc();
  for(const doc of [left,right,live])Y.applyUpdate(doc,Y.encodeStateAsUpdate(initial));
  const mirror=createPreflightMirror(live);
  f(left).get(0).get(0).format(0,5,{italic:{}});
  f(right).get(0).get(0).format(3,5,{code:{}});
  for(const writer of [right,left]){
    const update=Y.encodeStateAsUpdate(writer,Y.encodeStateVector(initial));
    assert.equal(mirror.apply(update).supported,true);
    Y.applyUpdate(live,update);
  }
  assert.equal(oldFullPreflight(f(live)),true);
  assert.deepEqual(vector(mirror.doc),vector(live));
  assert.deepEqual(f(live).get(0).get(0).toDelta().find(run=>run.attributes?.italic && run.attributes?.code)?.insert,'de');
  for(const doc of [initial,left,right,live])doc.destroy();mirror.destroy();
});

test('bounded concurrent writers delivered out of order agree with full oracle',()=>{
  for(let seed=1;seed<=12;seed++){
    let random=seed;const next=()=>((random=Math.imul(random,1664525)+1013904223|0)>>>0);
    const initial=new Y.Doc();f(initial).insert(0,[paragraph('abcdefgh')]);
    const live=new Y.Doc();Y.applyUpdate(live,Y.encodeStateAsUpdate(initial));
    const mirror=createPreflightMirror(live),writers=[];
    for(let i=0;i<4;i++){
      const writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(initial));
      const text=f(writer).get(0).get(0);
      if(i===0)text.format(next()%4,4,{italic:{}});
      else if(i===1)text.format(next()%4,4,{code:{}});
      else if(i===2)text.insert(next()%8,'x');
      else text.delete(next()%7,1);
      writers.push(writer);
    }
    const updates=writers.map(writer=>Y.encodeStateAsUpdate(writer,Y.encodeStateVector(initial)));
    // Deterministic shuffle; all writers edited the same initial state.
    for(let i=updates.length-1;i>0;i--){const j=next()%(i+1);[updates[i],updates[j]]=[updates[j],updates[i]];}
    for(const update of updates){
      Y.applyUpdate(live,update);
      const result=mirror.apply(update);
      assert.equal(result.supported,oldFullPreflight(f(live)),`seed ${seed}`);
      assert.deepEqual(vector(mirror.doc),vector(live));
    }
    mirror.destroy();live.destroy();initial.destroy();writers.forEach(writer=>writer.destroy());
  }
});

test('incremental changed-text mark validation rejects newly unsafe values without full fallback',()=>{
  const live=new Y.Doc();f(live).insert(0,[paragraph('safe')]);
  const mirror=createPreflightMirror(live),writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(live));
  const before=Y.encodeStateVector(writer);
  f(writer).get(0).get(0).format(0,1,{link:{href:'javascript:alert(1)'}});
  assert.equal(mirror.supported,true);
  const verdict=mirror.apply(Y.encodeStateAsUpdate(writer,before));
  assert.equal(verdict.supported,false,'a skipped changed-text mark check would accept unsafe link');
  assert.equal(oldFullPreflight(f(writer)),false);
  mirror.destroy();writer.destroy();live.destroy();
});

test('newly inserted descendants and ancestor required-first are both checked',()=>{
  const doc=new Y.Doc();const list=new Y.XmlElement('bulletList'),item=new Y.XmlElement('listItem');
  item.insert(0,[paragraph()]);list.insert(0,[item]);f(doc).insert(0,[list]);
  const mirror=createPreflightMirror(doc),writer=new Y.Doc();Y.applyUpdate(writer,Y.encodeStateAsUpdate(doc));
  const before=Y.encodeStateVector(writer);f(writer).get(0).get(0).delete(0,1);
  assert.equal(mirror.apply(Y.encodeStateAsUpdate(writer,before)).supported,false,'mutation proof: skipped ancestor required-first would accept');
  mirror.destroy();writer.destroy();doc.destroy();
});
