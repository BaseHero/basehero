import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as Y from 'yjs';
import {createPreflightMirror} from '../src/schema.mjs';

// Synthetic interop traces (7-21833 and 101-7463). These contain unsupported
// embeds and bold:true: lossless/read-only cases, not editable-schema examples.
const bytes=hex=>Uint8Array.from(Buffer.from(hex,'hex'));
const canonical=doc=>Buffer.from(Y.encodeStateAsUpdate(doc)).toString('hex');
function state(doc) {
  const sv=[...Y.decodeStateVector(Y.encodeStateVector(doc))].filter(([,n])=>n>0)
    .sort(([a],[b])=>a-b).map(([client,n])=>`${client}:${n}`).join(',');
  const deleted=[...Y.createDeleteSetFromStructStore(doc.store).clients].sort(([a],[b])=>a-b)
    .map(([client,ranges])=>`${client}:${ranges.map(({clock,len})=>`${clock}-${clock+len}`).join(',')}`).join(';');
  return `sv=${sv}|ds=${deleted}`;
}
function normalized(doc) {
  const value=v=>typeof v==='bigint'?`bigint:${v}`:v instanceof Uint8Array?`bin:${Buffer.from(v).toString('hex')}`:
    v instanceof Y.AbstractType?tree(v):Array.isArray(v)?v.map(value):v&&typeof v==='object'?
      Object.fromEntries(Object.keys(v).sort().map(k=>[k,value(v[k])])):v;
  function tree(node) {
    if(node instanceof Y.XmlText) {
      const runs=[];
      for(const part of node.toDelta()) {
        const attrs=value(part.attributes??{}),insert=value(part.insert);
        if(typeof insert==='string' && runs.length && typeof runs.at(-1)[0]==='string' &&
          JSON.stringify(runs.at(-1)[1])===JSON.stringify(attrs)) runs.at(-1)[0]+=insert;
        else runs.push([insert,attrs]);
      }
      return ['text',value(node.getAttributes()),runs];
    }
    if(node instanceof Y.XmlElement) return ['element',node.nodeName,value(node.getAttributes()),node.toArray().map(tree)];
    if(node instanceof Y.XmlFragment) return ['fragment',node.toArray().map(tree)];
    return ['value',value(node)];
  }
  return tree(doc.getXmlFragment('default'));
}
test('event delta describes real local and remote bold formatting without extra writes',()=>{
  const initial=new Y.Doc(),p=new Y.XmlElement('paragraph'),text=new Y.XmlText();
  text.insert(0,'abcdefgh');p.insert(0,[text]);initial.getXmlFragment('default').insert(0,[p]);
  for(const reverse of [false,true]) {
    const page=new Y.Doc(),peer=new Y.Doc();
    for(const doc of [page,peer])Y.applyUpdate(doc,Y.encodeStateAsUpdate(initial));
    const old=Y.encodeStateVector(initial),events=[];
    page.getXmlFragment('default').observeDeep(changes=>{
      for(const event of changes) if(event.target instanceof Y.XmlText) events.push(event.delta);
    });
    let outgoing=0;page.on('update',()=>outgoing++);
    page.getXmlFragment('default').get(0).get(0).format(reverse?5:0,2,{bold:{}});
    assert.deepEqual(events.splice(0),[reverse?[{retain:5},{retain:2,attributes:{bold:{}}}]:[{retain:2,attributes:{bold:{}}}]]);
    assert.equal(outgoing,1,'local authoring must still produce one write');
    peer.getXmlFragment('default').get(0).get(0).format(reverse?0:5,2,{bold:{}});
    Y.applyUpdate(page,Y.encodeStateAsUpdate(peer,old),'incoming');
    assert.deepEqual(events,[reverse?[{retain:2,attributes:{bold:{}}}]:[{retain:5},{retain:2,attributes:{bold:{}}}]]);
    assert.equal(outgoing,2,'remote change must not generate an additional local write');
    assert.deepEqual(page.getXmlFragment('default').get(0).get(0).toDelta(),[
      {insert:'ab',attributes:{bold:{}}},{insert:'cde'},{insert:'fg',attributes:{bold:{}}},{insert:'h'},
    ]);
    page.destroy();peer.destroy();
  }
  initial.destroy();
});

for(const id of ['7-21833','101-7463']) {
  const fixture=JSON.parse(readFileSync(new URL(`./fixtures/no-${id}.json`,import.meta.url)));
  test(`observing ${id} leaves every traced delete set and final marks intact`,()=>{
    for(const trace of fixture.docs) {
      let plain=new Y.Doc(),observed=new Y.Doc(),mirror=createPreflightMirror(new Y.Doc());
      let writes=0,localWrites=0,reads=0;
      const onUpdate=(_bytes,origin)=>{writes++;if(origin!=='incoming')localWrites++;};
      const onEvents=events=>{for(const event of events){void event.delta;void event.changes;reads++;}};
      observed.on('update',onUpdate);
      observed.getXmlFragment('default').observeDeep(onEvents);
      for(const [index,[kind,hex,want]] of trace.steps.entries()) {
        if(kind==='o') {
          observed.destroy();plain.destroy();mirror.destroy();
          observed=new Y.Doc();plain=new Y.Doc();mirror=createPreflightMirror(new Y.Doc());
          observed.on('update',onUpdate);observed.getXmlFragment('default').observeDeep(onEvents);
        }
        const update=bytes(hex);
        Y.applyUpdate(plain,update,'incoming');
        const before=writes;
        Y.applyUpdate(observed,update,'incoming');
        const applied=writes-before;
        const label=`${id}/${trace.name}/${index}`;
        const beforeRead=canonical(observed),stateBeforeRead=state(observed);
        // Delta and changes have already been read in observeDeep; reading again
        // must not turn an input into an extra local update/delete.
        assert.ok(applied<=1,`${label} observer must not generate a second update`);
        assert.equal(localWrites,0,`${label} observation must not generate local writes`);
        assert.equal(canonical(observed),beforeRead,label);
        assert.equal(state(observed),stateBeforeRead,label);
        assert.equal(state(observed),want,`${label} input delete set`);
        assert.equal(state(plain),want,`${label} no-read input delete set`);
        assert.equal(mirror.apply(update).uncertain,false,label);
        assert.equal(state(mirror.doc),want,`${label} preflight delete set`);
        assert.deepEqual(normalized(observed),normalized(plain),`${label} observed content`);
        assert.deepEqual(normalized(mirror.doc),normalized(plain),`${label} mirror content`);
        assert.equal(canonical(observed),canonical(plain),`${label} exact encoded update`);
        assert.equal(canonical(mirror.doc),canonical(plain),`${label} exact mirror update`);
      }
      const final=new Y.Doc();Y.applyUpdate(final,bytes(trace.fin));
      assert.deepEqual(normalized(mirror.doc),normalized(final),`${id}/${trace.name} fresh-open fragment`);
      assert.equal(canonical(mirror.doc),canonical(final),`${id}/${trace.name} fresh-open bytes`);
      assert.ok(reads>0,`${id}/${trace.name} observer actually read events`);
      final.destroy();mirror.destroy();plain.destroy();observed.destroy();
    }
  });
}
