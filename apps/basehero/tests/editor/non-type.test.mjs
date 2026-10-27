import test from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import {createPreflightMirror, classify, inventory, safeView} from '../../src/lib/editor/schema.mjs';
import {oldFullPreflight} from './preflight-oracle.mjs';

const fragment=doc=>doc.getXmlFragment(inventory.fragment);
const paragraph=()=>{const p=new Y.XmlElement('paragraph');const t=new Y.XmlText();t.insert(0,'before');p.insert(0,[t]);return p;};
const cases={json:()=>({untrusted:true}),string:()=> 'raw',binary:()=>new Uint8Array([1,2]),subdoc:()=>new Y.Doc()};
for(const [kind,make] of Object.entries(cases))for(const location of ['root','paragraph'])
  test(`incremental mirror rejects ${kind} at ${location}, preserves bytes and shows an inert placeholder`,()=>{
    const live=new Y.Doc(),writer=new Y.Doc();fragment(live).insert(0,[paragraph()]);
    Y.applyUpdate(writer,Y.encodeStateAsUpdate(live));const mirror=createPreflightMirror(live);
    const before=Y.encodeStateVector(writer);
    const target=location==='root'?fragment(writer):fragment(writer).get(0);
    target.insert(1,[make()]);const bytes=Y.encodeStateAsUpdate(writer,before);
    assert.equal(oldFullPreflight(fragment(writer)),false);
    assert.equal(mirror.apply(bytes).supported,false,'mirror must not allow binding');
    Y.applyUpdate(live,bytes);
    assert.equal(classify(fragment(live)).supported,false);
    assert.deepEqual([...Y.encodeStateAsUpdate(mirror.doc)],[...Y.encodeStateAsUpdate(live)],'mirror does not normalize or lose content');
    const view=safeView(fragment(live));
    assert.equal(JSON.stringify(view).includes('"placeholder":true'),true);
    assert.equal(JSON.stringify(view).includes('untrusted'),false);
    const after=Y.encodeStateVector(writer);
    target.delete(1,1);
    assert.equal(mirror.apply(Y.encodeStateAsUpdate(writer,after)).supported,true,
      'deleting the unsupported item must recover without losing other content');
    mirror.destroy();live.destroy();writer.destroy();
  });

test('one read-only changed root with 1000 changed paragraphs validates each text once',()=>{
  const writer=new Y.Doc(),live=new Y.Doc(),quote=new Y.XmlElement('blockquote');
  const paragraphs=Array.from({length:1000},()=>paragraph());
  quote.insert(0,paragraphs);fragment(writer).insert(0,[quote,new Y.XmlElement('future')]);
  Y.applyUpdate(live,Y.encodeStateAsUpdate(writer));const mirror=createPreflightMirror(live);
  assert.equal(mirror.supported,false);
  const texts=paragraphs.map(p=>p.get(0)),before=Y.encodeStateVector(writer);
  writer.transact(()=>{for(const text of texts)text.insert(0,'x');});
  const delta=Y.encodeStateAsUpdate(writer,before);
  const original=Y.XmlText.prototype.toDelta;let validations=0;
  Y.XmlText.prototype.toDelta=function(...args){validations++;return original.apply(this,args);};
  try {assert.equal(mirror.apply(delta).supported,false);} finally {Y.XmlText.prototype.toDelta=original;}
  assert.equal(validations,1000,'one root traversal, not one per changed descendant');
  Y.applyUpdate(live,delta);
  assert.deepEqual([...Y.encodeStateAsUpdate(mirror.doc)],[...Y.encodeStateAsUpdate(live)]);
  mirror.destroy();live.destroy();writer.destroy();
});
