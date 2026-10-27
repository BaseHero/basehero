import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import { prosemirrorToYXmlFragment } from '@tiptap/y-tiptap';
import { extensions, inventory, inspectDisposable, supportsProseMirror } from '../../src/lib/editor/schema.mjs';
import {oldFullPreflight} from './preflight-oracle.mjs';

const schema=getSchema(extensions);
function make(kind) {
  const doc=new Y.Doc();
  if (kind==='empty') return doc;
  if (kind.endsWith('.bin')) Y.applyUpdate(doc,readFileSync(new URL(kind,import.meta.url)));
  else {
    const paragraph=new Y.XmlElement('paragraph');
    const text=new Y.XmlText();text.insert(0,'safe');paragraph.insert(0,[text]);
    doc.getXmlFragment(inventory.fragment).insert(0,[paragraph]);
    if (kind==='unknown') doc.getXmlFragment(inventory.fragment).insert(1,[new Y.XmlElement('futureWidget')]);
    if (kind==='structure') doc.getXmlFragment(inventory.fragment).insert(1,[new Y.XmlElement('listItem')]);
  }
  return doc;
}

test('disposable combined verdict equals original full classifier and preserves canonical bytes without binding writes',()=>{
  for (const [kind,expected] of [['empty',true],['known',true],['unknown',false],['structure',false],['rich.bin',true],['attr.bin',false],['mark.bin',false],['value.bin',false],['textAttr.bin',false]]) {
    const canonical=make(kind);
    const before=Y.encodeStateAsUpdate(canonical);
    let writes=0;canonical.on('update',()=>writes++);
    const probe=new Y.Doc();Y.applyUpdate(probe,before);
    assert.equal(oldFullPreflight(canonical.getXmlFragment(inventory.fragment)),expected,`${kind} old verdict`);
    assert.equal(inspectDisposable(probe.getXmlFragment(inventory.fragment)).supported,expected,`${kind} new verdict`);
    assert.deepEqual(Y.encodeStateAsUpdate(canonical),before,`${kind} bytes`);
    assert.equal(writes,0,`${kind} binding writes`);
    probe.destroy();canonical.destroy();
  }
});

test('unknown insertion and dependency-resolving delete preserve raw content until support returns',()=>{
  const canonical=make('known'), writer=new Y.Doc();
  Y.applyUpdate(writer,Y.encodeStateAsUpdate(canonical));
  const fragment=writer.getXmlFragment(inventory.fragment);
  const start=Y.encodeStateVector(writer);
  fragment.insert(1,[new Y.XmlElement('futureWidget')]);
  const add=Y.encodeStateAsUpdate(writer,start);
  const afterAdd=Y.encodeStateVector(writer);
  fragment.delete(1,1);
  const remove=Y.encodeStateAsUpdate(writer,afterAdd);
  const probe=new Y.Doc();Y.applyUpdate(probe,Y.encodeStateAsUpdate(canonical));
  Y.applyUpdate(probe,remove); // unresolved deletion arrives before its insertion
  assert.equal(inspectDisposable(probe.getXmlFragment(inventory.fragment)).supported,true);
  assert.equal(oldFullPreflight(probe.getXmlFragment(inventory.fragment)),true);
  Y.applyUpdate(probe,add);
  assert.equal(inspectDisposable(probe.getXmlFragment(inventory.fragment)).supported,true);
  assert.equal(oldFullPreflight(probe.getXmlFragment(inventory.fragment)),true);
  const original=Y.encodeStateAsUpdate(canonical);let writes=0;canonical.on('update',()=>writes++);
  const other=new Y.Doc();Y.applyUpdate(other,original);
  Y.applyUpdate(other,add);
  assert.equal(inspectDisposable(other.getXmlFragment(inventory.fragment)).supported,false);
  assert.equal(oldFullPreflight(other.getXmlFragment(inventory.fragment)),false);
  Y.applyUpdate(other,remove);
  assert.equal(inspectDisposable(other.getXmlFragment(inventory.fragment)).supported,true);
  assert.equal(oldFullPreflight(other.getXmlFragment(inventory.fragment)),true);
  assert.deepEqual(Y.encodeStateAsUpdate(other),Y.encodeStateAsUpdate(probe));
  assert.deepEqual(Y.encodeStateAsUpdate(canonical),original);
  assert.equal(writes,0,'no canonical binding writes');
  for (const doc of [canonical,writer,probe,other]) doc.destroy();
});

test('direct PM inventory has same verdict as prior conversion for valid paste, Undo and invalid marks/structures',()=>{
  const p=schema.nodes.paragraph.create(null,schema.text('paste ',[schema.marks.bold.create()]));
  const valid=schema.nodes.doc.create(null,[p]);
  const cases=[[valid,true], // paste/Undo's valid document shape
    [schema.nodes.doc.create(null,[schema.nodes.bulletList.create(null,[schema.nodes.listItem.create(null,p)])]),true],
    [schema.nodes.doc.create(null,[schema.nodes.taskList.create(null,[schema.nodes.taskItem.create({checked:true},p)])]),true],
    [schema.nodes.doc.create(null,[schema.nodes.paragraph.create(null,schema.text('link',[schema.marks.link.create({href:'https://example.org'})]))]),true],
    [schema.nodes.doc.create(null,[schema.nodes.heading.create({level:4},schema.text('future'))]),false],
    [schema.nodes.doc.create(null,[schema.nodes.orderedList.create({start:100001},[schema.nodes.listItem.create(null,p)])]),false],
    [schema.nodes.doc.create(null,[schema.nodes.taskList.create(null,[schema.nodes.taskItem.create({checked:'future'},p)])]),false],
    [schema.nodes.doc.create(null,[schema.nodes.paragraph.create(null,schema.text('bad',[schema.marks.link.create({href:'javascript:alert(1)'})]))]),false],
    [schema.nodes.doc.create(null,[schema.nodes.paragraph.create(null,schema.text('bad',[schema.marks.link.create({href:'https://example.org',target:'_self'})]))]),false]];
  for (const [pm,expected] of cases) {
    const copy=new Y.Doc();let old=false;
    try {prosemirrorToYXmlFragment(pm,copy.getXmlFragment(inventory.fragment));old=oldFullPreflight(copy.getXmlFragment(inventory.fragment));}
    catch {old=false;}
    assert.equal(old,expected,`old PM verdict ${JSON.stringify(pm.toJSON())}`);
    assert.equal(supportsProseMirror(pm),expected,JSON.stringify(pm.toJSON()));
    copy.destroy();
  }
});
