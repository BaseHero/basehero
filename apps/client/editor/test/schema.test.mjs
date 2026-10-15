import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import { getSchema, Node, Mark } from '@tiptap/core';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { prosemirrorToYXmlFragment, initProseMirrorDoc } from '@tiptap/y-tiptap';
import { extensions, classify, safeView } from '../src/schema.mjs';

const schema = getSchema(extensions);
function note() { const doc = new Y.Doc(); return {doc, fragment: doc.getXmlFragment('default')}; }
function el(name, attributes = {}) {
  const element = new Y.XmlElement(name);
  for (const [key,value] of Object.entries(attributes)) element.setAttribute(key,value);
  return element;
}

test('inventory matches actual bundled editor nodes and marks', () => {
  assert.deepEqual(Object.keys(schema.nodes).sort(), ['blockquote','bulletList','doc','hardBreak','heading','listItem','orderedList','paragraph','taskItem','taskList','text'].sort());
  assert.deepEqual(Object.keys(schema.marks).sort(), ['bold','code','italic','link','strike','underline'].sort());
  for(const [name,mark] of Object.entries(schema.marks))
    for(const [otherName,other] of Object.entries(schema.marks))
      if(name!==otherName)assert.equal(mark.excludes(other),false,`${name} excludes ${otherName}`);
});

test('code and italic coexist in the shared fixture and project to an editable note', () => {
  const doc=new Y.Doc();Y.applyUpdate(doc,readFileSync(new URL('./code-italic.bin',import.meta.url)));
  const fragment=doc.getXmlFragment('default');
  assert.equal(classify(fragment).supported,true);
  const projected=initProseMirrorDoc(fragment,schema).doc;
  assert.deepEqual(projected.firstChild.firstChild.marks.map(mark=>mark.type.name).sort(),['code','italic']);
  doc.destroy();
});

test('reject unknown nodes, marks and attributes without mutating original bytes', () => {
  const { doc, fragment } = note();
  const p = el('paragraph'); const t = new Y.XmlText(); t.insert(0,'known'); p.insert(0,[t]); fragment.insert(0,[p]);
  assert.equal(classify(fragment).supported,true);
  const changes = [];
  doc.on('update', bytes => changes.push(bytes));
  const before = Buffer.from(Y.encodeStateAsUpdate(doc));
  const unknown = el('futureWidget',{payload:'keep'}); fragment.insert(1,[unknown]);
  const withUnknown = Buffer.from(Y.encodeStateAsUpdate(doc)); changes.length = 0;
  assert.equal(classify(fragment).supported,false);
  assert.equal(safeView(fragment).some(item => item.placeholder),true);
  assert.deepEqual(Buffer.from(Y.encodeStateAsUpdate(doc)),withUnknown);
  assert.equal(changes.length,0);
  fragment.delete(1,1);
  p.setAttribute('futureAttr','private'); changes.length = 0;
  assert.equal(classify(fragment).supported,false);
  assert.equal(changes.length,0);
  p.removeAttribute('futureAttr'); t.format(0,5,{futureMark:{secret:'kept'}}); changes.length = 0;
  assert.equal(classify(fragment).supported,false);
  assert.equal(changes.length,0);
  assert.notDeepEqual(before,Buffer.from(Y.encodeStateAsUpdate(doc)));
});

test('reject unknown values including unsafe URLs and future schema can recognize unchanged source', () => {
  const {doc,fragment}=note();
  const heading = el('heading',{level:4}); const txt = new Y.XmlText(); txt.insert(0,'future'); heading.insert(0,[txt]); fragment.insert(0,[heading]);
  const original = Buffer.from(Y.encodeStateAsUpdate(doc));
  assert.equal(classify(fragment).supported,false);
  assert.deepEqual(Buffer.from(Y.encodeStateAsUpdate(doc)), original);
  // Later releases can recognize an original unknown block without placeholder writeback.
  fragment.delete(0,1);
  const widget=el('futureWidget',{payload:'keep'});const text=new Y.XmlText();text.insert(0,'future text');widget.insert(0,[text]);fragment.insert(0,[widget]);
  const futureWidget=Node.create({name:'futureWidget',group:'block',content:'inline*',
    addAttributes(){return {payload:{default:null}};},
    parseHTML(){return [{tag:'future-widget'}];},renderHTML(){return ['future-widget',0];}});
  const future = getSchema([...extensions,futureWidget]);
  const untouched=Buffer.from(Y.encodeStateAsUpdate(doc));
  assert.equal(initProseMirrorDoc(fragment,future).doc.firstChild.attrs.payload,'keep');
  assert.deepEqual(Buffer.from(Y.encodeStateAsUpdate(doc)),untouched);
  fragment.delete(0,1);
  const para=el('paragraph'); const link=new Y.XmlText(); link.insert(0,'click',{link:{href:'javascript:alert(1)',target:'_blank',rel:'noopener noreferrer nofollow',class:null,title:null}}); para.insert(0,[link]);fragment.insert(0,[para]);
  assert.equal(classify(fragment).supported,false);
});

test('later recognizing schemas read original unknown mark, attribute and value without rewriting', () => {
  const futureMark=Mark.create({name:'futureMark',addAttributes(){return {secret:{default:null}};},
    parseHTML(){return [{tag:'future-mark'}];},renderHTML(){return ['future-mark',0];}});
  const futureParagraph=Node.create({name:'paragraph',group:'block',content:'inline*',
    addAttributes(){return {futureAttr:{default:null}};},
    parseHTML(){return [{tag:'p'}];},renderHTML(){return ['p',0];}});
  const futureCases=[
    ['mark',getSchema([...extensions,futureMark]),doc=>doc.firstChild.firstChild.marks[0].attrs.secret],
    ['attr',getSchema([extensions[0].configure({paragraph:false}),extensions[1],extensions[2],futureParagraph]),doc=>doc.firstChild.attrs.futureAttr],
    ['value',getSchema([extensions[0].configure({heading:{levels:[1,2,3,4]}}),extensions[1],extensions[2]]),doc=>doc.firstChild.attrs.level],
  ];
  for(const [name,future,read] of futureCases) {
    const doc=new Y.Doc();Y.applyUpdate(doc,readFileSync(new URL(`./${name}.bin`,import.meta.url)));
    const fragment=doc.getXmlFragment('default');
    assert.equal(classify(fragment).supported,false);
    const before=Buffer.from(Y.encodeStateAsUpdate(doc));let writes=0;doc.on('update',()=>writes++);
    const opened=initProseMirrorDoc(fragment,future).doc;
    assert.equal(read(opened),name==='value'?4:'keep');
    assert.equal(writes,0);assert.deepEqual(Buffer.from(Y.encodeStateAsUpdate(doc)),before);
  }
});

test('Rust yrs edit of real rich fixture opens in actual Yjs/Tiptap without binding writes', () => {
  const bytes=execFileSync('cargo',['run','--locked','--offline','--quiet','-p','bh-core','--example','note_to_yjs'],
    {cwd:new URL('../../../../',import.meta.url),maxBuffer:1024*1024});
  const doc=new Y.Doc();Y.applyUpdate(doc,bytes);
  const fragment=doc.getXmlFragment('default');
  assert.equal(classify(fragment).supported,true);
  const before=Buffer.from(Y.encodeStateAsUpdate(doc));let writes=0;
  doc.on('update',()=>writes++);
  const opened=initProseMirrorDoc(fragment,schema).doc;
  assert.equal(opened.childCount,4);
  assert.equal(opened.lastChild.textContent,'from Rust core');
  assert.equal(opened.child(2).type.name,'taskList');
  assert.equal(opened.child(1).child(1).marks[0].attrs.href,'https://example.org');
  assert.equal(writes,0);
  assert.deepEqual(Buffer.from(Y.encodeStateAsUpdate(doc)),before);
});

test('explicit rich structures round-trip through actual Yjs/Tiptap conversion', () => {
  const {fragment}=note();
  const p=schema.nodes.paragraph.create(null,[schema.text('safe ',[schema.marks.bold.create()]),schema.text('link',[schema.marks.link.create({href:'https://example.org'})])]);
  const checklist=schema.nodes.taskList.create(null,[schema.nodes.taskItem.create({checked:true},schema.nodes.paragraph.create(null,schema.text('done')))]);
  const pm=schema.nodes.doc.create(null,[p,schema.nodes.heading.create({level:2},schema.text('Heading')),checklist]);
  prosemirrorToYXmlFragment(pm,fragment);
  assert.equal(classify(fragment).supported,true);
  assert.deepEqual(initProseMirrorDoc(fragment,schema).doc.toJSON(),pm.toJSON());
});
