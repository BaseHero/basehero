import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import StarterKit from '@tiptap/starter-kit';
import { prosemirrorToYXmlFragment, initProseMirrorDoc } from '@tiptap/y-tiptap';

const schema = getSchema([StarterKit.configure({ undoRedo:false, trailingNode:false, codeBlock:false })]);
const doc = new Y.Doc();
doc.clientID = 121;
const fragment = doc.getXmlFragment('default');
const text = (value, marks = []) => schema.text(value, marks);
const paragraph = (children) => schema.nodes.paragraph.create(null, children);
const item = (children) => schema.nodes.listItem.create(null, children);
const nested = schema.nodes.bulletList.create(null, [
  item([paragraph([text('parent ', [schema.marks.bold.create()]), text('item')]),
    schema.nodes.bulletList.create(null, [item([paragraph([text('nested ', [schema.marks.italic.create()]), text('item')])])])]),
]);
const pm = schema.nodes.doc.create(null, [paragraph([text('intro')]), nested]);
prosemirrorToYXmlFragment(pm, fragment);
const fixture = Buffer.from(Y.encodeStateAsUpdate(doc));
if (process.argv.includes('--write')) {
  writeFileSync(new URL('known.bin', import.meta.url), fixture);
} else {
  assert.deepEqual(fixture, readFileSync(new URL('known.bin', import.meta.url)));
}
const copy = new Y.Doc();
Y.applyUpdate(copy, fixture);
assert.deepEqual(initProseMirrorDoc(copy.getXmlFragment('default'), schema).doc.toJSON(), pm.toJSON());
const a = new Y.Doc();
const b = new Y.Doc();
a.clientID = 122;
b.clientID = 123;
Y.applyUpdate(a, fixture);
Y.applyUpdate(b, fixture);
function append(document, content) {
  const fragment = document.getXmlFragment('default');
  const p = new Y.XmlElement('paragraph');
  const t = new Y.XmlText();
  t.insert(0, content);
  p.insert(0, [t]);
  fragment.insert(fragment.length, [p]);
}
append(a, 'edit A');
append(b, 'edit B');
const aUpdate = Y.encodeStateAsUpdate(a);
const bUpdate = Y.encodeStateAsUpdate(b);
Y.applyUpdate(a, bUpdate);
Y.applyUpdate(b, aUpdate);
assert.equal(a.getXmlFragment('default').toString(), b.getXmlFragment('default').toString());
assert.match(a.getXmlFragment('default').toString(), /edit A/);
assert.match(a.getXmlFragment('default').toString(), /edit B/);
console.log(`known nested-list/mark fixture: ${fixture.length} bytes; Tiptap/Yjs round-trip and concurrent merge passed`);
