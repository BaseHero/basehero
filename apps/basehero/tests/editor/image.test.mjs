import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import { extensions, classify, supportsProseMirror } from '../../src/lib/editor/schema.mjs';
import old from '../../../../note-schema/v1.json' with { type: 'json' };

const id = 'abcdef0123456789abcdef0123456789';
function check(attrs, child) {
  const doc = new Y.Doc(), body = doc.getXmlFragment('default');
  const image = new Y.XmlElement('image');
  for (const [key,value] of Object.entries(attrs)) image.setAttribute(key,value);
  if (child) image.insert(0,[new Y.XmlText('child')]);
  body.insert(0,[image]);
  const result = classify(body).supported;
  doc.destroy();
  return result;
}
test('schema v2 accepts an image with a 32-hex file id', () => {
  assert.equal(check({ file: id }), true);
  const schema = getSchema(extensions);
  assert.equal(supportsProseMirror(schema.nodes.doc.create(null,[schema.nodes.image.create({file:id})])), true);
});
test('schema v2 rejects an image with another attribute, an uppercase id or a child', () => {
  assert.equal(check({file:id, src:'https://x/y'}), false);
  assert.equal(check({file:id.toUpperCase()}), false);
  assert.equal(check({file:id},true), false);
});
test('schema v1 still finds an image unsupported, so older apps open the note read-only', () => {
  assert.equal(old.version,1);
  assert.equal(Object.hasOwn(old.nodes,'image'),false);
});
test('an image may not be the first child of a list item', () => {
  const schema=getSchema(extensions);
  const item=schema.nodes.listItem.create(null,[schema.nodes.image.create({file:id})]);
  const list=schema.nodes.bulletList.create(null,[item]);
  assert.equal(supportsProseMirror(schema.nodes.doc.create(null,[list])),false);
});
