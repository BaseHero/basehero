import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import { prosemirrorToYXmlFragment } from '@tiptap/y-tiptap';
import { extensions, editingPositions, withinEditingLimit } from '../src/schema.mjs';

// The core reads positions.bin and must count the same 28 positions: UTF-16
// units (an emoji and a supplementary-plane heading are two each), one for a
// hard break and two per block, list item and list, plus the document.
test('the shared editing budget counts ProseMirror positions, not characters or bytes',()=>{
  const schema=getSchema(extensions),n=schema.nodes;
  const pm=n.doc.create(null,[
    n.paragraph.create(null,[schema.text('a\u{1F600}b',[schema.marks.bold.create()]),n.hardBreak.create(),schema.text('c')]),
    n.bulletList.create(null,n.listItem.create(null,[n.paragraph.create(null,schema.text('x')),
      n.bulletList.create(null,n.listItem.create(null,n.paragraph.create(null,schema.text('\u00e9'))))])),
    n.heading.create({level:1},schema.text('\u{1D11E}')),
  ]);
  assert.equal(pm.nodeSize,28);
  const doc=new Y.Doc();doc.clientID=231;
  prosemirrorToYXmlFragment(pm,doc.getXmlFragment('default'));
  const bytes=Buffer.from(Y.encodeStateAsUpdate(doc));
  const fixture=new URL('positions.bin',import.meta.url);
  if(process.env.BH_WRITE_FIXTURES)writeFileSync(fixture,bytes);
  assert.deepEqual(bytes,readFileSync(fixture));
});

test('a document is editable up to exactly one million positions',()=>{
  const schema=getSchema(extensions);
  const block=length=>schema.nodes.paragraph.create(null,length?schema.text('a'.repeat(length)):null);
  // One paragraph of 999,996 units: 999,996 + 2 + 2 = 1,000,000 positions.
  assert.equal(withinEditingLimit(schema.nodes.doc.create(null,block(999_996))),true);
  assert.equal(withinEditingLimit(schema.nodes.doc.create(null,block(999_997))),false);
  assert.equal(editingPositions,1_000_000);
});
