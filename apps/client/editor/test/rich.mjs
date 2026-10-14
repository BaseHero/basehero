import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import { prosemirrorToYXmlFragment } from '@tiptap/y-tiptap';
import { extensions, classify } from '../src/schema.mjs';

const schema=getSchema(extensions);
const doc=new Y.Doc();doc.clientID=230;
const pm=schema.nodes.doc.create(null,[
  schema.nodes.heading.create({level:2},schema.text('Heading')),
  schema.nodes.paragraph.create(null,[schema.text('bold',[schema.marks.bold.create()]),schema.text(' link',[schema.marks.link.create({href:'https://example.org'})])]),
  schema.nodes.taskList.create(null,[schema.nodes.taskItem.create({checked:true},schema.nodes.paragraph.create(null,schema.text('done')))]),
]);
const fragment=doc.getXmlFragment('default');prosemirrorToYXmlFragment(pm,fragment);
assert.equal(classify(fragment).supported,true);
const bytes=Buffer.from(Y.encodeStateAsUpdate(doc));
if(process.argv.includes('--write'))writeFileSync(new URL('rich.bin',import.meta.url),bytes);
else assert.deepEqual(bytes,readFileSync(new URL('rich.bin',import.meta.url)));
console.log(`rich inventory fixture: ${bytes.length} bytes`);
