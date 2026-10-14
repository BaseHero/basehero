// Expected RED with @tiptap/y-tiptap 3.0.9. This is the actual conversion
// used by its ySyncPlugin; not a JSON-only sketch or an app-shipped editor.
// Run after npm ci: npm run proof:unknown. Do NOT wire into green default checks.
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import StarterKit from '@tiptap/starter-kit';
import { initProseMirrorDoc, updateYFragment } from '@tiptap/y-tiptap';

const schema = getSchema([StarterKit.configure({ undoRedo: false, trailingNode: false, codeBlock: false })]);
const doc = new Y.Doc();
const fragment = doc.getXmlFragment('default');
function block(name, text) {
  const p = new Y.XmlElement(name);
  const t = new Y.XmlText();
  t.insert(0, text);
  p.insert(0, [t]);
  return p;
}
const before = block('paragraph', 'known before');
const unknown = block('futureWidget', 'private future payload');
unknown.setAttribute('payload', 'opaque:keep-me');
const after = block('paragraph', 'known after');
fragment.insert(0, [before, unknown, after]);
const original = Y.encodeStateAsUpdate(doc);
let unexpectedWrites = 0;
doc.on('update', () => unexpectedWrites++);
const binding = initProseMirrorDoc(fragment, schema);
// Simulate a normal editor transaction in an adjacent known node via the
// same y-prosemirror update path. Conversion must not rewrite unknown nodes.
const edited = binding.doc.type.create(null, [
  schema.nodes.paragraph.create(null, schema.text('known before edited')),
  ...binding.doc.content.content.slice(1),
]);
updateYFragment(doc, fragment, edited, binding.meta);
const preserved = fragment.toArray().find(el => el.nodeName === 'futureWidget');
console.log({ originalBytes: original.length, unknownPresent: !!preserved,
  unexpectedWrites, result: fragment.toString() });
assert.ok(preserved, 'editing known neighbor must retain unknown Y.XmlElement');
assert.equal(preserved.getAttribute('payload'), 'opaque:keep-me');
assert.equal(preserved.toArray()[0].toString(), 'private future payload');
