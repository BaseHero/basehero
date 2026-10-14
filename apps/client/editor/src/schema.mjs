import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import StarterKit from '@tiptap/starter-kit';
import TaskList from '@tiptap/extension-task-list';
import TaskItem from '@tiptap/extension-task-item';
import { initProseMirrorDoc } from '@tiptap/y-tiptap';
import inventory from '../../../../note-schema/v1.json' with { type: 'json' };

// The inventory is shared with bh-core. Do not silently add a StarterKit node:
// every supported name, attribute and value must be checked before binding.
export const extensions = [
  StarterKit.configure({ undoRedo:false, trailingNode:false, codeBlock:false,
    horizontalRule:false, heading:{levels:inventory.nodes.heading.level.enum},
    link:{openOnClick:false,autolink:false,linkOnPaste:false} }),
  TaskList, TaskItem.configure({ nested:true }),
];
export { inventory };

// Fail the bundled build if StarterKit silently adds or removes a structure or
// attribute not in the static inventory. The actual editor uses these extensions.
const editorSchema=getSchema(extensions);
for (const [types, names] of [[editorSchema.nodes, [...Object.keys(inventory.nodes),'doc','text']],
  [editorSchema.marks,Object.keys(inventory.marks)]]) {
  if (JSON.stringify(Object.keys(types).sort())!==JSON.stringify(names.sort())) throw new Error('note schema names diverged');
  for (const name of Object.keys(types)) {
    if(name==='doc'||name==='text') continue;
    if(JSON.stringify(Object.keys(types[name].spec.attrs??{}).sort())!==
       JSON.stringify(Object.keys((types===editorSchema.nodes?inventory.nodes:inventory.marks)[name]).sort()))
      throw new Error(`note schema attributes diverged: ${name}`);
  }
}

function valueMatches(rule, value) {
  if ('enum' in rule) return rule.enum.some(item => item === value);
  if ('integer' in rule) return Number.isSafeInteger(value) && value >= rule.integer[0] && value <= rule.integer[1];
  if ('url' in rule) {
    if (typeof value !== 'string' || /[\u0000-\u001f\u007f]/u.test(value)) return false;
    try { const url = new URL(value); return rule.url.includes(url.protocol) && !!url.hostname; }
    catch { return false; }
  }
  return false;
}
function supportedAttributes(value, rules) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.entries(value).every(([name, attr]) => Object.hasOwn(rules,name) && valueMatches(rules[name],attr));
}
const allowed = Object.fromEntries(Object.entries(inventory.children).map(([name,children])=>[name,new Set(children)]));

// No editor/plugin may see the actual document until this check passes. Read
// Yjs types and delta metadata directly; even projecting an unknown with the
// editor's binding could change the original canonical document.
export function classify(fragment) {
  function visit(node, parent) {
    const name = node instanceof Y.XmlText ? 'text' : node instanceof Y.XmlElement ? node.nodeName : null;
    if (!name || !allowed[parent]?.has(name)) return `unsupported structure: ${String(name)}`;
    if (name === 'text') {
      if (Object.keys(node.getAttributes()).length) return 'unsupported text attribute';
      for (const piece of node.toDelta()) {
        if (typeof piece.insert !== 'string') return 'unsupported text embed';
        for (const [mark, value] of Object.entries(piece.attributes ?? {})) {
          if (!Object.hasOwn(inventory.marks,mark) || !supportedAttributes(value,inventory.marks[mark])) return `unsupported mark: ${mark}`;
        }
      }
      return null;
    }
    if (!Object.hasOwn(inventory.nodes,name) || !supportedAttributes(node.getAttributes(),inventory.nodes[name])) return `unsupported node or attribute: ${name}`;
    const children=node.toArray();
    const first=inventory.requiredFirst[name];
    if (first && !first.includes(children[0] instanceof Y.XmlElement ? children[0].nodeName : null)) return `unsupported structure: ${name}`;
    for (const child of children) { const error=visit(child,name); if (error) return error; }
    return null;
  }
  for (const child of fragment.toArray()) { const error=visit(child,'default'); if (error) return {supported:false,reason:error}; }
  return {supported:true};
}

export function canBind(fragment) {
  if (!classify(fragment).supported) return false;
  // The editor creates its empty paragraph locally; an empty canonical note
  // has no unsupported content and no projection to validate yet.
  if (fragment.length===0) return true;
  const probe=new Y.Doc();
  try {
    Y.applyUpdate(probe,Y.encodeStateAsUpdate(fragment.doc));
    let writes=0;probe.on('update',()=>writes++);
    const projected=initProseMirrorDoc(probe.getXmlFragment(inventory.fragment),editorSchema).doc;
    projected.check();
    return writes===0;
  } catch {return false;} finally {probe.destroy();}
}

// Render data only as text nodes and inert placeholders; never HTML, a URL,
// image, or an editor plugin. This view does not round-trip or modify the note.
export function safeView(fragment) {
  function visit(node) {
    if (node instanceof Y.XmlText) {
      if (Object.keys(node.getAttributes()).length) return [{placeholder:true}];
      return node.toDelta().map(part => {
      if (typeof part.insert !== 'string' || Object.entries(part.attributes ?? {}).some(([mark,attrs]) =>
        !Object.hasOwn(inventory.marks,mark) || !supportedAttributes(attrs,inventory.marks[mark]))) return {placeholder:true};
      return {text:part.insert};
      });
    }
    if (!(node instanceof Y.XmlElement) || !Object.hasOwn(inventory.nodes,node.nodeName) ||
        !supportedAttributes(node.getAttributes(),inventory.nodes[node.nodeName])) return [{placeholder:true}];
    const nodes=node.toArray();
    const first=inventory.requiredFirst[node.nodeName];
    if (first && !first.includes(nodes[0] instanceof Y.XmlElement ? nodes[0].nodeName : null)) return [{placeholder:true}];
    const children=nodes.flatMap(visit);
    return [{label:node.nodeName,children}];
  }
  return fragment.toArray().flatMap(visit);
}
