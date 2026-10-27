// @ts-nocheck
import * as Y from 'yjs';
import { getSchema } from '@tiptap/core';
import StarterKit from '@tiptap/starter-kit';
import TaskList from '@tiptap/extension-task-list';
import TaskItem from '@tiptap/extension-task-item';
import { initProseMirrorDoc } from '@tiptap/y-tiptap';
import { Mark } from '@tiptap/pm/model';
import inventory from '../../../../../note-schema/v1.json' with { type: 'json' };

// The inventory is shared with bh-core. Do not silently add a StarterKit node:
// every supported name, attribute and value must be checked before binding.
// Inline code combines with other marks but excludes itself: y-tiptap stores
// a non-self-excluding mark under a hashed `code--…` key the inventory lacks.
export const extensions = [
  StarterKit.extend({
    addExtensions() {
      return this.parent().map(extension=>extension.name==='code'
        ? extension.extend({excludes:'code'}) : extension);
    },
  }).configure({ undoRedo:false, trailingNode:false, codeBlock:false,
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
// The shared inventory has no cross-mark exclusions. Fail on a changed
// extension rather than silently disagreeing with the Rust classifier.
for (const [name,mark] of Object.entries(editorSchema.marks)) {
  for (const [otherName,other] of Object.entries(editorSchema.marks)) {
    if (name!==otherName && mark.excludes(other))
      throw new Error(`note schema mark exclusions diverged: ${name} excludes ${otherName}`);
  }
}


// Local editing policy shared with the core's checked authoring: a note larger
// than this many ProseMirror positions (UTF-16 units plus structure, about a
// million characters) is kept and shown read-only. Never a reason to refuse,
// truncate or stop saving content that is already accepted or received.
export const editingPositions=inventory.editingPositions;
export function withinEditingLimit(doc) {return doc.nodeSize<=editingPositions;}
export const isLeafNode=name=>!!editorSchema.nodes[name]?.isLeaf;

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
function supportedTextMarks(attributes={}) {
  return Object.entries(attributes).every(([mark,value])=>Object.hasOwn(inventory.marks,mark) &&
    supportedAttributes(value,inventory.marks[mark]));
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
        if (!supportedTextMarks(piece.attributes)) return 'unsupported mark combination or value';
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

// Only call this on a disposable document: projection may normalize its input.
// Return one combined classification/projection verdict so an incoming
// preflight can reuse it after applying the update to the live editing copy.
export function inspectDisposable(fragment) {
  const classification=classify(fragment);
  if (!classification.supported) return classification;
  if (fragment.length===0) return classification;
  let writes=0;
  const onUpdate=()=>writes++;
  fragment.doc.on('update',onUpdate);
  try {
    const projected=initProseMirrorDoc(fragment,editorSchema).doc;
    projected.check();
    return writes===0 ? classification : {supported:false,reason:'projection wrote to document'};
  } catch {return {supported:false,reason:writes?'projection wrote to document':'projection failed'}; }
  finally {fragment.doc.off('update',onUpdate);}
}

// Validate only the changed edge, its structural ancestors and any newly
// integrated subtree. In a supported document unchanged siblings were already
// checked at load; deleting a child still rechecks requiredFirst on its parent.
function checkYSubtree(node,parent,deep=true,seen=new Set()) {
  if (seen.has(node) && !deep) return true;
  seen.add(node);
  const name=node instanceof Y.XmlText?'text':node instanceof Y.XmlElement?node.nodeName:null;
  if (!name || !allowed[parent]?.has(name)) return false;
  if (name==='text') {
    if (Object.keys(node.getAttributes()).length) return false;
    return node.toDelta().every(piece=>typeof piece.insert==='string' && supportedTextMarks(piece.attributes));
  }
  if (!Object.hasOwn(inventory.nodes,name) || !supportedAttributes(node.getAttributes(),inventory.nodes[name])) return false;
  const first=inventory.requiredFirst[name];
  if (first && !first.includes(node.get(0) instanceof Y.XmlElement?node.get(0).nodeName:null)) return false;
  return !deep || node.toArray().every(child=>checkYSubtree(child,name,true,seen));
}
function inspectChanges(changes, fragment) {
  const seen=new Set();
  for (const [type,addedTypes] of changes) {
    if (type!==fragment && !(type instanceof Y.XmlElement) && !(type instanceof Y.XmlText)) continue;
    if (type!==fragment) {
      const parent=type.parent;
      if (parent && !checkYSubtree(type,parent===fragment?'default':parent.nodeName,false,seen)) return false;
    }
    for (const added of addedTypes) {
      if (added.parent!==type) continue; // inserted and removed in one transaction
      if (!checkYSubtree(added,type===fragment?'default':type.nodeName,true,seen)) return false;
    }
  }
  return true;
}

// Project on a separate probe: even if a future projection writes before
// reporting failure, the persistent mirror remains an exact copy of live.
function inspectMirror(doc) {
  if (!classify(doc.getXmlFragment(inventory.fragment)).supported) return false;
  const probe=new Y.Doc();
  try {
    Y.applyUpdate(probe,Y.encodeStateAsUpdate(doc));
    return inspectDisposable(probe.getXmlFragment(inventory.fragment)).supported;
  } catch {return false;} finally {probe.destroy();}
}

// One persistent copy per view. No projection ever runs on the live document.
// While unsupported, track invalid roots and recheck only changed subtrees;
// recovering full support requires a disposable projection check.
export function createPreflightMirror(live) {
  const doc=new Y.Doc();
  Y.applyUpdate(doc,Y.encodeStateAsUpdate(live));
  let supported=inspectMirror(doc);
  const invalidRoots=new Set();
  let invalidRootValues=0;
  function indexRoots(fragment) {
    invalidRoots.clear();invalidRootValues=0;
    for (const child of fragment.toArray()) {
      if (!(child instanceof Y.XmlElement || child instanceof Y.XmlText)) invalidRootValues++;
      else if (!checkYSubtree(child,'default')) invalidRoots.add(child);
    }
  }
  if (!supported) indexRoots(doc.getXmlFragment(inventory.fragment));
  return {
    doc,
    get supported(){return supported;},
    apply(bytes) {
      const fragment=doc.getXmlFragment(inventory.fragment),changes=new Map();
      const rootAdded=[],rootDeleted=[];
      let nonTypeInXml=false;
      const capture=events=>{
        for (const event of events) {
          if (event.target===fragment) {
            rootAdded.push(...event.changes.added);
            rootDeleted.push(...event.changes.deleted);
          }
          const types=changes.get(event.target)??[];
          for (const item of event.changes.added) {
            if (item.deleted) continue;
            if (item.content?.type) types.push(item.content.type);
            else if (event.target===fragment || event.target instanceof Y.XmlElement) nonTypeInXml=true;
            // XmlText strings and embeds are checked by its delta validator.
          }
          changes.set(event.target,types);
        }
      };
      fragment.observeDeep(capture);
      try {Y.applyUpdate(doc,bytes,'preflight');}
      catch {return {supported:false,uncertain:true};}
      finally {fragment.unobserveDeep(capture);}
      if (supported) {
        supported=!nonTypeInXml && inspectChanges(changes,fragment);
        if (!supported) indexRoots(fragment);
      } else {
        // The Yjs change set identifies new/deleted root items without
        // enumerating every old sibling. Recheck changed descendants too.
        for (const item of rootDeleted) if (item.content?.type) invalidRoots.delete(item.content.type);
        // Yjs GC may replace a deleted type's content before observeDeep
        // runs. Its original XmlElement still has the deleted _item.
        for (const root of invalidRoots) if (root._item?.deleted) invalidRoots.delete(root);
        const affected=new Set();
        for (const item of rootAdded) if (!item.deleted && item.content?.type) affected.add(item.content.type);
        if (changes.has(fragment)) invalidRootValues=fragment.toArray().filter(child=>
          !(child instanceof Y.XmlElement || child instanceof Y.XmlText)).length;
        for (const type of changes.keys()) {
          let root=type;
          while (root.parent && root.parent!==fragment) root=root.parent;
          if (root.parent===fragment && !root._item?.deleted) affected.add(root);
        }
        for (const root of affected) {
          if (checkYSubtree(root,'default')) invalidRoots.delete(root);
          else invalidRoots.add(root);
        }
        if (invalidRootValues===0 && !invalidRoots.size) supported=inspectMirror(doc);
      }
      return {supported,uncertain:false};
    },
    destroy(){doc.destroy();},
  };
}

// Validate the complete PM transaction inventory before ySync may write it.
// No PM->Yjs conversion or projection oracle runs on the canonical document.
const checkedPM=new WeakMap(); // PM nodes are immutable; the document root changes per edit.
export function supportsProseMirror(doc) {
  function visit(node,parent,level) {
    const name=node.type.name;
    // Count every PM node, including text: its shared type's parent must be
    // below depth 128. A 63-level list ends with text at depth 128.
    level+=1;
    if (level>128 || !allowed[parent]?.has(name)) return -1;
    // Cached nodes still have to fit when reparented deeper.
    if (checkedPM.has(node)) return level+checkedPM.get(node)<=128 ? level+checkedPM.get(node) : -1;
    if (name==='text') {
      if (Object.keys(node.attrs).length) return -1;
    } else if (!Object.hasOwn(inventory.nodes,name) ||
        !supportedAttributes(node.attrs,inventory.nodes[name]) ||
        !node.type.validContent(node.content)) return -1;
    const first=inventory.requiredFirst[name];
    if (first && !first.includes(node.firstChild?.type.name)) return -1;
    let canonical=Mark.none;
    for (const mark of node.marks) {
      if (!Object.hasOwn(inventory.marks,mark.type.name) ||
          !supportedAttributes(mark.attrs,inventory.marks[mark.type.name])) return -1;
      canonical=mark.addToSet(canonical);
    }
    if (!Mark.sameSet(canonical,node.marks)) return -1;
    let deepest=level;
    for (let i=0;i<node.childCount;i++) {
      const child=visit(node.child(i),name,level);
      if (child<0) return -1;
      deepest=Math.max(deepest,child);
    }
    checkedPM.set(node,deepest-level);
    return deepest;
  }
  try {
    // The root's block+ shape has one global condition; inventory validates
    // each child. Calling doc.check() here recursively walks every old block.
    if (doc.type.name!=='doc' || !doc.childCount || doc.marks.length ||
        Object.keys(doc.attrs).length || !doc.type.validContent(doc.content)) return false;
    for (let i=0;i<doc.childCount;i++) if (visit(doc.child(i),'default',0)<0) return false;
    return true;
  } catch {return false;}
}

// Render data only as text nodes and inert placeholders; never HTML, a URL,
// image, or an editor plugin. This view does not round-trip or modify the note.
export function safeViewNode(node) {
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
  return visit(node);
}
export function safeView(fragment) {
  return fragment.toArray().flatMap(safeViewNode);
}
