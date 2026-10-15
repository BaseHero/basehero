// Test-only copy of the pre-change FULL classifier and projection path.
// Keep independent of the production classifier when checking changed preflight.
import * as Y from 'yjs';
import {getSchema} from '@tiptap/core';
import {initProseMirrorDoc} from '@tiptap/y-tiptap';
import {extensions,inventory} from '../src/schema.mjs';
const schema=getSchema(extensions);
const allowed=Object.fromEntries(Object.entries(inventory.children).map(([name,children])=>[name,new Set(children)]));
function valueMatches(rule,value) {
  if ('enum' in rule) return rule.enum.some(item=>item===value);
  if ('integer' in rule) return Number.isSafeInteger(value)&&value>=rule.integer[0]&&value<=rule.integer[1];
  if ('url' in rule) {
    if(typeof value!=='string'||/[\u0000-\u001f\u007f]/u.test(value)) return false;
    try {const url=new URL(value);return rule.url.includes(url.protocol)&&!!url.hostname;} catch {return false;}
  }
  return false;
}
function attributes(value,rules) {
  return !!value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.entries(value).every(([name,attr])=>Object.hasOwn(rules,name)&&valueMatches(rules[name],attr));
}
function classifyOld(fragment) {
  function visit(node,parent) {
    const name=node instanceof Y.XmlText?'text':node instanceof Y.XmlElement?node.nodeName:null;
    if(!name||!allowed[parent]?.has(name))return false;
    if(name==='text') {
      if(Object.keys(node.getAttributes()).length)return false;
      return node.toDelta().every(piece=>typeof piece.insert==='string'&&
        Object.entries(piece.attributes??{}).every(([mark,value])=>Object.hasOwn(inventory.marks,mark)&&attributes(value,inventory.marks[mark])));
    }
    if(!Object.hasOwn(inventory.nodes,name)||!attributes(node.getAttributes(),inventory.nodes[name]))return false;
    const children=node.toArray(),first=inventory.requiredFirst[name];
    return (!first||first.includes(children[0] instanceof Y.XmlElement?children[0].nodeName:null))&&
      children.every(child=>visit(child,name));
  }
  return fragment.toArray().every(child=>visit(child,'default'));
}
export function oldFullPreflight(fragment) {
  if(!classifyOld(fragment))return false;
  if(fragment.length===0)return true;
  const probe=new Y.Doc();
  try {
    Y.applyUpdate(probe,Y.encodeStateAsUpdate(fragment.doc));
    let writes=0;probe.on('update',()=>writes++);
    const projected=initProseMirrorDoc(probe.getXmlFragment(inventory.fragment),schema).doc;
    projected.check();return writes===0;
  } catch {return false;} finally {probe.destroy();}
}
