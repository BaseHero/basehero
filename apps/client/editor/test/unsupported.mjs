import assert from 'node:assert/strict';
import { readFileSync,writeFileSync } from 'node:fs';
import * as Y from 'yjs';
import {classify} from '../src/schema.mjs';
const cases=['mark','attr','value','textAttr'];
for(const [i,kind] of cases.entries()) {
  const doc=new Y.Doc();doc.clientID=241+i;
  const frag=doc.getXmlFragment('default');const node=new Y.XmlElement(kind==='value'?'heading':'paragraph');
  if(kind==='value')node.setAttribute('level',4);
  if(kind==='attr')node.setAttribute('futureAttr','keep');
  const text=new Y.XmlText();text.insert(0,'hello',kind==='mark'?{futureMark:{secret:'keep'}}:{});
  if(kind==='textAttr')text.setAttribute('futureTextAttr','keep');
  node.insert(0,[text]);frag.insert(0,[node]);
  assert.equal(classify(frag).supported,false);
  const bytes=Buffer.from(Y.encodeStateAsUpdate(doc));
  const path=new URL(`${kind}.bin`,import.meta.url);
  if(process.argv.includes('--write'))writeFileSync(path,bytes);
  else assert.deepEqual(bytes,readFileSync(path));
}
console.log('four unsupported-content fixtures stay unchanged');
