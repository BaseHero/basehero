#!/usr/bin/env node
// Prepare the single pinned Yjs dependency even after npm ci --ignore-scripts.
// See ../patches/yjs-13.6.33.md for upstream licence and exact source hashes.
import {readFileSync,writeFileSync,renameSync,unlinkSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const packageRoot=process.argv[2]??join(dirname(fileURLToPath(import.meta.url)),'../node_modules/yjs');
const files=[
  ['src/types/YText.js','9bb124a3bc5ae724ce4a77c705643da29c2d414edb153939df99804db842e07e','3c668b2fb276e989b45df221b1b46e74dca8491fc15202982398a83e5f94525a'],
  ['dist/yjs.mjs','a514c183100fc375eb46df9cb58acaf0deabbf414d2508841336179b1cb45107','600b936c54f1762149df08f39eb0b9c278a2fe62d5da682517c4b51282a36e02'],
  ['dist/yjs.cjs','8891769da278d678988510fbe27844082fb1674132e847633dd8d114497c61ce','ae5d5a05692f11658a99997ba739e9a043d141eb7c7ce7e3d2277a5c25c03605'],
];
const changes=[
  [/} else if \(value !== null\) \{\n\s*item.delete\(transaction\);?\n\s*}/g,'}'],
  [/} else if \(attr !== null\) \{[^\n]*\n\s*item.delete\(transaction\);?\n\s*}/g,'}'],
  [/    \/\/ If a remote change happened, we try to cleanup potential formatting duplicates\.\n    if \(!transaction\.local && this\._hasFormatting\) \{\n      transaction\._needFormattingCleanup = true;?\n    \}\n/g,''],
];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function prepare(){
  const pkg=JSON.parse(readFileSync(join(packageRoot,'package.json'),'utf8'));
  if(pkg.name!=='yjs'||pkg.version!=='13.6.33') throw Error('refusing non-pinned Yjs package');
  // Validate every file and its output before changing any file. A mixed
  // pristine/patched install is accepted only when every input is known.
  const writes=[];
  for(const [name,pristine,patched] of files){
    const path=join(packageRoot,name),source=readFileSync(path),digest=sha(source);
    if(digest===patched) continue;
    if(digest!==pristine) throw Error(`refusing unknown Yjs content: ${name} (${digest})`);
    let output=source.toString('utf8');
    for(const [pattern,replacement] of changes){
      let count=0;
      output=output.replace(pattern,()=>{count++;return replacement;});
      if(count!==1) throw Error(`refusing unexpected Yjs source: ${name}`);
    }
    if(sha(output)!==patched) throw Error(`refusing unexpected Yjs output: ${name}`);
    writes.push([path,output]);
  }
  for(const [path,output] of writes){
    const tmp=`${path}.bh-prepare-${process.pid}`;
    try{writeFileSync(tmp,output,{flag:'wx'});renameSync(tmp,path);}
    catch(error){try{unlinkSync(tmp);}catch{}throw error;}
  }
  console.log(`Yjs 13.6.33 prepared: ${writes.length} file(s) updated, ${files.length-writes.length} already patched`);
}
try{prepare();}catch(error){console.error(`patch-yjs: ${error.message}`);process.exitCode=1;}
