// Manual long-failure measurement, not a timing-gated test:
// node test/measure-queue.mjs [count] (run inside the project Nix shell).
import * as Y from 'yjs';
import {SaveQueue} from '../src/save-queue.mjs';
const count=Number(process.argv[2]??144000);
const doc=new Y.Doc(),text=doc.getText('note'),queue=new SaveQueue();
let totalInput=0,mergeCalls=0,maxMergeInput=0;
const merge=queue.merge;
queue.merge=parts=>{
  const bytes=parts.reduce((sum,part)=>sum+part.length,0);
  maxMergeInput=Math.max(maxMergeInput,bytes);mergeCalls++;
  return merge(parts);
};
doc.on('update',bytes=>{totalInput+=bytes.length;queue.append(bytes);});
const start=performance.now();
text.insert(text.length,'x');
const first=queue.submit('failed-head');
for(let i=1;i<count;i++)text.insert(text.length,'x');
const appendMs=performance.now()-start;
// Keep the first attempt immutable for the whole failure, then retry and drain.
if(queue.submit('retry').bytes!==first.bytes || queue.submit('retry').id!=='failed-head')
  throw Error('attempt changed');
queue.acknowledge();
let chunk=1;const times=[];
while(queue.count){
  const before=performance.now();queue.submit(String(chunk++));times.push(performance.now()-before);
  queue.acknowledge();
}
times.sort((a,b)=>a-b);
console.log(JSON.stringify({count,totalInput,appendMs,chunks:chunk,mergeCalls,maxMergeInput,
  submitP50Ms:times[Math.floor(times.length*.5)],submitP95Ms:times[Math.floor(times.length*.95)],
  maxSubmitMs:times.at(-1),retainedBytes:queue.retainedBytes}));
doc.destroy();
