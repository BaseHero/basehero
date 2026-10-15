import test from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import {SaveQueue} from '../src/save-queue.mjs';

function updates(count) {
  const doc=new Y.Doc(),text=doc.getText('note'),result=[];
  doc.on('update',bytes=>result.push(bytes));
  for(let i=0;i<count;i++) text.insert(text.length,'x');
  doc.destroy();
  return result;
}

test('a failed first attempt never makes subsequent typing merge growing backlog',()=>{
  const input=updates(20000);
  for (const count of [5000,10000,20000]) {
    let calls=0,mergedInput=0,maxInput=0;
    const queue=new SaveQueue(parts=>{
      calls++;const size=parts.reduce((sum,part)=>sum+part.length,0);
      mergedInput+=size;maxInput=Math.max(maxInput,size);
      return Y.mergeUpdates(parts);
    });
    queue.append(input[0]);const first=queue.submit('first');
    const submitted=[new Uint8Array(first.bytes)];
    for(let i=1;i<count;i++) queue.append(input[i]);
    assert.deepEqual(queue.submit('first'),first,'retry has identical bytes and ID');
    assert.equal(calls,0,'typing behind failed attempt must not merge backlog');
    assert.equal(queue.count,Math.ceil((count-1)/256)+1);
    queue.acknowledge();
    while(queue.count) {
      const attempt=queue.submit(`chunk-${submitted.length}`);
      submitted.push(new Uint8Array(attempt.bytes));queue.acknowledge();
    }
    const restored=new Y.Doc();
    for(const part of submitted)Y.applyUpdate(restored,part);
    assert.equal(restored.getText('note').toString(),'x'.repeat(count));restored.destroy();
    assert.equal(calls,Math.ceil((count-1)/256),'exactly one merge per sealed chunk');
    assert.ok(maxInput<=65536,'merge never decodes more than one bounded raw chunk');
    assert.ok(mergedInput<=input.slice(1,count).reduce((sum,part)=>sum+part.length,0));
    assert.equal(queue.retainedBytes,0);
  }
});

test('an oversized update stands alone; ack releases large consumed payloads immediately',()=>{
  const queue=new SaveQueue();
  const original=new Uint8Array(1024*1024);
  queue.append(original);queue.append(new Uint8Array([1]));
  assert.equal(queue.count,2);
  const attempted=queue.submit('head');
  assert.equal(attempted.bytes.length,original.length);
  const owned=new Uint8Array(attempted.bytes);
  queue.acknowledge();
  assert.equal(queue.retainedBytes,1,'consumed megabyte no longer referenced');
  assert.equal(queue.submit('tail').id,'tail');queue.acknowledge();
  assert.equal(queue.retainedBytes,0);
  assert.deepEqual(owned,new Uint8Array(1024*1024),'host copy is not wiped');
  assert.equal(queue.count,0);
});
