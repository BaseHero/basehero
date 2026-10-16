import test from 'node:test';
import assert from 'node:assert/strict';
import * as Y from 'yjs';
import { WriterGuard, editBound, historyBound, historyGrowth, LAST } from '../src/writer.mjs';
import { positionCost, isLeafNode } from '../src/schema.mjs';

const id=2002468231004600;
test('hydrate then assign exact native ID before any authoring observer',()=>{
  for(const clientId of [0,id,Number.MAX_SAFE_INTEGER]) {
    const source=new Y.Doc();source.getText('text').insert(0,'initial');
    const doc=new Y.Doc();Y.applyUpdate(doc,Y.encodeStateAsUpdate(source));
    const guard=new WriterGuard(doc,clientId,()=>{});
    const ids=[];doc.on('update',bytes=>ids.push(...Y.decodeUpdate(bytes).structs.map(s=>s.id.client)));
    assert.equal(ids.length,0);doc.getText('text').insert(0,'authored');
    assert.deepEqual(ids,[clientId]);assert.equal(guard.paused,false);
  }
});
test('a pending writer prefix is never assigned; the same ID resumes at its integrated clock',()=>{
  // Writer 42 inserts "b" after origin 1:2, which has not arrived yet.
  const doc=new Y.Doc();Y.applyUpdate(doc,new Uint8Array([1,1,42,0,132,1,2,1,98,0]));
  const reopened=new Y.Doc();Y.applyUpdate(reopened,Y.encodeStateAsUpdate(doc));
  assert.equal(Y.getState(reopened.store,42),0);
  assert.throws(()=>new WriterGuard(reopened,42,()=>{}));
  const guard=new WriterGuard(reopened,7,()=>{});
  const ids=[];reopened.on('update',bytes=>ids.push(...Y.decodeUpdate(bytes).structs.map(s=>[s.id.client,s.id.clock])));
  reopened.getText('mine').insert(0,'x');
  assert.deepEqual(ids,[[7,0]]);
  const dependency=new Y.Doc();dependency.clientID=1;dependency.getText('t').insert(0,'abc');
  Y.applyUpdate(reopened,Y.encodeStateAsUpdate(dependency));
  assert.equal(reopened.getText('t').toString(),'abcb');assert.equal(Y.getState(reopened.store,42),1);
  guard.assign(42);ids.length=0;reopened.getText('mine').insert(1,'y');
  assert.deepEqual(ids,[[42,1]]);
});
test('a used-up writer is never assigned; a run past the last clock blocks and keeps its bytes',()=>{
  const gc=len=>{const out=[1,1,42,0,0];while(len>=128){out.push(len%128+128);len=Math.floor(len/128);}return new Uint8Array([...out,len,0]);};
  const full=new Y.Doc();Y.applyUpdate(full,gc(2**32-1));
  assert.throws(()=>new WriterGuard(full,42,()=>{}));
  // Known limit: one page operation can need more clocks than remain. The
  // page stops authoring and keeps it; native decoding refuses it, never wraps.
  const doc=new Y.Doc();Y.applyUpdate(doc,gc(2**32-2));
  const guard=new WriterGuard(doc,42,()=>{});
  assert.equal(guard.blocked,false);
  const issued=[];doc.on('update',bytes=>issued.push(bytes));
  doc.getText('t').insert(0,'ab');
  assert.equal(guard.spent,true);assert.equal(guard.blocked,true);
  assert.deepEqual(Y.decodeUpdate(issued[0]).structs.map(s=>[s.id.client,s.id.clock,s.length]),[[42,2**32-2,2]]);
});
test('synchronous auto-ID tripwire keeps unsaved bytes on drain or reacquire failure',async()=>{
  const doc=new Y.Doc();let held=0;
  const guard=new WriterGuard(doc,id,()=>held++);
  const pending=[];doc.on('update',(bytes,origin)=>{if(origin!=='incoming')pending.push(bytes)});
  doc.getText('text').insert(0,'unsaved');const original=pending[0].slice();
  // A conflicting same-writer remote suffix makes Yjs swap the local ID.
  const remote=new Y.Doc();Y.applyUpdate(remote,Y.encodeStateAsUpdate(doc));remote.clientID=id;
  remote.getText('text').insert(7,'remote');
  guard.apply(()=>Y.applyUpdate(doc,Y.encodeStateAsUpdate(remote),'incoming'));
  assert.equal(guard.paused,true);assert.equal(held,1);assert.notEqual(doc.clientID,id);
  let opened=0;
  assert.equal(await guard.reacquire(async()=>false,async()=>{opened++;}),false);
  assert.equal(opened,0);assert.deepEqual(pending[0],original);
  const state=Y.encodeStateAsUpdate(doc);
  assert.equal(await guard.reacquire(async()=>true,async()=>{throw Error('unavailable')}),false);
  assert.deepEqual(Y.encodeStateAsUpdate(doc),state);assert.deepEqual(pending[0],original);
  assert.equal(guard.paused,true);
});
test('drained reacquisition preserves live Doc and only resumes with safe native ID',async()=>{
  const doc=new Y.Doc();const guard=new WriterGuard(doc,id,()=>{});
  doc.getText('text').insert(0,'keep');guard.hold();
  const order=[];
  assert.equal(await guard.reacquire(async()=>{order.push('drain');return true;},async()=>{
    order.push('native');return {clientId:42,hydrate(){order.push('hydrate');doc.getText('text').insert(4,' merged');}};
  }),true);
  assert.deepEqual(order,['drain','native','hydrate']);assert.equal(doc.clientID,42);
  assert.equal(doc.getText('text').toString(),'keep merged');assert.equal(guard.paused,false);
  assert.throws(()=>new WriterGuard(doc,2**53,()=>{}));
});
test('capacity is checked before an operation: fit, fresh writer, or no writer at all',()=>{
  const doc=new Y.Doc();
  // Writer 42 has durably used clocks 0..LAST-5 (one GC run).
  Y.applyUpdate(doc,new Uint8Array([1,1,42,0,0,250,255,255,255,15,0]));
  assert.equal(Y.getState(doc.store,42),LAST-5);
  const guard=new WriterGuard(doc,42,()=>{});
  assert.equal(guard.admit(5),'fit');
  assert.equal(guard.admit(6),'rollover');
  assert.equal(guard.admit(LAST),'rollover');
  assert.equal(guard.admit(LAST+1),'refuse');
  // The pinned schema's cost (six self-excluding marks, one format key each),
  // and the largest document a fresh writer can edit.
  assert.equal(positionCost,14);
  const largest=Math.floor((LAST-1)/(3*positionCost));
  assert.ok(editBound(largest)<=LAST && editBound(largest+1)>LAST);
});
test('Undo bound is the largest stack item deletion; actual redone clocks stay within it',()=>{
  const doc=new Y.Doc();doc.clientID=1;
  const text=doc.getText('t');text.insert(0,'abcdefgh');
  doc.clientID=42;
  const manager=new Y.UndoManager(text,{captureTimeout:0});
  text.delete(1,3);text.delete(0,2);
  assert.equal(historyBound(manager.undoStack),4);
  assert.equal(historyBound([]),1);
  for (const expected of [2,3]) {
    const bound=historyBound(manager.undoStack),before=Y.getState(doc.store,42);
    manager.undo();
    assert.equal(Y.getState(doc.store,42)-before,expected);assert.ok(expected<bound);
  }
  assert.equal(text.toString(),'abcdefgh');
});
test('history growth counts the positions an Undo could restore, not its clocks',()=>{
  const doc=new Y.Doc();doc.clientID=1;
  const fragment=doc.getXmlFragment('default');
  const paragraph=new Y.XmlElement('paragraph'),text=new Y.XmlText();
  text.insert(0,'ab\u{1F600}',{bold:{}});paragraph.insert(0,[text,new Y.XmlElement('hardBreak')]);
  fragment.insert(0,[paragraph]);
  doc.clientID=42;
  const manager=new Y.UndoManager(fragment,{captureTimeout:0});
  fragment.delete(0,1);
  // Paragraph 2 + "ab😀" 4 UTF-16 units + hard break 1; the text type and bold
  // markers occupy clocks (9, plus historyBound's migration entry) but no positions.
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),7);
  assert.equal(historyBound(manager.undoStack),10);
  assert.equal(historyGrowth(doc.store,[],isLeafNode),0);
  manager.undo();
  assert.equal(fragment.get(0).get(0).toString(),'<bold>ab\u{1F600}</bold>');
});
test('history growth ignores what one item both inserted and deleted',()=>{
  const doc=new Y.Doc();doc.clientID=5;
  const fragment=doc.getXmlFragment('default');
  const manager=new Y.UndoManager(fragment,{captureTimeout:10_000});
  const paragraph=new Y.XmlElement('paragraph'),text=new Y.XmlText();text.insert(0,'gone');
  paragraph.insert(0,[text]);fragment.insert(0,[paragraph]);
  fragment.delete(0,1);
  assert.equal(manager.undoStack.length,1);
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),0);
});
test('history growth looks only as deep as the item Undo will certainly apply',()=>{
  const doc=new Y.Doc();doc.clientID=1;
  const fragment=doc.getXmlFragment('default');
  const paragraph=new Y.XmlElement('paragraph'),text=new Y.XmlText();text.insert(0,'restore');
  paragraph.insert(0,[text]);fragment.insert(0,[paragraph]);
  doc.clientID=6;
  const manager=new Y.UndoManager(fragment,{captureTimeout:0});
  fragment.delete(0,1);
  // A deletion on top: Undo may restore its 9 positions.
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),9);
  fragment.insert(0,[new Y.XmlElement('paragraph')]);
  // A live insertion on top: Undo removes it and stops, restoring nothing.
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),0);
  // Once that insertion is gone (here, by a peer), Undo would pass it by.
  const peer=new Y.Doc();Y.applyUpdate(peer,Y.encodeStateAsUpdate(doc));
  peer.getXmlFragment('default').delete(0,1);
  Y.applyUpdate(doc,Y.encodeStateAsUpdate(peer,Y.encodeStateVector(doc)),'peer');
  assert.equal(manager.undoStack.length,2);
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),9);
});
test('history growth nets out the live insertions the same item removes',()=>{
  const doc=new Y.Doc();doc.clientID=1;
  const fragment=doc.getXmlFragment('default');
  const block=text=>{const p=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,text);p.insert(0,[t]);return p;};
  fragment.insert(0,[block('restore')]);
  doc.clientID=6;
  const manager=new Y.UndoManager(fragment,{captureTimeout:10_000});
  // One step replaces 9 positions with 5: its Undo grows the note by 4.
  doc.transact(()=>{fragment.delete(0,1);fragment.insert(0,[block('new')]);});
  assert.equal(manager.undoStack.length,1);
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),4);
  manager.undo();
  assert.equal(fragment.get(0).get(0).toString(),'restore');
});
test('history growth follows an insertion that Undo then Redo brought back',()=>{
  const doc=new Y.Doc();doc.clientID=1;
  const fragment=doc.getXmlFragment('default');
  const block=text=>{const p=new Y.XmlElement('paragraph'),t=new Y.XmlText();t.insert(0,text);p.insert(0,[t]);return p;};
  fragment.insert(0,[block('old')]);
  doc.clientID=6;
  const manager=new Y.UndoManager(fragment,{captureTimeout:0});
  fragment.delete(0,1);fragment.insert(0,[block('first')]);
  // Replace the block in one step; undoing it restores a copy of "first".
  doc.transact(()=>{fragment.delete(0,1);fragment.insert(0,[block('second')]);});
  manager.undo();
  assert.equal(fragment.get(0).get(0).toString(),'first');
  assert.equal(manager.undoStack.length,2);
  // The next Undo deletes that live copy and stops: "old" cannot come back yet.
  assert.equal(historyGrowth(doc.store,manager.undoStack,isLeafNode),0);
});
