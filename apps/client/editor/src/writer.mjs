import * as Y from 'yjs';
import { positionCost } from './schema.mjs';

// Native (yrs) clocks are u32: a writer's run may end exactly here, never past.
export const LAST=2**32-1;

// Yjs cannot refuse a write once it starts, so each local operation is bounded
// before it is accepted. For pinned y-tiptap 3.0.10 and Yjs 13.6.33, one
// ProseMirror edit runs updateYFragment over the new document, then for a
// structural edit applyPositionMigration. Each pass creates or updates every
// node of the new document at most once: positionCost per position covers a
// new text node (its characters, one text type, a start and end marker per
// format key) or an updated one (a diff insertion no longer than its text,
// markers per key), and an element with its attributes. Migration may also
// recreate a subtree once, then adds one map entry. Deletions use no clocks.
export function editBound(nodeSize) {return 3*positionCost*nodeSize+1;}
// Undo/Redo pops stack items until one changes the document; only structs in
// that item's deletion set are redone, each once. Take the largest item, plus
// y-tiptap's one position-migration entry. No history is truncated.
export function historyBound(stack) {
  let most=0;
  for (const item of stack) {
    let length=0;
    item.deletions.clients.forEach(ranges=>{for (const range of ranges) length+=range.len;});
    most=Math.max(most,length);
  }
  return most+1;
}

// Most ProseMirror positions the next Undo/Redo could add. Yjs pops items from
// the top until one changes the note and applies that one whole: it deletes
// the item's live insertions, or their redone copies (certainly a change, so
// look no deeper) and may
// restore its deletions. Positions are text units, two per element and one
// per leaf (a hard break); text types and formatting markers take clocks but
// no positions, a garbage-collected struct cannot return, and Yjs never redoes
// a struct the same item both inserted and deleted. Linear in item ranges.
export function historyGrowth(store,stack,isLeaf) {
  const positions=(struct,overlap)=>{
    const content=struct.content;
    if (!content || content instanceof Y.ContentDeleted || content instanceof Y.ContentFormat) return 0;
    if (content instanceof Y.ContentType) return content.type instanceof Y.XmlElement ? (isLeaf(content.type.nodeName)?1:2) : 0;
    return overlap;
  };
  const structsIn=(set,visit)=>set.clients.forEach((ranges,client)=>{
    const structs=store.clients.get(client);
    for (const {clock,len} of ranges) {
      let index;
      try {index=structs?Y.findIndexSS(structs,clock):-1;} catch {index=-1;}
      if (index<0) {visit(null,len);continue;}
      for (;index<structs.length && structs[index].id.clock<clock+len;index++) {
        const struct=structs[index];
        visit(struct,Math.min(struct.id.clock+struct.length,clock+len)-Math.max(struct.id.clock,clock));
      }
    }
  });
  let most=0;
  for (let i=stack.length-1;i>=0;i--) {
    const item=stack[i];let restored=0,removed=0,live=false;
    structsIn(item.deletions,(struct,overlap)=>{
      if (!struct) restored+=2*overlap; // unknown: assume the costliest
      else if (!Y.isDeleted(item.insertions,struct.id)) restored+=positions(struct,overlap);
    });
    structsIn(item.insertions,(struct,overlap)=>{
      // An insertion an earlier Undo/Redo brought back lives on as its copy.
      let at=struct,diff=0;
      try {
        while (at?.redone) {
          const id=Y.createID(at.redone.client,at.redone.clock+diff);
          const next=Y.getItem(store,id);diff=id.clock-next.id.clock;at=next;
        }
      } catch {at=null;}
      if (at?.content && !at.deleted) {live=true;removed+=positions(at,Math.min(overlap,at.length-diff));}
    });
    most=Math.max(most,restored-removed);
    if (live) break;
  }
  return most;
}

// Per-view authoring barrier, not the whole-app close/Quit barrier. The live
// document and already-issued request bytes remain owned by the view throughout.
export class WriterGuard {
  constructor(doc,clientId,onHold) {
    this.doc=doc;this.onHold=onHold;this.paused=false;this.reacquiring=null;
    this.assign(clientId);
  }
  assign(id) {
    if (!Number.isSafeInteger(id) || id<0) throw new TypeError('native writer ID required');
    // Yjs allocates from integrated structs: a pending prefix would overlap.
    const pending=this.doc.store.pendingStructs;
    if (pending && Y.decodeUpdateV2(pending.update).structs.some(s=>s.id.client===id)) throw new TypeError('writer prefix pending');
    if (Y.getState(this.doc.store,id)>=LAST) throw new TypeError('writer exhausted');
    this.doc.clientID=id;this.expected=id;
  }
  // The last clock is used: the terminal work drains, then a new lease.
  get spent() {return Y.getState(this.doc.store,this.expected)>=LAST;}
  get blocked() {return this.paused||this.spent;}
  // An operation of at most `bound` clocks fits this writer, needs a fresh
  // one (whose whole range it fits), or fits no writer at all.
  admit(bound) {
    if (bound<=LAST-Y.getState(this.doc.store,this.expected)) return 'fit';
    return bound<=LAST ? 'rollover' : 'refuse';
  }
  hold() {
    if (!this.paused) {this.paused=true;this.onHold();}
  }
  apply(apply) {
    try {return apply();}
    finally {if(this.doc.clientID!==this.expected)this.hold();}
  }
  reacquire(drain,open) {
    if(this.reacquiring)return this.reacquiring;
    this.hold();
    this.reacquiring=(async()=>{
      try {
        if(!await drain())return false;
        const next=await open();
        // Merge into the same document, after drain and before assigning the ID.
        // Never flatten a document or alter updates to force a lease to fit.
        next.hydrate();this.assign(next.clientId);this.paused=false;return true;
      } catch {return false;}
      finally {this.reacquiring=null;}
    })();
    return this.reacquiring;
  }
}
