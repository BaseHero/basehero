// @ts-nocheck
import * as Y from 'yjs';

// Only never-submitted deltas can share a chunk. Bound raw merge input, not
// outstanding content: a failed attempt must never make typing revisit history.
const MAX_DELTAS=256, MAX_BYTES=64*1024;
// No further local growth while this much accepted writing is unsaved.
// Accepted input is never split or dropped, and this bounds the queue, not
// Undo history.
export const PAUSE_CHUNKS=512, PAUSE_BYTES=4*1024*1024;
export class SaveQueue {
  constructor(merge=Y.mergeUpdates) {this.merge=merge;this.items=[];this.head=0;this.bytes=0;}
  get count() {return this.items.length-this.head;}
  // Submitted plus raw unsubmitted bytes, kept incrementally (no history walk).
  get retainedBytes() {return this.bytes;}
  get full() {return this.count>=PAUSE_CHUNKS || this.bytes>=PAUSE_BYTES;}
  append(bytes) {
    const copy=new Uint8Array(bytes),last=this.items.at(-1);
    this.bytes+=copy.length;
    if (last && !last.id && last.updates.length<MAX_DELTAS &&
        last.rawBytes+copy.length<=MAX_BYTES) {
      last.updates.push(copy);last.rawBytes+=copy.length;
    } else this.items.push({updates:[copy],rawBytes:copy.length});
  }
  submit(id) {
    const item=this.items[this.head];
    if (!item) return null;
    if (!item.id) {
      item.bytes=item.updates.length===1?item.updates[0]:this.merge(item.updates);
      item.id=id;this.bytes+=item.bytes.length-item.rawBytes;
      // The new merged encoding owns its bytes. Release raw input immediately.
      if (item.updates.length!==1) for (const part of item.updates) part.fill(0);
      item.updates=null;item.rawBytes=0;
    }
    return {id:item.id,bytes:item.bytes};
  }
  acknowledge() {
    const item=this.items[this.head];
    if (!item?.id) throw new Error('no submitted save to acknowledge');
    this.bytes-=item.bytes.length;item.bytes.fill(0);this.items[this.head++]=null;
    if (this.head===this.items.length) {this.items.length=0;this.head=0;}
    else if (this.head>=64 && this.head*2>=this.items.length) {
      this.items.splice(0,this.head);this.head=0;
    }
  }
  close() {
    for (let i=this.head;i<this.items.length;i++) {
      const item=this.items[i];
      item.bytes?.fill(0);
      for (const part of item.updates??[]) part.fill(0);
    }
    this.items.length=0;this.head=0;this.bytes=0;
  }
}
