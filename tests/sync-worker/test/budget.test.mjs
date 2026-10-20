// The edge's memory budget on its own, with sessions modelled on the edge's
// `#pump`: each takes its waiting frames in order while they fit and its
// turn has come, and leaves the queues when it has none left.
import test from 'node:test';
import assert from 'node:assert/strict';
import { block, budget, charge, take, unblock, uncharge } from '../../../services/sync-worker/src/budget.mjs';

const MIB = 1 << 20;

function session(...frames) {
  const s = { waiting: frames.map(([size, small]) => ({ size, small })), taken: [] };
  s.resume = () => {
    while (s.waiting.length) {
      const { size, small } = s.waiting[0];
      if (!take(size, small, s.resume)) { block(s.resume, small); return; }
      s.taken.push(s.waiting.shift().size);
    }
    unblock(s.resume);
  };
  // A close holding nothing: its frames stop waiting and no charge returns.
  s.close = () => { s.waiting = []; unblock(s.resume); };
  return s;
}

// Runs `body` on an empty budget and empties it after, pass or fail.
function clean(body) {
  return () => {
    const sessions = [];
    try { body(sessions); } finally {
      for (const s of sessions) s.close();
      uncharge(budget().frames);
    }
  };
}

test('a session that becomes first in its queue during a wake pass is resumed in that pass', clean(sessions => {
  const { limits } = budget();
  assert.ok(charge(limits.frames, true));
  // S waits for a small frame and then a bulk one; H waits for a bulk one.
  const s = session([1000, true], [MIB, false]);
  const h = session([MIB, false]);
  sessions.push(s, h);
  s.resume();
  h.resume();
  assert.equal(budget().waiting, 2);
  // One uncharge leaves room for all three. S, resumed first, takes its small
  // frame and queues behind H for its bulk one; H then takes its frame and
  // leaves, so S is first and its frame fits.
  const left = limits.bulk - 2 * MIB - 1000;
  uncharge(limits.frames - left);
  assert.deepEqual([s.taken, h.taken], [[1000, MIB], [MIB]]);
  assert.deepEqual([budget().frames, budget().waiting], [limits.bulk, 0]);
}));

test('a waiting frame that leaves holding nothing passes its turn on', clean(sessions => {
  const { limits } = budget();
  // Room for a 14-byte Peers but not a 352-byte Head: the Head waits first,
  // and the Peers behind it.
  assert.ok(charge(limits.frames - 100, true));
  const head = session([352, true]);
  const peers = session([14, true]);
  sessions.push(head, peers);
  head.resume();
  peers.resume();
  assert.equal(budget().waiting, 2);
  // The Head's socket closes (or the Head expires) holding nothing, so no
  // charge returns to wake the queue.
  head.close();
  assert.deepEqual([peers.taken, budget().waiting], [[14], 0]);
}));
