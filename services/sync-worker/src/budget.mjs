// The isolate's memory budget for the edge's sockets, in bytes, instead of a
// socket count. Cloudflare documents 128 MB of memory per isolate
// (https://developers.cloudflare.com/workers/platform/limits/); half is left
// for the Wasm instance, the runtime and the transient copies made while a
// frame is built. The budget's two halves are charged apart, so neither can
// take the other's:
//   - lasting costs: 16 KiB per admitted data socket or authz session, and
//     4 KiB per subscription or presence join, for as long as it lasts
//     (estimates, not measured on a live isolate);
//   - frames: each data frame's window take, from before its bytes are read
//     until the device's Credit returns it (or the edge refunds it unsent),
//     and each request frame, twice its length (the frame and the copy passed
//     to the log object), while it is handled.
// Bulk frames, of a request of more than 256 KiB, may not use the last 8 MiB
// of the frames half, so small replies (Acks, Heads, Peers, a few events or a
// small body) still flow when catch-up reads fill the rest. Worked case, all
// at once in one isolate:
//   - an idle device (authz session, receive lane with one subscription)
//     costs 36 KiB of the lasting half, and a typing one (adding a presence
//     socket with a join and an outbox link) 72 KiB: 32 MiB holds 910 idle or
//     455 typing devices, or a mix, and sheds only new lasting costs past it;
//   - at the same time, a catching-up socket holds up to one initial window
//     (8 MiB + 64 KiB) of the 24 MiB bulk part: two catch up at full speed,
//     and a third with most of a window. Further bulk frames wait, first come
//     first served across the isolate, reading nothing for themselves until
//     the budget covers them; each device's Credit frees budget as it
//     receives, so a 4.2 MB read of 64 events behind three catch-ups at
//     10 Mbit/s waits about a second, and a frame still waiting at its
//     deadline ends Expired, which clients retry with a fresh permit. New
//     sockets, subscriptions and joins are admitted meanwhile while the
//     lasting half has room. A socket that stops crediting what it holds is
//     closed after two minutes while frames wait (`STALL_MS` in edge.mjs).
// The edge cannot see the runtime's own send buffers: a device that grants
// Credit for bytes it has not read can make them grow. Nor does the budget
// hold authz frames once forwarded.
const BUDGET = 64 * 1024 * 1024;
const FIXED = 32 * 1024 * 1024;
const RESERVE = 8 * 1024 * 1024;
export const SMALL = 256 * 1024;
export const SOCKET_COST = 16 * 1024;
export const STREAM_COST = 4 * 1024;
// Lasting costs and frames now charged.
let fixed = 0;
let frames = 0;
// Each session whose first waiting frame has its window but not the budget,
// as its resume function, in the order they began to wait: small and bulk
// frames apart, as they take from different limits.
const blocked = { small: new Set(), bulk: new Set() };
const queue = small => (small ? blocked.small : blocked.bulk);
let waking = false;
let again = false;

// Charges a frame of `size` if it fits: a small one anywhere in the frames
// half, a bulk one only outside its reserve.
export function charge(size, small) {
  if (frames + size > (small ? BUDGET - FIXED : BUDGET - FIXED - RESERVE)) return false;
  frames += size;
  return true;
}
// Charges an outbound frame only in its turn: if no session waits before it
// in its class, `self` being the caller's resume function if it waits. So
// frames that keep fitting never starve a larger one waiting first, and
// presence (small) is sent only while no small frame waits.
export function take(size, small, self) {
  const first = queue(small).values().next().value;
  return (first === undefined || first === self) && charge(size, small);
}
// Lets waiting sessions take what now fits, in order. A session that stops
// waiting during a pass may make one already resumed first in its queue, so
// the pass repeats until none does.
function wake() {
  if (waking) { again = true; return; }
  waking = true;
  try {
    do {
      again = false;
      for (const resume of [...blocked.small, ...blocked.bulk]) resume();
    } while (again);
  } finally { waking = false; }
}
// Returns a frame's `size` and lets waiting sessions take what now fits.
export function uncharge(size) {
  if (size <= 0) return;
  frames -= size;
  wake();
}
// Charges a lasting cost if it fits in the lasting half.
export function admit(size) {
  if (fixed + size > FIXED) return false;
  fixed += size;
  return true;
}
// Returns a lasting cost.
export function release(size) {
  fixed -= size;
}
// A session's first waiting frame waits for the budget in its class, keeping
// the session's turn, or no longer waits, which may pass the turn on. Whether
// it began to wait in that class.
export function block(resume, small) {
  queue(!small).delete(resume);
  const began = !queue(small).has(resume);
  queue(small).add(resume);
  return began;
}
export function unblock(resume) {
  if (blocked.small.delete(resume) || blocked.bulk.delete(resume)) wake();
}
// Whether any frame waits for the budget.
export const waiting = () => blocked.small.size + blocked.bulk.size > 0;

// Test-only readback: what is charged now, and the limits it is charged
// against. Not reachable from any route.
export const budget = () => ({
  fixed, frames, waiting: blocked.small.size + blocked.bulk.size,
  limits: { fixed: FIXED, frames: BUDGET - FIXED, bulk: BUDGET - FIXED - RESERVE, socket: SOCKET_COST, stream: STREAM_COST },
});
