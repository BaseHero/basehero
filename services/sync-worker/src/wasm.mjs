// The Worker's Rust helpers and the small byte utilities the log object and
// edge share. Rust decodes, verifies, hashes and signs; JS only lays out the
// input and parses the bounded JSON result.
import syncModule from '../sync_worker.wasm';
import { assertImports, createHost } from '../../../libs/crypto/worker-host.mjs';

// Data-wire refusal codes 1-10, in order.
export const REASONS = [null, 'Expired', 'Scope', 'Epoch', 'Predecessor', 'Conflict', 'NotStaged',
  'Reclaiming', 'Missing', 'Malformed', 'Unavailable'];
const dec = new TextDecoder('utf-8', { fatal: true });

export class Refused extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}
export const refuse = reason => { throw new Refused(reason); };

export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function unhex(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(value)) refuse('Malformed');
  return Uint8Array.from(value.match(/../g) ?? [], h => parseInt(h, 16));
}
export function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return refuse('Malformed');
}
export function be(value, size) {
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  if (size === 4) view.setUint32(0, value); else view.setBigUint64(0, BigInt(value));
  return out;
}
export const safe = n => Number.isSafeInteger(n) && n >= 0;

export function instantiate() {
  assertImports(WebAssembly.Module.imports(syncModule));
  const host = createHost();
  return WebAssembly.instantiate(syncModule, host.imports).then(instance => {
    host.bindMemory(instance.exports.memory);
    return instance;
  });
}
function span(memory, ptr, len) {
  const view = new Uint8Array(memory.buffer);
  if (!Number.isSafeInteger(ptr) || ptr <= 0 || !Number.isSafeInteger(len) || len < 0 ||
      ptr > view.length || len > view.length - ptr) throw new Error('Wasm memory bounds');
  return view.subarray(ptr, ptr + len);
}
// Synchronous, non-reentrant call into a Rust helper. A refusal code throws
// `Refused` with its data-wire name.
export function call(instance, name, parts) {
  const exports = instance.exports;
  const total = parts.reduce((n, part) => n + part.length, 0);
  const input = span(exports.memory, exports.reserve_input(total), total);
  let at = 0;
  for (const part of parts) { input.set(part, at); at += part.length; }
  const status = exports[name](total);
  if (status !== 0) refuse(REASONS[status] ?? 'Unavailable');
  return JSON.parse(dec.decode(span(exports.memory, exports.result_ptr(), exports.result_len())));
}
