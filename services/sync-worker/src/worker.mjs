// Internal SQLite Durable Object adapter. This module has no public request
// handler, checker-key provisioning route, clock or authority source.
import { DurableObject } from 'cloudflare:workers';
import syncModule from '../sync_worker.wasm';
import { assertImports, createHost } from '../../../libs/crypto/worker-host.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
function checked(view, ptr, len) {
  if (!Number.isSafeInteger(ptr) || ptr <= 0 || !Number.isSafeInteger(len) || len < 0 ||
      ptr > view.length || len > view.length - ptr) throw new Error('Wasm memory bounds');
  return view.subarray(ptr, ptr + len);
}
function wasmPlan(instance, request) {
  const bytes = enc.encode(JSON.stringify(request));
  if (bytes.length < 1 || bytes.length > 10 * 1024 * 1024) throw new Error('request bound');
  const exports = instance.exports;
  const ptr = exports.reserve_input(bytes.length);
  checked(new Uint8Array(exports.memory.buffer), ptr, bytes.length).set(bytes);
  if (exports.execute(bytes.length) !== 0) throw new Error('plan refused');
  const result = checked(new Uint8Array(exports.memory.buffer), exports.result_ptr(), exports.result_len());
  if (result.length === 0 || result.length > 1024) throw new Error('result bound');
  return JSON.parse(dec.decode(result));
}
function only(sql, statement, ...params) {
  const values = sql.exec(statement, ...params).toArray();
  if (values.length !== 1) throw new Error('missing or duplicate row');
  return values[0];
}
function maybe(sql, statement, ...params) {
  const values = sql.exec(statement, ...params).toArray();
  if (values.length > 1) throw new Error('duplicate row');
  return values[0] ?? null;
}
function stored(sql, row) {
  if (!row) return null;
  const prior = row.position === 1 ? null : only(sql, 'SELECT commitment FROM events WHERE position=?', row.position - 1).commitment;
  return { ...row, previous: prior };
}
function gate(sql) {
  return only(sql, 'SELECT base,position,hash,incarnation,sequence,checker_key FROM gate WHERE singleton=1');
}
export class BaseLog extends DurableObject {
  #instance;
  constructor(ctx, env) {
    super(ctx, env);
    // Fail before touching storage if an updated product build imports more
    // than the already audited hash/verify libsodium Worker glue.
    assertImports(WebAssembly.Module.imports(syncModule));
    const host = createHost();
    this.#instance = WebAssembly.instantiate(syncModule, host.imports).then(instance => {
      host.bindMemory(instance.exports.memory);
      return instance;
    });
  }
  // Internal DO RPC, callable only by a future authenticated host. The fixture
  // invokes it directly. This is not an HTTP endpoint or authority checker.
  async consume(request, binding, time) {
    try {
      const instance = await this.#instance;
      const result = this.ctx.storage.transactionSync(() => {
        const sql = this.ctx.storage.sql;
        const before = gate(sql);
        // SQLite JS numbers cannot represent every u64 exactly. Refuse rather
        // than silently round the persisted position, sequence or time bounds.
        if (![before.position, before.sequence, time.earliest, time.latest].every(
          n => Number.isSafeInteger(n) && n >= 0)) throw new Error('integer bound');
        const head = before.position === 0 ? null : stored(sql,
          only(sql, 'SELECT position,event_id,event_digest,commitment,event FROM events WHERE position=?', before.position));
        if (before.position === 0 && maybe(sql, 'SELECT position FROM events LIMIT 1')) throw new Error('unexpected genesis row');
        const selection = request.kind === 'append'
          ? [maybe(sql, 'SELECT position,event_id,event_digest,commitment,event FROM events WHERE event_id=?', request.event?.slice(4, 68))]
          : request.kind === 'read' && Array.isArray(request.objects) && request.objects.length <= 64
            ? request.objects.map(d => maybe(sql, 'SELECT position,event_id,event_digest,commitment,event FROM events WHERE event_digest=?', d))
            : [];
        if (selection.some(r => request.kind === 'read' && !r)) throw new Error('missing read');
        const selected = selection.filter(Boolean).map(r => stored(sql, r));
        const plan = wasmPlan(instance, {
          version: 1, gate: before, approval: request.grant,
          operation: request.kind === 'append' ? { kind: 'append', event: request.event }
            : { kind: 'read', objects: request.objects },
          binding, earliest: time.earliest, latest: time.latest, head, selected,
        });
        if (![plan.position, plan.sequence].every(n => Number.isSafeInteger(n) && n >= 0))
          throw new Error('result integer bound');
        let bodies;
        if (request.kind === 'read') bodies = selected.map(r => r.event);
        if (plan.append) {
          // Canonical bytes produced by Rust Commitment::order, not JS crypto.
          const id = plan.append.slice(148, 212);
          const digest = plan.append.slice(212, 276);
          sql.exec('INSERT INTO events(position,event_id,event_digest,commitment,event) VALUES(?,?,?,?,?)',
            plan.position, id, digest, plan.append, request.event);
        }
        const changed = sql.exec(`UPDATE gate SET position=?,hash=?,sequence=?,last_approval=?,last_ack=?
          WHERE singleton=1 AND base=? AND position=? AND hash=? AND incarnation=? AND sequence=? AND checker_key=?`,
          plan.position, plan.hash, plan.sequence, request.grant, plan.ack,
          before.base, before.position, before.hash, before.incarnation, before.sequence, before.checker_key);
        if (changed.rowsWritten !== 1) throw new Error('gate compare');
        return plan.ack ? { ack: plan.ack } : { bodies };
      });
      // transactionSync has committed; sync waits for outstanding DO writes.
      // Do not release any Ack/ciphertext before this resolves.
      await this.ctx.storage.sync();
      return result;
    } catch { return { refusal: 'Unavailable' }; }
  }
}

export default { fetch() { return new Response(null, { status: 404 }); } };
