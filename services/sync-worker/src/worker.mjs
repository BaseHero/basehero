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
function wasmHelper(instance, name, parts) {
  const exports = instance.exports;
  const length = parts.reduce((total, part) => total + part.length, 0);
  const ptr = exports.reserve_input(length);
  const input = checked(new Uint8Array(exports.memory.buffer), ptr, length);
  let offset = 0;
  for (const part of parts) { input.set(part, offset); offset += part.length; }
  if (exports[name](length) !== 0) throw new Error('canonical helper refused');
  return JSON.parse(dec.decode(checked(new Uint8Array(exports.memory.buffer), exports.result_ptr(), exports.result_len())));
}
const unhex = value => Uint8Array.from(value.match(/../g) ?? [], pair => parseInt(pair, 16));
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
  return only(sql, 'SELECT base,order_format,opening AS "order",position,hash,incarnation,sequence,checker_key FROM gate WHERE singleton=1');
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
        // Dispatch exactly four kinds; never let an unknown label fall through
        // to a default operation or a wrong body write.
        if (!['append', 'read', 'stage', 'readbodies'].includes(request.kind))
          throw new Error('unknown kind');
        // Compare with the indexed actual tail, not the row at the gate's
        // claimed position: a coherent earlier gate cannot hide later rows.
        const tail = maybe(sql,
          'SELECT position,event_id,event_digest,commitment,event FROM events ORDER BY position DESC LIMIT 1');
        if (tail ? !Number.isSafeInteger(tail.position) || tail.position !== before.position
                 : before.position !== 0) throw new Error('order tail mismatch');
        const head = tail ? stored(sql, tail) : null;
        const routed = request.kind === 'append'
          ? wasmHelper(instance, 'routed_id', [unhex(before.base), unhex(request.event)]).event_id : null;
        const selection = request.kind === 'append'
          ? [maybe(sql, 'SELECT position,event_id,event_digest,commitment,event FROM events WHERE event_id=?', routed)]
          : request.kind === 'read' && Array.isArray(request.objects) && request.objects.length <= 64
            ? request.objects.map(d => maybe(sql, 'SELECT position,event_id,event_digest,commitment,event FROM events WHERE event_digest=?', d))
            : [];
        if (selection.some(r => request.kind === 'read' && !r)) throw new Error('missing read');
        const selected = selection.filter(Boolean).map(r => stored(sql, r));
        // The first 32 envelope bytes of an appended descriptor name its body.
        const stagedBody = request.kind === 'append' && typeof request.event === 'string'
          ? maybe(sql, 'SELECT body FROM bodies WHERE commitment=?', request.event.slice(76, 140))?.body ?? null
          : null;
        const bodyRows = request.kind === 'readbodies' && Array.isArray(request.objects)
          ? request.objects.map(d => maybe(sql, 'SELECT commitment,body FROM bodies WHERE commitment=?', d))
          : [];
        if (bodyRows.some(r => !r)) throw new Error('missing body');
        const operation = request.kind === 'append' ? { kind: 'append', event: request.event }
          : request.kind === 'read' ? { kind: 'read', objects: request.objects }
            : request.kind === 'readbodies' ? { kind: 'readbodies', objects: request.objects }
              : { kind: 'stage', body: request.body };
        const plan = wasmPlan(instance, {
          version: 1, gate: before, approval: request.grant,
          operation,
          binding, earliest: time.earliest, latest: time.latest, head, selected,
          staged_body: stagedBody, bodies: bodyRows.filter(Boolean),
        });
        if (![plan.position, plan.sequence].every(n => Number.isSafeInteger(n) && n >= 0))
          throw new Error('result integer bound');
        let bodies;
        if (request.kind === 'read') bodies = selected.map(r => r.event);
        if (request.kind === 'readbodies') bodies = bodyRows.map(r => r.body);
        if (plan.stage) {
          // Follow the Rust plan, not the request label. Repeat staging of
          // identical bytes keeps one row; a pre-existing row must match the
          // exact canonical bytes or the false receipt is refused.
          const inserted = sql.exec('INSERT OR IGNORE INTO bodies(commitment,body) VALUES(?,?)',
            plan.stage, request.body).rowsWritten;
          if (!inserted && maybe(sql, 'SELECT body FROM bodies WHERE commitment=?', plan.stage)?.body !== request.body)
            throw new Error('stored body mismatch');
        }
        if (plan.append) {
          // Canonical bytes produced by Rust Commitment::order, not JS crypto.
          const state = wasmHelper(instance, 'commitment_state', [unhex(before.base), unhex(plan.append)]);
          if (state.position !== plan.position || state.hash !== plan.hash || state.order !== plan.order ||
              state.event_id !== routed) throw new Error('ordered state mismatch');
          sql.exec('INSERT INTO events(position,event_id,event_digest,commitment,event) VALUES(?,?,?,?,?)',
            plan.position, state.event_id, state.digest, plan.append, request.event);
        }
        const changed = sql.exec(`UPDATE gate SET position=?,hash=?,opening=?,sequence=?,last_approval=?,last_ack=?
          WHERE singleton=1 AND base=? AND order_format=2 AND opening=? AND position=? AND hash=? AND incarnation=? AND sequence=? AND checker_key=?`,
          plan.position, plan.hash, plan.order, plan.sequence, request.grant, plan.ack,
          before.base, before.order, before.position, before.hash, before.incarnation, before.sequence, before.checker_key);
        if (changed.rowsWritten !== 1) throw new Error('gate compare');
        return plan.ack ? { ack: plan.ack }
          : plan.stage ? { commitment: plan.stage }
            : { bodies };
      });
      // transactionSync has committed; sync waits for outstanding DO writes.
      // Do not release any Ack/ciphertext before this resolves.
      await this.ctx.storage.sync();
      return result;
    } catch { return { refusal: 'Unavailable' }; }
  }
}

export default { fetch() { return new Response(null, { status: 404 }); } };
