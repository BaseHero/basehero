import { DurableObject } from 'cloudflare:workers';
import type { BaseKeyResponse } from './proto/gen/BaseKeyResponse';
import type { ChangeResult } from './proto/gen/ChangeResult';
import type { ChangesResponse } from './proto/gen/ChangesResponse';
import type { GrantMode } from './proto/gen/GrantMode';
import type { SinceResponse } from './proto/gen/SinceResponse';
import type { Env, Principal, Result } from './http';
import { fail } from './http';

/** Bodies above this go to R2; SQLite-backed objects cap a value at 2 MB. */
export const INLINE_MAX = 1024 * 1024;
const FETCH_MAX = 16 * 1024 * 1024;

export type NewChange = { changeId: string; objectId: string; kind: 'update' | 'state'; body: Uint8Array; covers: number; keep: boolean };
/** A body stored inline, or the R2 key the Worker reads it from. */
export type StoredBody = { bytes: Uint8Array } | { r2: string };
export type FetchedObject = {
  objectId: string; head: number;
  state: { seq: number; covers: number; deviceId: string; body: StoredBody } | null;
  updates: { seq: number; deviceId: string; body: StoredBody }[];
};
export type Fetched = { objects: FetchedObject[]; more: string[] };
export type Stored = { changes: { seq: number; kind: string; keep: boolean }[] };
export type Created = 'created' | 'yours' | 'taken';

type AccessRow = { mode: GrantMode; epoch: number; wrapper: string };
type ObjectState = { head: number; state_seq: number | null; state_covers: number; tail: number };
type BodyRow = { seq: number; device_id: string; body: ArrayBuffer | null; r2_key: string | null; size: number; covers: number | null };
type Decision = { result: ChangeResult } | { object: ObjectState; seq: number };

function stored(row: BodyRow): StoredBody {
  return row.r2_key ? { r2: row.r2_key } : { bytes: new Uint8Array(row.body!) };
}
function buffer(value: Uint8Array): ArrayBuffer {
  return value.byteOffset === 0 && value.byteLength === value.buffer.byteLength ? value.buffer as ArrayBuffer : value.slice().buffer;
}

/**
 * One base: who may use it, and its ordered changes. It stores ciphertext it can't read.
 * Every method takes the caller's principal from the Worker, never from the client.
 */
export class BaseDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS access (principal TEXT PRIMARY KEY, mode TEXT NOT NULL, epoch INTEGER NOT NULL, wrapper TEXT NOT NULL)');
    // prev_head is kept so a repeated change gets its original result, which the client invariant relies on.
    sql.exec('CREATE TABLE IF NOT EXISTS changes (seq INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT NOT NULL UNIQUE, object_id TEXT NOT NULL, kind TEXT NOT NULL, body BLOB, r2_key TEXT, size INTEGER NOT NULL, covers INTEGER, keep INTEGER NOT NULL, prev_head INTEGER NOT NULL, device_id TEXT NOT NULL, at INTEGER NOT NULL)');
    sql.exec('CREATE INDEX IF NOT EXISTS changes_by_object ON changes (object_id, seq)');
    sql.exec('CREATE TABLE IF NOT EXISTS objects (object_id TEXT PRIMARY KEY, head INTEGER NOT NULL, state_seq INTEGER, state_covers INTEGER NOT NULL, tail INTEGER NOT NULL)');
    sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS objects_by_head ON objects (head)');
  }
  private get sql() { return this.ctx.storage.sql; }
  private access(principal: string): AccessRow | null {
    return this.sql.exec<AccessRow>('SELECT mode, epoch, wrapper FROM access WHERE principal = ?', principal).toArray()[0] ?? null;
  }
  // A full device of a member account uses the account's row; an app device also needs its own.
  private member(p: Principal): AccessRow | null {
    if (p.status !== 'active') return null;
    const account = this.access(`acct:${p.accountId}`);
    return account && p.kind === 'app' ? this.access(`dev:${p.deviceId}`) : account;
  }
  private denied(p: Principal, write = false): Result<never> | null {
    if (p.status === 'pending') return fail(403, 'pending');
    const row = this.member(p);
    if (!row) return fail(403, 'forbidden');
    if (write && row.mode !== 'rw') return fail(403, 'read_only');
    return null;
  }
  private owns(p: Principal): boolean {
    return p.kind === 'full' && p.status === 'active' && this.access(`acct:${p.accountId}`) !== null;
  }
  private head(): number {
    return this.sql.exec<{ head: number }>('SELECT COALESCE(MAX(head), 0) AS head FROM objects').one().head;
  }
  private object(objectId: string): ObjectState {
    return this.sql.exec<ObjectState>('SELECT head, state_seq, state_covers, tail FROM objects WHERE object_id = ?', objectId).toArray()[0]
      ?? { head: 0, state_seq: null, state_covers: 0, tail: 0 };
  }

  create(p: Principal, epoch: number, wrapper: string): Created {
    if (this.sql.exec("SELECT principal FROM access WHERE principal LIKE 'acct:%' LIMIT 1").toArray().length) return this.owns(p) ? 'yours' : 'taken';
    this.sql.exec('INSERT INTO access VALUES (?, ?, ?, ?)', `acct:${p.accountId}`, 'rw', epoch, wrapper);
    return 'created';
  }
  key(p: Principal): Result<BaseKeyResponse> {
    const denied = this.denied(p);
    if (denied) return denied;
    const row = this.member(p)!;
    return { status: 200, body: { epoch: row.epoch, wrapper: row.wrapper, mode: row.mode } };
  }
  grant(p: Principal, deviceId: string, mode: GrantMode, epoch: number, wrapper: string): Result {
    if (!this.owns(p)) return fail(403, 'forbidden');
    this.sql.exec('INSERT OR REPLACE INTO access VALUES (?, ?, ?, ?)', `dev:${deviceId}`, mode, epoch, wrapper);
    return { status: 200, body: {} };
  }
  revoke(p: Principal, deviceId: string): Result {
    if (!this.owns(p)) return fail(403, 'forbidden');
    this.sql.exec('DELETE FROM access WHERE principal = ?', `dev:${deviceId}`);
    return { status: 200, body: {} };
  }

  private decide(c: NewChange): Decision {
    const old = this.sql.exec<{ seq: number; prev_head: number; object_id: string }>('SELECT seq, prev_head, object_id FROM changes WHERE change_id = ?', c.changeId).toArray()[0];
    if (old) return { result: { changeId: c.changeId, seq: old.seq, prevHead: old.prev_head, tail: this.object(old.object_id).tail, stale: false } };
    const object = this.object(c.objectId);
    if (c.kind === 'state' && !(c.covers > object.state_covers && c.covers <= object.head)) {
      return { result: { changeId: c.changeId, seq: null, prevHead: object.head, tail: object.tail, stale: true } };
    }
    return { object, seq: this.head() + 1 };
  }
  /** Stores one change; synchronous, so its reads and writes can't interleave with another request. */
  private apply(deviceId: string, c: NewChange, r2Key: string | null, deletes: string[]): ChangeResult {
    const decision = this.decide(c);
    if ('result' in decision) return decision.result;
    const { object, seq } = decision;
    let { state_seq, state_covers, tail } = object;
    const replacedKeys: string[] = [];
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT INTO changes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', seq, c.changeId, c.objectId, c.kind,
        r2Key ? null : buffer(c.body), r2Key, c.body.length, c.kind === 'state' ? c.covers : null,
        c.kind === 'state' && c.keep ? 1 : 0, object.head, deviceId, Date.now());
      if (c.kind === 'update') tail += 1;
      else {
        // The state replaces the updates it covers and earlier states that aren't kept.
        const replaced = "object_id = ? AND seq < ? AND ((kind = 'update' AND seq <= ?) OR (kind = 'state' AND keep = 0))";
        for (const row of this.sql.exec<{ r2_key: string }>(`SELECT r2_key FROM changes WHERE ${replaced} AND r2_key IS NOT NULL`, c.objectId, seq, c.covers)) replacedKeys.push(row.r2_key);
        this.sql.exec(`DELETE FROM changes WHERE ${replaced}`, c.objectId, seq, c.covers);
        tail = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM changes WHERE object_id = ? AND kind = 'update'", c.objectId).one().n;
        state_seq = seq;
        state_covers = c.covers;
      }
      this.sql.exec('INSERT INTO objects VALUES (?, ?, ?, ?, ?) ON CONFLICT (object_id) DO UPDATE SET head = excluded.head, state_seq = excluded.state_seq, state_covers = excluded.state_covers, tail = excluded.tail',
        c.objectId, seq, state_seq, state_covers, tail);
    });
    // Only delete R2 bodies after their SQL transaction committed.
    deletes.push(...replacedKeys);
    return { changeId: c.changeId, seq, prevHead: object.head, tail, stale: false };
  }
  async changes(p: Principal, changes: NewChange[]): Promise<Result<ChangesResponse>> {
    const denied = this.denied(p, true);
    if (denied) return denied;
    const results: ChangeResult[] = [];
    const deletes: string[] = [];
    try {
      if (!changes.some(c => c.body.length > INLINE_MAX)) {
        // One synchronous span: no other request runs between a read and the write that depends on it.
        for (const c of changes) results.push(this.apply(p.deviceId, c, null, deletes));
      } else {
        // Writing to R2 needs awaits, so hold every other request until the batch is stored.
        // The body goes to R2 before its row exists, so a stored row always has its body.
        let failure: unknown;
        let failed = false;
        await this.ctx.blockConcurrencyWhile(async () => {
          try {
            for (const c of changes) {
              const decision = c.body.length > INLINE_MAX ? this.decide(c) : null;
              const r2Key = decision && 'seq' in decision ? `b/${this.ctx.id.name}/${c.objectId}/${decision.seq}` : null;
              if (r2Key) await this.env.FILES.put(r2Key, c.body);
              results.push(this.apply(p.deviceId, c, r2Key, deletes));
            }
          } catch (e) {
            // An exception escaping this callback resets the whole Durable Object.
            failure = e;
            failed = true;
          }
        });
        if (failed) throw failure;
      }
      return { status: 200, body: { results, head: this.head() } };
    } finally {
      // Best effort: a failed delete can orphan R2 bodies, but cannot fail a committed reply.
      for (let i = 0; i < deletes.length; i += 1000) {
        try { await this.env.FILES.delete(deletes.slice(i, i + 1000)); } catch { /* orphaned bodies are a known limit */ }
      }
    }
  }
  since(p: Principal, after: number, limit: number): Result<SinceResponse> {
    const denied = this.denied(p);
    if (denied) return denied;
    const rows = this.sql.exec<{ object_id: string; head: number }>('SELECT object_id, head FROM objects WHERE head > ? ORDER BY head LIMIT ?', after, limit + 1).toArray();
    return { status: 200, body: { head: this.head(), objects: rows.slice(0, limit).map(r => ({ objectId: r.object_id, head: r.head })), more: rows.length > limit } };
  }
  /** Not `fetch`, which a Durable Object reserves for HTTP. */
  fetchObjects(p: Principal, objectIds: string[]): Result<Fetched> {
    const denied = this.denied(p);
    if (denied) return denied;
    const objects: FetchedObject[] = [];
    let total = 0;
    for (const [i, objectId] of objectIds.entries()) {
      const object = this.object(objectId);
      const state = object.state_seq === null ? undefined
        : this.sql.exec<BodyRow>('SELECT seq, device_id, body, r2_key, size, covers FROM changes WHERE seq = ?', object.state_seq).toArray()[0];
      const updates = this.sql.exec<BodyRow>("SELECT seq, device_id, body, r2_key, size, covers FROM changes WHERE object_id = ? AND kind = 'update' AND seq > ? ORDER BY seq",
        objectId, object.state_covers).toArray();
      const size = (state?.size ?? 0) + updates.reduce((n, u) => n + u.size, 0);
      // A reply always holds at least one object, so a client always makes progress.
      if (objects.length && total + size > FETCH_MAX) return { status: 200, body: { objects, more: objectIds.slice(i) } };
      total += size;
      objects.push({
        objectId, head: object.head,
        state: state ? { seq: state.seq, covers: state.covers!, deviceId: state.device_id, body: stored(state) } : null,
        updates: updates.map(u => ({ seq: u.seq, deviceId: u.device_id, body: stored(u) })),
      });
    }
    return { status: 200, body: { objects, more: [] } };
  }
  /** Test-only view of what is stored for an object. */
  stored(p: Principal, objectId: string): Result<Stored> {
    const denied = this.denied(p);
    if (denied) return denied;
    const rows = this.sql.exec<{ seq: number; kind: string; keep: number }>('SELECT seq, kind, keep FROM changes WHERE object_id = ? ORDER BY seq', objectId).toArray();
    return { status: 200, body: { changes: rows.map(r => ({ seq: r.seq, kind: r.kind, keep: r.keep === 1 })) } };
  }
}
