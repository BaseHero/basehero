import { DurableObject } from 'cloudflare:workers';
import type { LiveMessage } from './proto/gen/LiveMessage';
import type { BaseKeyResponse } from './proto/gen/BaseKeyResponse';
import type { AppWrapper } from './proto/gen/AppWrapper';
import type { ChangeResult } from './proto/gen/ChangeResult';
import type { ChangesResponse } from './proto/gen/ChangesResponse';
import type { GrantMode } from './proto/gen/GrantMode';
import type { SinceResponse } from './proto/gen/SinceResponse';
import type { VersionsResponse } from './proto/gen/VersionsResponse';
import type { Env, Principal, Result } from './http';
import { answer, b64, fail } from './http';

/** Bodies above this go to R2; SQLite-backed objects cap a value at 2 MB. */
export const INLINE_MAX = 1024 * 1024;
const FETCH_MAX = 16 * 1024 * 1024;
const LIVE_SOCKET_MAX_AGE_MS = 15 * 60_000;

export type NewChange = { changeId: string; objectId: string; kind: 'update' | 'state'; body: Uint8Array; covers: number; keep: boolean };
/** A body stored inline, or the R2 key the Worker reads it from. */
export type StoredBody = { bytes: Uint8Array } | { r2: string };
export type FetchedObject = {
  objectId: string; head: number;
  state: { seq: number; covers: number; deviceId: string; body: StoredBody } | null;
  updates: { seq: number; deviceId: string; body: StoredBody }[];
};
export type Fetched = { objects: FetchedObject[]; more: string[] };
export type Stored = { changes: { seq: number; kind: string; keep: boolean; inR2: boolean }[] };
export type StoredVersion = { seq: number; covers: number; deviceId: string; at: number; body: StoredBody };
export type Created = 'created' | 'yours' | 'taken' | 'epoch_conflict';

type AccessRow = { mode: GrantMode; epoch: number; wrapper: string; account_epoch: number; data_floor: number };
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
  private dropNext = new Set<string>();
  private failNextDeviceClose = false;
  private missNextFetch = new Set<string>();
  private shortNextFetch = new Set<string>();
  private holdNextReply = new Set<string>();
  private heldReply = new Set<string>();
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS access (principal TEXT PRIMARY KEY, mode TEXT NOT NULL, epoch INTEGER NOT NULL, wrapper TEXT NOT NULL)');
    for (const column of ['account_epoch INTEGER NOT NULL DEFAULT 1', 'data_floor INTEGER NOT NULL DEFAULT 0']) {
      if (!sql.exec<{ name: string }>('PRAGMA table_info(access)').toArray().some(row => row.name === column.split(' ')[0])) {
        sql.exec(`ALTER TABLE access ADD COLUMN ${column}`);
      }
    }
    sql.exec('CREATE TABLE IF NOT EXISTS removed_devices (device_id TEXT PRIMARY KEY)');
    sql.exec('CREATE TABLE IF NOT EXISTS previous_keys (epoch INTEGER PRIMARY KEY, sealed TEXT NOT NULL)');
    // prev_head is kept so a repeated change gets its original result, which the client invariant relies on.
    sql.exec('CREATE TABLE IF NOT EXISTS changes (seq INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT NOT NULL UNIQUE, object_id TEXT NOT NULL, kind TEXT NOT NULL, body BLOB, r2_key TEXT, size INTEGER NOT NULL, covers INTEGER, keep INTEGER NOT NULL, prev_head INTEGER NOT NULL, device_id TEXT NOT NULL, at INTEGER NOT NULL)');
    sql.exec('CREATE INDEX IF NOT EXISTS changes_by_object ON changes (object_id, seq)');
    sql.exec('CREATE TABLE IF NOT EXISTS objects (object_id TEXT PRIMARY KEY, head INTEGER NOT NULL, state_seq INTEGER, state_covers INTEGER NOT NULL, tail INTEGER NOT NULL)');
    sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS objects_by_head ON objects (head)');
  }
  private get sql() { return this.ctx.storage.sql; }
  private access(principal: string): AccessRow | null {
    return this.sql.exec<AccessRow>('SELECT mode, epoch, wrapper, account_epoch, data_floor FROM access WHERE principal = ?', principal).toArray()[0] ?? null;
  }
  // A full device of a member account uses the account's row; an app device also needs its own.
  private member(p: Principal): AccessRow | null {
    if (p.status !== 'active' || this.removed(p.deviceId)) return null;
    const account = this.access(`acct:${p.accountId}`);
    return account && p.kind === 'app' ? this.access(`dev:${p.deviceId}`) : account;
  }
  private removed(deviceId: string): boolean {
    return this.sql.exec('SELECT device_id FROM removed_devices WHERE device_id = ?', deviceId).toArray().length !== 0;
  }
  private denied(p: Principal, write = false): Result<never> | null {
    if (p.status === 'pending') return fail(403, 'pending');
    const row = this.member(p);
    if (!row) return fail(403, 'forbidden');
    if (write && row.mode !== 'rw') return fail(403, 'read_only');
    if (p.protocol === 1 && this.access(`acct:${p.accountId}`)!.epoch > 1) return fail(426, 'needs_update');
    return null;
  }
  /** Apply exactly the same grant and device checks as change and fetch routes. */
  fileAccess(p: Principal, write: boolean, changesRetry = false): Result {
    const denied = this.denied(p, write);
    if (denied) return denied;
    if (write && !changesRetry && p.epoch > this.access(`acct:${p.accountId}`)!.account_epoch) return fail(409, 'rekey_needed');
    return { status: 200, body: {} };
  }
  private owns(p: Principal): boolean {
    return p.kind === 'full' && p.status === 'active' && !this.removed(p.deviceId) && this.access(`acct:${p.accountId}`) !== null;
  }
  private head(): number {
    return this.sql.exec<{ head: number }>('SELECT COALESCE(MAX(head), 0) AS head FROM objects').one().head;
  }
  private object(objectId: string): ObjectState {
    return this.sql.exec<ObjectState>('SELECT head, state_seq, state_covers, tail FROM objects WHERE object_id = ?', objectId).toArray()[0]
      ?? { head: 0, state_seq: null, state_covers: 0, tail: 0 };
  }

  create(p: Principal, epoch: number, wrapper: string, accountEpoch: number): Created {
    if (this.sql.exec("SELECT principal FROM access WHERE principal LIKE 'acct:%' LIMIT 1").toArray().length) {
      if (!this.owns(p)) return 'taken';
      return accountEpoch === p.epoch && accountEpoch >= this.access(`acct:${p.accountId}`)!.account_epoch ? 'yours' : 'epoch_conflict';
    }
    if (accountEpoch !== p.epoch) return 'epoch_conflict';
    this.sql.exec('INSERT INTO access (principal, mode, epoch, wrapper, account_epoch) VALUES (?, ?, ?, ?, ?)', `acct:${p.accountId}`, 'rw', epoch, wrapper, accountEpoch);
    return 'created';
  }
  key(p: Principal): Result<BaseKeyResponse> {
    const denied = this.denied(p);
    if (denied) return denied;
    const row = this.member(p)!;
    const previous = this.sql.exec<{ epoch: number; sealed: string }>('SELECT epoch, sealed FROM previous_keys ORDER BY epoch').toArray();
    const account = this.access(`acct:${p.accountId}`)!;
    return { status: 200, body: { epoch: row.epoch, wrapper: row.wrapper, mode: row.mode, previous,
      accountEpoch: account.account_epoch, dataFloor: account.data_floor } };
  }
  /** Replace all wrappers under the next key in a single synchronous compare-and-set. */
  rekey(p: Principal, from: number, wrapper: string, previous: string, apps: AppWrapper[], accountEpoch: number, dataVersion: number): Result {
    if (!this.owns(p)) return fail(403, 'forbidden');
    const account = `acct:${p.accountId}`;
    const current = this.access(account)!;
    if (p.protocol === 1 && current.epoch > 1) return fail(426, 'needs_update');
    if (accountEpoch !== p.epoch || accountEpoch < current.account_epoch || current.epoch !== from) return fail(409, 'epoch_conflict');
    if (dataVersion < current.data_floor) return fail(409, 'stale_grant');
    const listed = new Map(apps.map(app => [app.deviceId, app.wrapper]));
    const removed: string[] = [];
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('UPDATE access SET epoch = ?, wrapper = ?, account_epoch = ?, data_floor = ? WHERE principal = ?', from + 1, wrapper, accountEpoch, Math.max(dataVersion, current.data_floor), account);
      this.sql.exec('INSERT INTO previous_keys VALUES (?, ?)', from, previous);
      for (const row of this.sql.exec<{ principal: string }>("SELECT principal FROM access WHERE principal LIKE 'dev:%'")) {
        const deviceId = row.principal.slice(4);
        const appWrapper = listed.get(deviceId);
        if (appWrapper !== undefined) this.sql.exec('UPDATE access SET epoch = ?, wrapper = ?, account_epoch = ? WHERE principal = ?', from + 1, appWrapper, accountEpoch, row.principal);
        else {
          this.sql.exec('DELETE FROM access WHERE principal = ?', row.principal);
          removed.push(deviceId);
        }
      }
    });
    const message: LiveMessage = { t: 'epoch', epoch: from + 1 };
    for (const ws of this.ctx.getWebSockets()) {
      try { ws.send(JSON.stringify(message)); } catch { /* reconnect reads the new epoch */ }
    }
    for (const deviceId of removed) this.closeDevice(deviceId);
    return { status: 200, body: {} };
  }
  grant(p: Principal, deviceId: string, mode: GrantMode, epoch: number, wrapper: string, accountEpoch: number, dataVersion: number): Result {
    if (!this.owns(p)) return fail(403, 'forbidden');
    const current = this.access(`acct:${p.accountId}`)!;
    if (p.protocol === 1 && current.epoch > 1) return fail(426, 'needs_update');
    if (accountEpoch !== p.epoch || accountEpoch < current.account_epoch || current.epoch !== epoch) return fail(409, 'epoch_conflict');
    if (dataVersion < current.data_floor) return fail(409, 'stale_grant');
    this.sql.exec('INSERT OR REPLACE INTO access (principal, mode, epoch, wrapper, account_epoch) VALUES (?, ?, ?, ?, ?)', `dev:${deviceId}`, mode, epoch, wrapper, accountEpoch);
    return { status: 200, body: {} };
  }
  revoke(p: Principal, deviceId: string): Result {
    if (!this.owns(p)) return fail(403, 'forbidden');
    if (p.protocol === 1 && this.access(`acct:${p.accountId}`)!.epoch > 1) return fail(426, 'needs_update');
    this.sql.exec('DELETE FROM access WHERE principal = ?', `dev:${deviceId}`);
    this.closeDevice(deviceId);
    return { status: 200, body: {} };
  }
  /** A removed account device may still have an open socket on this base. */
  closeDevice(deviceId: string, removed = false, notice: string | null = null): void {
    if (this.failNextDeviceClose) {
      this.failNextDeviceClose = false;
      throw new Error('test closeDevice failure');
    }
    const revoked: LiveMessage = { t: 'revoked', ...(notice ? { notice } : {}) };
    const message = JSON.stringify(revoked);
    if (removed) this.sql.exec('INSERT OR IGNORE INTO removed_devices VALUES (?)', deviceId);
    for (const ws of this.ctx.getWebSockets(`dev:${deviceId}`)) {
      try {
        if (removed) ws.send(message);
        ws.close(4001, 'revoked');
      } catch { /* already closed */ }
    }
    // Full devices also have sockets opened before principal tags were added.
    for (const ws of this.ctx.getWebSockets(deviceId)) {
      try {
        if (removed) ws.send(message);
        ws.close(4001, 'revoked');
      } catch { /* already closed */ }
    }
  }

  private decide(c: NewChange): Decision {
    const old = this.sql.exec<{ seq: number; prev_head: number; object_id: string }>('SELECT seq, prev_head, object_id FROM changes WHERE change_id = ?', c.changeId).toArray()[0];
    if (old) return { result: { changeId: c.changeId, seq: old.seq, prevHead: old.prev_head, tail: this.object(old.object_id).tail, stale: false } };
    const object = this.object(c.objectId);
    // Known limit: a writer may keep any number of states at the same covers.
    if (c.kind === 'state' && !(c.covers <= object.head &&
      (c.covers > object.state_covers || (c.keep && c.covers > 0 && c.covers === object.state_covers)))) {
      return { result: { changeId: c.changeId, seq: null, prevHead: object.head, tail: object.tail, stale: true } };
    }
    return { object, seq: this.head() + 1 };
  }
  /** SQLite size billed for this base. Does not hold the DO while usage is read. */
  storageBytes(): number {
    // Local workerd shrinks databaseSize after compaction of an inline change;
    // whether deployed Cloudflare storage does the same remains unverified.
    return this.ctx.storage.sql.databaseSize;
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
    const live = JSON.stringify({
      t: 'change', seq, objectId: c.objectId, prevHead: object.head, kind: c.kind,
      changeId: c.changeId, deviceId, ...(c.body.length <= 64 * 1024 ? { body: b64(c.body) } : {}),
    });
    for (const ws of this.ctx.getWebSockets()) {
      const [receiver, principal] = this.ctx.getTags(ws);
      // A socket is authenticated only at upgrade. Grants can change later.
      const openedAt = (ws.deserializeAttachment() as { openedAt: number } | null)?.openedAt ?? 0;
      const maxAge = Number(this.env.LIVE_SOCKET_MAX_AGE_MS ?? LIVE_SOCKET_MAX_AGE_MS);
      if (Date.now() - openedAt >= maxAge) {
        try { ws.close(4000, 'reconnect'); } catch { /* already closed */ }
        continue;
      }
      if (!receiver || this.removed(receiver) || !this.access(principal ?? `dev:${receiver}`)) {
        try { ws.close(4001, 'revoked'); } catch { /* already closed */ }
        continue;
      }
      if (receiver && this.dropNext.delete(receiver)) continue;
      try { ws.send(live); } catch { /* reconnect catches up from the stored head */ }
    }
    return { changeId: c.changeId, seq, prevHead: object.head, tail, stale: false };
  }
  private needsRekey(changes: NewChange[], p: Principal): boolean {
    return p.epoch > this.access(`acct:${p.accountId}`)!.account_epoch && changes.some(c =>
      !this.sql.exec('SELECT seq FROM changes WHERE change_id = ?', c.changeId).toArray().length);
  }
  private staleEpoch(changes: NewChange[], epoch: number): boolean {
    return changes.some(c => {
      // A stored change must keep its original answer even after a re-key.
      if (this.sql.exec('SELECT seq FROM changes WHERE change_id = ?', c.changeId).toArray().length) return false;
      if (c.body.length < 5 || c.body[0] !== 1) return false;
      const sealedEpoch = new DataView(c.body.buffer, c.body.byteOffset + 1, 4).getUint32(0, false);
      return sealedEpoch < epoch;
    });
  }
  async changes(p: Principal, changes: NewChange[]): Promise<Result<ChangesResponse>> {
    const denied = this.denied(p, true);
    if (denied) return denied;
    const results: ChangeResult[] = [];
    const deletes: string[] = [];
    try {
      if (!changes.some(c => c.keep || c.body.length > INLINE_MAX)) {
        // One synchronous span: no other request runs between a read and the write that depends on it.
        if (this.needsRekey(changes, p)) return fail(409, 'rekey_needed');
        if (this.staleEpoch(changes, this.access(`acct:${p.accountId}`)!.epoch)) return fail(409, 'stale_epoch');
        for (const c of changes) results.push(this.apply(p.deviceId, c, null, deletes));
      } else {
        // Writing to R2 needs awaits, so hold every other request until the batch is stored.
        // The body goes to R2 before its row exists, so a stored row always has its body.
        let failure: unknown;
        let failed = false;
        let refusal: Result<ChangesResponse> | null = null;
        await this.ctx.blockConcurrencyWhile(async () => {
          try {
            refusal = this.denied(p, true);
            if (refusal) return;
            if (this.needsRekey(changes, p)) {
              refusal = fail(409, 'rekey_needed');
              return;
            }
            if (this.staleEpoch(changes, this.access(`acct:${p.accountId}`)!.epoch)) {
              refusal = fail(409, 'stale_epoch');
              return;
            }
            for (const c of changes) {
              const decision = c.keep || c.body.length > INLINE_MAX ? this.decide(c) : null;
              const r2Key = decision && 'seq' in decision ? `b/${this.ctx.id.name}/${c.objectId}/${decision.seq}` : null;
              if (r2Key) {
                const written = await this.env.FILES.put(r2Key, c.body, { onlyIf: { etagDoesNotMatch: '*' } });
                if (!written) {
                  // A failed SQL write may have left this key behind. Reuse it only for
                  // an identical retry; never replace an existing opaque body. Known limit:
                  // if a different change for this object then takes the same sequence
                  // number, the batch fails until another change moves the sequence on.
                  const existing = await this.env.FILES.get(r2Key);
                  const bytes = existing && new Uint8Array(await existing.arrayBuffer());
                  if (!bytes || bytes.length !== c.body.length || bytes.some((b, i) => b !== c.body[i])) {
                    throw new Error('R2 body key already exists');
                  }
                }
              }
              results.push(this.apply(p.deviceId, c, r2Key, deletes));
            }
          } catch (e) {
            // An exception escaping this callback resets the whole Durable Object.
            failure = e;
            failed = true;
          }
        });
        if (failed) throw failure;
        if (refusal) return refusal;
      }
      return { status: 200, body: { results, head: this.head() } };
    } finally {
      // Best effort: a failed delete can orphan R2 bodies, but cannot fail a committed reply.
      for (let i = 0; i < deletes.length; i += 1000) {
        try { await this.env.FILES.delete(deletes.slice(i, i + 1000)); } catch { /* orphaned bodies are a known limit */ }
      }
    }
  }
  /** Test-only: omit one notification for this device while still committing it. */
  dropNextLive(deviceId: string): void { this.dropNext.add(deviceId); }
  /** Test-only: fail a base's next device-removal RPC before marking it removed. */
  failNextClose(): void { this.failNextDeviceClose = true; }
  /** Test-only: simulate a missing R2 body on the next fetch. */
  missNextFetchBody(deviceId: string): void { this.missNextFetch.add(deviceId); }
  /** Test-only: simulate a truncated fetch with an unaccounted object. */
  shortNextFetchBody(deviceId: string): void { this.shortNextFetch.add(deviceId); }
  /** Test-only: hold the Worker reply, not the DO, so other sockets can catch up. */
  holdChangeReply(deviceId: string): void { this.holdNextReply.add(deviceId); }
  takeHeldReply(deviceId: string): boolean {
    if (!this.holdNextReply.delete(deviceId)) return false;
    this.heldReply.add(deviceId);
    return true;
  }
  replyHeld(deviceId: string): boolean { return this.heldReply.has(deviceId); }
  releaseChangeReply(deviceId: string): void { this.heldReply.delete(deviceId); }
  /** Test-only: count sockets retained by this base's Durable Object. */
  liveCount(): number { return this.ctx.getWebSockets().length; }
  /** The Worker checked the token; the DO checks current membership before accepting. */
  async fetch(request: Request): Promise<Response> {
    const p: Principal = {
      accountId: request.headers.get('BH-Account') ?? '', deviceId: request.headers.get('BH-Device') ?? '',
      kind: request.headers.get('BH-Kind') === 'app' ? 'app' : 'full', status: request.headers.get('BH-Status') ?? '', epoch: 1,
      protocol: request.headers.get('BH-Protocol') === '1' ? 1 : 2,
    };
    const denied = this.denied(p);
    if (denied) return answer(denied);
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server, [p.deviceId, p.kind === 'app' ? `dev:${p.deviceId}` : `acct:${p.accountId}`, `dev:${p.deviceId}`]);
    server.serializeAttachment({ openedAt: Date.now() });
    return new Response(null, { status: 101, webSocket: client, headers: { 'BH-Protocol': '1' } });
  }
  webSocketMessage(): void { /* clients send only pings */ }
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
    if (this.missNextFetch.delete(p.deviceId)) return { status: 200, body: { objects: [], more: objectIds } };
    const short = this.shortNextFetch.delete(p.deviceId);
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
    return { status: 200, body: { objects: short ? objects.slice(0, 1) : objects, more: [] } };
  }
  /** A newest-first page of kept states, exclusive of `before`. */
  versions(p: Principal, objectId: string, before: number | null, limit: number): Result<VersionsResponse> {
    const denied = this.denied(p);
    if (denied) return denied;
    const rows = this.sql.exec<{ seq: number; covers: number; device_id: string; at: number; size: number }>(
      "SELECT seq, covers, device_id, at, size FROM changes WHERE object_id = ? AND kind = 'state' AND keep = 1 AND seq < ? ORDER BY seq DESC LIMIT ?",
      objectId, before ?? Number.MAX_SAFE_INTEGER, limit + 1).toArray();
    return { status: 200, body: { versions: rows.slice(0, limit).map(r => ({
      seq: r.seq, covers: r.covers, deviceId: r.device_id, at: r.at, size: r.size,
    })), more: rows.length > limit } };
  }
  /** Get only a kept state belonging to this exact object. */
  version(p: Principal, objectId: string, seq: number): Result<StoredVersion> {
    const denied = this.denied(p);
    if (denied) return denied;
    const row = this.sql.exec<BodyRow & { at: number }>(
      "SELECT seq, covers, device_id, at, body, r2_key, size FROM changes WHERE object_id = ? AND seq = ? AND kind = 'state' AND keep = 1",
      objectId, seq).toArray()[0];
    if (!row) return fail(404, 'not_found');
    return { status: 200, body: { seq: row.seq, covers: row.covers!, deviceId: row.device_id, at: row.at, body: stored(row) } };
  }
  /** Test-only view of what is stored for an object. */
  stored(p: Principal, objectId: string): Result<Stored> {
    const denied = this.denied(p);
    if (denied) return denied;
    const rows = this.sql.exec<{ seq: number; kind: string; keep: number; in_r2: number }>('SELECT seq, kind, keep, r2_key IS NOT NULL AS in_r2 FROM changes WHERE object_id = ? ORDER BY seq', objectId).toArray();
    return { status: 200, body: { changes: rows.map(r => ({ seq: r.seq, kind: r.kind, keep: r.keep === 1, inR2: r.in_r2 === 1 })) } };
  }
}
