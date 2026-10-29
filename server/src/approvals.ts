import type { ApprovalCreateResponse } from './proto/gen/ApprovalCreateResponse';
import type { ApprovalEndReason } from './proto/gen/ApprovalEndReason';
import type { ApprovalListResponse } from './proto/gen/ApprovalListResponse';
import type { ApprovalLiveMessage } from './proto/gen/ApprovalLiveMessage';
import type { ApprovalKind } from './proto/gen/ApprovalKind';
import type { ApprovalState } from './proto/gen/ApprovalState';
import type { ApprovalStateResponse } from './proto/gen/ApprovalStateResponse';
import type { Env, Principal, Result } from './http';
import { accountStub, answer, body, bytes, equal, fail, HttpError, id, requireDevice, revoked, str } from './http';

/** Each exchange message is at most this many bytes. */
const MESSAGE_MAX = 4096;
const CREATES_PER_HOUR = 10;
const HOUR = 60 * 60_000;
/** How long an approval is kept, so both devices can read how it ended. */
const KEEP_MS = 10 * 60_000;
const END_REASONS: readonly string[] = ['declined', 'cancelled', 'wrong_digits', 'failed', 'expired'] satisfies ApprovalEndReason[];

export type Step = 'respond' | 'reveal' | 'transfer';
type Row = {
  approval_id: string; new_device_id: string; approver_device_id: string | null; state: ApprovalState;
  end_reason: ApprovalEndReason | null; request: string; response: string | null; reveal: string | null;
  transfer: string | null; created_at: number; updated_at: number; kind: ApprovalKind; secret_hash: string | null;
};
/** The column each step fills and the state it leads to. */
const STEPS = {
  respond: { column: 'response', from: 'requested', to: 'responded' },
  reveal: { column: 'reveal', from: 'responded', to: 'revealed' },
  transfer: { column: 'transfer', from: 'revealed', to: 'transferred' },
} as const;

export function message(value: unknown): string {
  const encoded = str(value);
  if (encoded.length > Math.ceil(MESSAGE_MAX / 3) * 4) throw new HttpError(413, 'too_large');
  if (bytes(encoded).length > MESSAGE_MAX) throw new HttpError(413, 'too_large');
  return encoded;
}
async function live(request: Request, env: Env): Promise<Response> {
  const principal = await requireDevice(request, env);
  if (principal.kind !== 'full') throw new HttpError(403, 'forbidden');
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') throw new HttpError(400, 'bad_request');
  // A fresh request, so nothing the client sent reaches the object.
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(principal.accountId))
    .fetch('https://account/approvals/live', { headers: { Upgrade: 'websocket', 'BH-Device': principal.deviceId } });
}

/** The `/v1/approvals` routes. IDs are checked before the caller, which reveals nothing. */
export async function handleApprovals(request: Request, env: Env, path: string): Promise<Response> {
  const method = request.method;
  if (path === '/v1/approvals/live' && method === 'GET') return live(request, env);
  if (path === '/v1/approvals') {
    if (method !== 'POST' && method !== 'GET') throw new HttpError(404, 'not_found');
    const principal = await requireDevice(request, env);
    const account = accountStub(env, principal.accountId);
    if (method === 'GET') return answer(await account.listApprovals(principal));
    const raw = await body(request);
    return answer(await account.createApproval(principal, id(raw.approvalId), message(raw.request)));
  }
  const match = /^\/v1\/approvals\/([^/]+)(?:\/(respond|reveal|transfer))?$/.exec(path);
  if (!match) throw new HttpError(404, 'not_found');
  const approvalId = id(match[1]);
  const step = match[2] as Step | undefined;
  if (step ? method !== 'POST' : method !== 'GET' && method !== 'DELETE') throw new HttpError(404, 'not_found');
  const principal = await requireDevice(request, env);
  const account = accountStub(env, principal.accountId);
  if (method === 'GET') return answer(await account.approval(principal, approvalId));
  const raw = await body(request);
  if (!step) {
    if (typeof raw.reason !== 'string' || !END_REASONS.includes(raw.reason)) throw new HttpError(400, 'bad_request');
    return answer(await account.endApproval(principal, approvalId, raw.reason as ApprovalEndReason));
  }
  return answer(await account.approvalStep(principal, approvalId, step, message(raw[STEPS[step].column])));
}

/**
 * The relay's storage in the account's Durable Object. It carries the exchange's messages
 * without reading them. Every check and the write that depends on it run in one synchronous
 * span, so no other request interleaves.
 */
export class Approvals {
  constructor(private ctx: DurableObjectState, private env: Env) {
    const sql = ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, new_device_id TEXT NOT NULL, approver_device_id TEXT, state TEXT NOT NULL, end_reason TEXT, request TEXT NOT NULL, response TEXT, reveal TEXT, transfer TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)');
    const columns = sql.exec<{ name: string }>('PRAGMA table_info(approvals)').toArray().map(c => c.name);
    if (!columns.includes('kind')) sql.exec("ALTER TABLE approvals ADD COLUMN kind TEXT NOT NULL DEFAULT 'device'");
    if (!columns.includes('secret_hash')) sql.exec('ALTER TABLE approvals ADD COLUMN secret_hash TEXT');
    sql.exec('CREATE TABLE IF NOT EXISTS approval_creates (at INTEGER NOT NULL)');
    sql.exec('CREATE TABLE IF NOT EXISTS connect_creates (at INTEGER NOT NULL)');
  }
  private get sql() { return this.ctx.storage.sql; }
  private get ttl(): number { return Number(this.env.APPROVAL_TTL_MS ?? 120_000); }
  private row(approvalId: string): Row | null {
    return this.sql.exec<Row>('SELECT * FROM approvals WHERE approval_id = ?', approvalId).toArray()[0] ?? null;
  }
  /** Past its time, an open approval reads as expired; nothing needs to write that. */
  private view(row: Row, now: number): Row {
    return row.state !== 'ended' && now >= row.created_at + this.ttl ? { ...row, state: 'ended', end_reason: 'expired' } : row;
  }
  /** The Worker authenticated earlier; its principal may have changed before this RPC. */
  private current(p: Principal): Principal | Result<never> {
    const device = this.sql.exec<{ kind: Principal['kind']; status: string; removal_notice: string | null }>('SELECT kind, status, removal_notice FROM devices WHERE device_id = ?', p.deviceId).toArray()[0];
    if (!device) return fail(401, 'unauthorized');
    if (device.status === 'revoked') return revoked(device.removal_notice);
    return { ...p, kind: device.kind, status: device.status };
  }
  private full(p: Principal): boolean { return p.kind === 'full' && p.status === 'active'; }
  private owns(p: Principal, row: Row): boolean { return p.kind === 'full' && p.status === 'pending' && row.new_device_id === p.deviceId; }
  /** Tells every full device, and the approval's own pending device, its new state. */
  private notify(approvalId: string, newDeviceId: string, state: ApprovalState, kind: ApprovalKind, endReason?: ApprovalEndReason): void {
    const live: ApprovalLiveMessage = { t: 'approval', approvalId, kind, state, ...(endReason ? { endReason } : {}) };
    const text = JSON.stringify(live);
    for (const ws of this.ctx.getWebSockets()) {
      const tag = this.ctx.getTags(ws)[0] ?? '';
      if (!tag.startsWith('full:') && tag !== `pending:${newDeviceId}`) continue;
      try { ws.send(text); } catch { /* a closing socket catches up when it reconnects */ }
    }
  }

  async create(p: Principal, approvalId: string, request: string): Promise<Result<ApprovalCreateResponse>> {
    const now = Date.now();
    const cancelled: string[] = [];
    const refused = this.ctx.storage.transactionSync(() => {
      const current = this.current(p);
      if ('body' in current) return current;
      if (current.kind !== 'full' || current.status !== 'pending') return fail(403, 'forbidden');
      if (this.row(approvalId)) return fail(409, 'exists');
      this.sql.exec('DELETE FROM approval_creates WHERE at <= ?', now - HOUR);
      if (this.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM approval_creates').one().n >= CREATES_PER_HOUR) return fail(429, 'rate_limited');
      this.sql.exec('DELETE FROM approvals WHERE created_at <= ?', now - KEEP_MS);
      // One open request per device: a new one ends the earlier ones.
      const open = "new_device_id = ? AND state != 'ended' AND created_at > ?";
      for (const r of this.sql.exec<{ approval_id: string }>(`SELECT approval_id FROM approvals WHERE ${open}`, p.deviceId, now - this.ttl)) cancelled.push(r.approval_id);
      this.sql.exec(`UPDATE approvals SET state = 'ended', end_reason = 'cancelled', updated_at = ? WHERE ${open}`, now, p.deviceId, now - this.ttl);
      this.sql.exec("INSERT INTO approvals (approval_id, new_device_id, state, request, created_at, updated_at) VALUES (?, ?, 'requested', ?, ?, ?)",
        approvalId, p.deviceId, request, now, now);
      this.sql.exec('INSERT INTO approval_creates VALUES (?)', now);
      return null;
    });
    if (refused) return refused;
    for (const old of cancelled) this.notify(old, p.deviceId, 'ended', 'device');
    this.notify(approvalId, p.deviceId, 'requested', 'device');
    // Wake for the earliest expiry or housekeeping, including requests created earlier.
    await this.scheduleAlarm();
    return { status: 200, body: { createdAt: now, expiresAt: now + this.ttl } };
  }
  list(p: Principal): Result<ApprovalListResponse> {
    if (!this.full(p)) return fail(403, 'forbidden');
    const rows = this.sql.exec<Row>("SELECT * FROM approvals WHERE state = 'requested' AND created_at > ? ORDER BY created_at, approval_id", Date.now() - this.ttl).toArray();
    return { status: 200, body: { approvals: rows.map(r => ({ approvalId: r.approval_id, kind: r.kind, deviceId: r.new_device_id, createdAt: r.created_at, expiresAt: r.created_at + this.ttl, request: r.request })) } };
  }
  state(p: Principal, approvalId: string): Result<ApprovalStateResponse> {
    const stored = this.row(approvalId);
    if (!stored) return fail(404, 'not_found');
    if (!this.full(p) && !(stored.kind === 'device' && this.owns(p, stored))) return fail(403, 'forbidden');
    const row = this.view(stored, Date.now());
    const body: ApprovalStateResponse = { state: row.state };
    if (row.response !== null) body.response = row.response;
    if (row.reveal !== null) body.reveal = row.reveal;
    if (row.transfer !== null) body.transfer = row.transfer;
    if (row.end_reason !== null) body.endReason = row.end_reason;
    return { status: 200, body };
  }
  step(p: Principal, approvalId: string, step: Step, message: string): Result {
    if (step !== 'reveal') {
      const current = this.current(p);
      if ('body' in current) return current;
      if (current.status === 'pending') return fail(403, 'pending');
      p = current;
    }
    const stored = this.row(approvalId);
    if (!stored) return fail(404, 'not_found');
    const now = Date.now();
    const row = this.view(stored, now);
    const allowed = step === 'respond' ? this.full(p)
      : step === 'reveal' ? row.kind === 'device' && this.owns(p, row)
      : this.full(p) && row.approver_device_id === p.deviceId;
    if (!allowed) return fail(403, 'forbidden');
    const { column, from, to } = STEPS[step];
    if (row.state !== from) return fail(409, step === 'respond' && row.state !== 'ended' ? 'exists' : 'version_conflict');
    this.sql.exec(`UPDATE approvals SET state = ?, ${column} = ?, approver_device_id = COALESCE(approver_device_id, ?), updated_at = ? WHERE approval_id = ?`,
      to, message, p.deviceId, now, approvalId);
    this.notify(approvalId, row.new_device_id, to, row.kind);
    return { status: 200, body: {} };
  }
  /** Ends an approval; ending one that already ended keeps its first reason. */
  end(p: Principal, approvalId: string, reason: ApprovalEndReason): Result {
    const stored = this.row(approvalId);
    if (!stored) return fail(404, 'not_found');
    if (!this.full(p) && !(stored.kind === 'device' && this.owns(p, stored))) return fail(403, 'forbidden');
    const now = Date.now();
    if (this.view(stored, now).state === 'ended') return { status: 200, body: {} };
    this.sql.exec("UPDATE approvals SET state = 'ended', end_reason = ?, updated_at = ? WHERE approval_id = ?", reason, now, approvalId);
    this.notify(approvalId, stored.new_device_id, 'ended', stored.kind);
    return { status: 200, body: {} };
  }
  /** Creates an app exchange, independently limited from device approvals. */
  async createApp(approvalId: string, deviceId: string, secretHash: string, request: string): Promise<Result<ApprovalCreateResponse>> {
    const now = Date.now();
    const refused = this.ctx.storage.transactionSync(() => {
      if (this.row(approvalId)) return fail(409, 'exists');
      this.sql.exec('DELETE FROM connect_creates WHERE at <= ?', now - HOUR);
      if (this.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM connect_creates').one().n >= CREATES_PER_HOUR) return fail(429, 'rate_limited');
      this.sql.exec('DELETE FROM approvals WHERE created_at <= ?', now - KEEP_MS);
      this.sql.exec("INSERT INTO approvals (approval_id, new_device_id, kind, secret_hash, state, request, created_at, updated_at) VALUES (?, ?, 'app', ?, 'requested', ?, ?, ?)",
        approvalId, deviceId, secretHash, request, now, now);
      this.sql.exec('INSERT INTO connect_creates VALUES (?)', now);
      return null;
    });
    if (refused) return refused;
    this.notify(approvalId, deviceId, 'requested', 'app');
    await this.scheduleAlarm();
    return { status: 200, body: { createdAt: now, expiresAt: now + this.ttl } };
  }
  private appRow(approvalId: string, secretHash: string): Row | Result<never> {
    const row = this.row(approvalId);
    if (!row) return fail(404, 'not_found');
    if (row.kind !== 'app' || !row.secret_hash || !equal(bytes(row.secret_hash, 32), bytes(secretHash, 32))) return fail(403, 'forbidden');
    return row;
  }
  /** The app may read only its own request. */
  appState(approvalId: string, secretHash: string): Result<ApprovalStateResponse> {
    const row = this.appRow(approvalId, secretHash);
    if ('body' in row) return row;
    const view = this.view(row, Date.now());
    const body: ApprovalStateResponse = { state: view.state };
    if (view.response !== null) body.response = view.response;
    if (view.reveal !== null) body.reveal = view.reveal;
    if (view.transfer !== null) body.transfer = view.transfer;
    if (view.end_reason !== null) body.endReason = view.end_reason;
    return { status: 200, body };
  }
  /** The app alone supplies its reveal. */
  appReveal(approvalId: string, secretHash: string, reveal: string): Result {
    const row = this.appRow(approvalId, secretHash);
    if ('body' in row) return row;
    if (this.view(row, Date.now()).state !== 'responded') return fail(409, 'version_conflict');
    this.sql.exec("UPDATE approvals SET state = 'revealed', reveal = ?, updated_at = ? WHERE approval_id = ?", reveal, Date.now(), approvalId);
    this.notify(approvalId, row.new_device_id, 'revealed', 'app');
    return { status: 200, body: {} };
  }
  /** The app alone may cancel its request. */
  appEnd(approvalId: string, secretHash: string, reason: ApprovalEndReason): Result {
    const row = this.appRow(approvalId, secretHash);
    if ('body' in row) return row;
    if (this.view(row, Date.now()).state === 'ended') return { status: 200, body: {} };
    this.sql.exec("UPDATE approvals SET state = 'ended', end_reason = ?, updated_at = ? WHERE approval_id = ?", reason, Date.now(), approvalId);
    this.notify(approvalId, row.new_device_id, 'ended', 'app');
    return { status: 200, body: {} };
  }
  /** A revoked approver cannot finish the exchange; tell the new device immediately. */
  failAnswered(deviceId: string): void {
    const now = Date.now();
    const open = this.sql.exec<{ approval_id: string; new_device_id: string; kind: ApprovalKind }>(
      "SELECT approval_id, new_device_id, kind FROM approvals WHERE approver_device_id = ? AND state != 'ended' AND created_at > ?",
      deviceId, now - this.ttl).toArray();
    this.sql.exec("UPDATE approvals SET state = 'ended', end_reason = 'failed', updated_at = ? WHERE approver_device_id = ? AND state != 'ended' AND created_at > ?",
      now, deviceId, now - this.ttl);
    for (const row of open) this.notify(row.approval_id, row.new_device_id, 'ended', row.kind);
  }
  /** A device that activates or is revoked has no more use for its approvals. */
  drop(deviceId: string): void {
    const open = this.sql.exec<{ approval_id: string }>("SELECT approval_id FROM approvals WHERE new_device_id = ? AND kind = 'device' AND state != 'ended'", deviceId).toArray();
    this.sql.exec("DELETE FROM approvals WHERE new_device_id = ? AND kind = 'device'", deviceId);
    for (const r of open) this.notify(r.approval_id, deviceId, 'ended', 'device');
  }
  accept(role: 'full' | 'pending', deviceId: string): Response {
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server, [`${role}:${deviceId}`]);
    return new Response(null, { status: 101, webSocket: client, headers: { 'BH-Protocol': '1' } });
  }
  /** An activated device must reconnect with its new full role. */
  closePending(deviceId: string): void {
    for (const ws of this.ctx.getWebSockets(`pending:${deviceId}`)) {
      try { ws.close(1000, 'activated'); } catch { /* already closing */ }
    }
  }
  /** Closes a revoked device's sockets with the foundation's revoked code. */
  close(deviceId: string): void {
    for (const tag of [`full:${deviceId}`, `pending:${deviceId}`]) {
      for (const ws of this.ctx.getWebSockets(tag)) {
        try { ws.close(4001, 'revoked'); } catch { /* already closing */ }
      }
    }
  }
  /** Expiry is a state change, not just a read-time view: notify idle listeners too. */
  async prune(): Promise<void> {
    const now = Date.now();
    const expired = this.sql.exec<{ approval_id: string; new_device_id: string; kind: ApprovalKind }>(
      "SELECT approval_id, new_device_id, kind FROM approvals WHERE state != 'ended' AND created_at <= ?", now - this.ttl).toArray();
    this.sql.exec("UPDATE approvals SET state = 'ended', end_reason = 'expired', updated_at = ? WHERE state != 'ended' AND created_at <= ?", now, now - this.ttl);
    for (const row of expired) this.notify(row.approval_id, row.new_device_id, 'ended', row.kind, 'expired');
    this.sql.exec('DELETE FROM approvals WHERE created_at <= ?', now - KEEP_MS);
    await this.scheduleAlarm();
  }
  private async scheduleAlarm(): Promise<void> {
    const next = this.sql.exec<{ next: number | null }>(
      "SELECT MIN(due) AS next FROM (SELECT created_at + ? AS due FROM approvals WHERE state != 'ended' UNION ALL SELECT created_at + ? AS due FROM approvals)",
      this.ttl, KEEP_MS).one().next;
    if (next === null) { await this.ctx.storage.deleteAlarm(); return; }
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, next));
  }
}
