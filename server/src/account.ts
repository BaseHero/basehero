import { DurableObject } from 'cloudflare:workers';
import type { SignupRequest } from './proto/gen/SignupRequest';
import type { CredentialsRequest } from './proto/gen/CredentialsRequest';
import type { LoginParamsResponse } from './proto/gen/LoginParamsResponse';
import type { AccountResponse } from './proto/gen/AccountResponse';
import type { MeResponse } from './proto/gen/MeResponse';
import type { ApprovalEndReason } from './proto/gen/ApprovalEndReason';
import type { Env, Principal, Result, Revoked } from './http';
import { b64, bytes, equal, error, fail, randomBytes, sha, testMode, verifier } from './http';
import { Approvals } from './approvals';
import type { Step } from './approvals';
import { listedBytes } from './storage';

type AccountRow = { email: string; salt: string; kdf: string; verifier_salt: string; verifier: string; envelope: string; activation_hash: string; data: string | null; data_version: number; failed_logins: number; window_start: number };
type DeviceRow = { device_id: string; kind: 'full' | 'app'; status: string; token_hash: string; created_at: number; last_seen_at: number; cap_micro_usd: number; removal_notice: string | null };

// Abuse guard, not a billing allowance. Writes count conservatively until the
// next over-limit check re-measures real usage, no more than once a day.
const STORAGE_CAP_BYTES = 50 * 1024 * 1024 * 1024; // 50 GiB per account

export class AccountDO extends DurableObject<Env> {
  private approvals: Approvals;
  private measuringStorage?: Promise<void>;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec('CREATE TABLE IF NOT EXISTS account (id INTEGER PRIMARY KEY CHECK(id = 1), email TEXT NOT NULL, salt TEXT NOT NULL, kdf TEXT NOT NULL, verifier_salt TEXT NOT NULL, verifier TEXT NOT NULL, envelope TEXT NOT NULL, activation_hash TEXT NOT NULL, data TEXT, data_version INTEGER NOT NULL DEFAULT 0, failed_logins INTEGER NOT NULL DEFAULT 0, window_start INTEGER NOT NULL DEFAULT 0)');
    sql.exec('CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL)');
    if (!sql.exec<{ name: string }>('PRAGMA table_info(devices)').toArray().some(column => column.name === 'cap_micro_usd')) {
      sql.exec('ALTER TABLE devices ADD COLUMN cap_micro_usd INTEGER NOT NULL DEFAULT 1000000');
    }
    // The removing device's notice, returned with every `revoked` answer; the server can't make one.
    if (!sql.exec<{ name: string }>('PRAGMA table_info(devices)').toArray().some(column => column.name === 'removal_notice')) {
      sql.exec('ALTER TABLE devices ADD COLUMN removal_notice TEXT');
    }
    sql.exec('CREATE TABLE IF NOT EXISTS bases (base_id TEXT PRIMARY KEY, added_at INTEGER NOT NULL)');
    sql.exec('CREATE TABLE IF NOT EXISTS device_bases (device_id TEXT NOT NULL, base_id TEXT NOT NULL, PRIMARY KEY (device_id, base_id))');
    sql.exec('CREATE TABLE IF NOT EXISTS storage_guard (bytes INTEGER NOT NULL, measured_at INTEGER NOT NULL DEFAULT 0)');
    if (!sql.exec<{ name: string }>('PRAGMA table_info(storage_guard)').toArray().some(column => column.name === 'measured_at')) {
      sql.exec('ALTER TABLE storage_guard ADD COLUMN measured_at INTEGER NOT NULL DEFAULT 0');
    }
    this.approvals = new Approvals(ctx, env);
  }
  private row(): AccountRow | null { return this.ctx.storage.sql.exec<AccountRow>('SELECT * FROM account WHERE id = 1').toArray()[0] ?? null; }
  exists(): boolean { return this.row() !== null; }
  params(): LoginParamsResponse | null {
    const row = this.row();
    return row ? { salt: row.salt, kdf: JSON.parse(row.kdf) } : null;
  }
  async create(input: SignupRequest, token: string, tokenHash: string): Promise<Result> {
    if (this.exists()) return fail(409, 'exists');
    const salt = b64(randomBytes(16));
    const hash = b64(await verifier(bytes(input.loginKey, 32), bytes(salt)));
    // The insert makes the account's existence and first active device atomic.
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec('INSERT INTO account (id,email,salt,kdf,verifier_salt,verifier,envelope,activation_hash) VALUES (1,?,?,?,?,?,?,?)',
        input.email, input.salt, JSON.stringify(input.kdf), salt, hash, input.accountKeyEnvelope, input.activationHash);
      const now = Date.now();
      this.ctx.storage.sql.exec('INSERT INTO devices (device_id, kind, status, token_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)', input.deviceId, 'full', 'active', tokenHash, now, now);
    });
    return { status: 200, body: { token } };
  }
  async login(key: string, deviceId: string, token: string, tokenHash: string): Promise<Result> {
    const row = this.row();
    if (!row) return fail(401, 'bad_credentials');
    const now = Date.now();
    // No await may separate the throttle check and increment: input gates reopen during PBKDF2.
    const withinWindow = now - row.window_start < 15 * 60_000;
    if (withinWindow && row.failed_logins >= 10) return fail(429, 'rate_limited');
    if (withinWindow) this.ctx.storage.sql.exec('UPDATE account SET failed_logins = failed_logins + 1 WHERE id = 1');
    else this.ctx.storage.sql.exec('UPDATE account SET failed_logins = 1, window_start = ? WHERE id = 1', now);
    const valid = equal(await verifier(bytes(key, 32), bytes(row.verifier_salt, 16)), bytes(row.verifier, 32));
    if (!valid) return fail(401, 'bad_credentials');
    if (this.ctx.storage.sql.exec('SELECT device_id FROM devices WHERE device_id = ?', deviceId).toArray().length) return fail(409, 'exists');
    this.ctx.storage.sql.exec('UPDATE account SET failed_logins = 0, window_start = 0 WHERE id = 1');
    this.ctx.storage.sql.exec('INSERT INTO devices (device_id, kind, status, token_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)', deviceId, 'full', 'pending', tokenHash, now, now);
    return { status: 200, body: { token, accountKeyEnvelope: row.envelope } };
  }
  // Each device's recent change requests, in memory: a restart only resets the window.
  private changeTimes = new Map<string, number[]>();
  auth(tokenHash: string, countChange = false): Principal | Revoked | 'rate_limited' | null {
    const device = this.ctx.storage.sql.exec<DeviceRow>('SELECT * FROM devices WHERE token_hash = ?', tokenHash).toArray()[0];
    if (!device) return null;
    if (device.status === 'revoked') return { revoked: device.removal_notice };
    if (countChange) {
      const now = Date.now();
      const window = Number((this.env as Env).CHANGE_RATE_WINDOW_MS ?? 1000);
      const recent = (this.changeTimes.get(device.device_id) ?? []).filter(t => now - t < window);
      if (recent.length >= 50) return 'rate_limited';
      recent.push(now);
      this.changeTimes.set(device.device_id, recent);
    }
    // Even a first request in the creation millisecond marks the device as used.
    this.ctx.storage.sql.exec('UPDATE devices SET last_seen_at = ? WHERE device_id = ?', Math.max(Date.now(), device.created_at + 1), device.device_id);
    return { accountId: this.ctx.id.name!, deviceId: device.device_id, kind: device.kind, status: device.status,
      ...(device.kind === 'app' ? { capMicroUsd: device.cap_micro_usd } : {}) };
  }
  async activate(principal: Principal, activation: string): Promise<Result> {
    if (principal.status !== 'pending' || principal.kind !== 'full') return fail(403, 'forbidden');
    const row = this.row();
    if (!row || !equal(await sha(bytes(activation, 32)), bytes(row.activation_hash, 32))) return fail(401, 'unauthorized');
    this.ctx.storage.sql.exec("UPDATE devices SET status = 'active' WHERE device_id = ? AND status = 'pending'", principal.deviceId);
    this.approvals.closePending(principal.deviceId);
    this.approvals.drop(principal.deviceId);
    return { status: 200, body: {} };
  }
  private bases(deviceId: string): string[] {
    return this.ctx.storage.sql.exec<{ base_id: string }>('SELECT base_id FROM device_bases WHERE device_id = ? ORDER BY base_id', deviceId).toArray().map(r => r.base_id);
  }
  private accountBases(): string[] {
    return this.ctx.storage.sql.exec<{ base_id: string }>('SELECT base_id FROM bases ORDER BY added_at, base_id').toArray().map(b => b.base_id);
  }
  private storageNow(): number {
    return testMode(this.env) && this.env.STORAGE_NOW_MS !== undefined
      ? Number(this.env.STORAGE_NOW_MS) : Date.now();
  }
  /** Measure the same base SQLite and R2 bytes as /v1/usage; preserve writes reserved during the read. */
  private async measureStorage(): Promise<void> {
    const sql = this.ctx.storage.sql;
    const previous = sql.exec<{ bytes: number }>('SELECT bytes FROM storage_guard').toArray()[0];
    let total = 0;
    for (const baseId of this.accountBases()) {
      const stub = this.env.BASE.get(this.env.BASE.idFromName(baseId)) as unknown as { storageBytes(): Promise<number> };
      total += await stub.storageBytes();
      total += await listedBytes(this.env, `b/${baseId}/`);
      total += await listedBytes(this.env, `f/${baseId}/`);
    }
    const measuredAt = this.storageNow();
    if (previous) {
      // In-flight reservations may not yet appear in the measured R2/SQLite sizes.
      sql.exec('UPDATE storage_guard SET bytes = ? + max(bytes - ?, 0), measured_at = ?', total, previous.bytes, measuredAt);
    } else {
      sql.exec('INSERT INTO storage_guard (bytes, measured_at) VALUES (?, ?)', total, measuredAt);
    }
  }
  private async refreshStorage(): Promise<void> {
    this.measuringStorage ??= this.measureStorage().finally(() => { this.measuringStorage = undefined; });
    await this.measuringStorage;
  }
  /** Reserve before writing; synchronous check-and-add serializes concurrent devices. */
  async reserveStorage(bytes: number): Promise<boolean> {
    const sql = this.ctx.storage.sql;
    type Guard = { bytes: number; measured_at: number };
    if (!sql.exec<Guard>('SELECT bytes, measured_at FROM storage_guard').toArray().length) await this.refreshStorage();
    let { bytes: used, measured_at: measuredAt } = sql.exec<Guard>('SELECT bytes, measured_at FROM storage_guard').one();
    const cap = testMode(this.env) && this.env.STORAGE_CAP_TEST_BYTES !== undefined
      ? Number(this.env.STORAGE_CAP_TEST_BYTES) : STORAGE_CAP_BYTES;
    if (used + bytes > cap && this.storageNow() - measuredAt >= 24 * 60 * 60 * 1000) {
      await this.refreshStorage();
      ({ bytes: used, measured_at: measuredAt } = sql.exec<Guard>('SELECT bytes, measured_at FROM storage_guard').one());
    }
    if (used + bytes > cap) return false;
    sql.exec('UPDATE storage_guard SET bytes = bytes + ?', bytes);
    return true;
  }
  /** Server-side IDs only; the caller is authenticated by the Worker. */
  usageBases(principal: Principal): string[] {
    return principal.kind === 'full' && principal.status === 'active' ? this.accountBases() : [];
  }
  me(principal: Principal): Result<MeResponse> {
    const bases = principal.kind === 'full' ? this.accountBases() : this.bases(principal.deviceId);
    return { status: 200, body: { accountId: principal.accountId, deviceId: principal.deviceId, kind: principal.kind, bases } };
  }
  account(principal: Principal): Result<AccountResponse> {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    const row = this.row()!;
    const devices = this.ctx.storage.sql.exec<DeviceRow>('SELECT * FROM devices ORDER BY created_at, device_id').toArray()
      .map(d => ({ deviceId: d.device_id, kind: d.kind, status: d.status, createdAt: d.created_at, lastSeenAt: d.last_seen_at,
        ...(d.kind === 'app' ? { capMicroUsd: d.cap_micro_usd } : {}) }));
    return { status: 200, body: { devices, bases: this.accountBases(), data: row.data === null ? null : { ciphertext: row.data, version: row.data_version }, accountKeyEnvelope: row.envelope } };
  }
  data(principal: Principal, ciphertext: string, expectedVersion: number): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    const row = this.row()!;
    if (row.data_version !== expectedVersion) return fail(409, 'version_conflict');
    const version = expectedVersion + 1;
    this.ctx.storage.sql.exec('UPDATE account SET data = ?, data_version = ? WHERE id = 1', ciphertext, version);
    return { status: 200, body: { version } };
  }
  async credentials(principal: Principal, input: CredentialsRequest): Promise<Result> {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    const row = this.row()!;
    const valid = equal(await verifier(bytes(input.currentLoginKey, 32), bytes(row.verifier_salt, 16)), bytes(row.verifier, 32));
    if (!valid) return fail(401, 'bad_credentials');
    const salt = b64(randomBytes(16));
    const hash = b64(await verifier(bytes(input.loginKey, 32), bytes(salt)));
    this.ctx.storage.sql.exec('UPDATE account SET salt = ?, kdf = ?, verifier_salt = ?, verifier = ?, envelope = ? WHERE id = 1',
      input.salt, JSON.stringify(input.kdf), salt, hash, input.accountKeyEnvelope);
    return { status: 200, body: {} };
  }
  addDevice(principal: Principal, deviceId: string, token: string, tokenHash: string, capMicroUsd = 1_000_000): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    if (this.ctx.storage.sql.exec('SELECT device_id FROM devices WHERE device_id = ?', deviceId).toArray().length) return fail(409, 'exists');
    const now = Date.now();
    this.ctx.storage.sql.exec('INSERT INTO devices (device_id, kind, status, token_hash, created_at, last_seen_at, cap_micro_usd) VALUES (?, ?, ?, ?, ?, ?, ?)', deviceId, 'app', 'active', tokenHash, now, now, capMicroUsd);
    return { status: 200, body: { token } };
  }
  setCap(principal: Principal, deviceId: string, cap: number): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    const updated = this.ctx.storage.sql.exec("UPDATE devices SET cap_micro_usd = ? WHERE device_id = ? AND kind = 'app' AND status = 'active' RETURNING device_id", cap, deviceId).toArray();
    return updated.length ? { status: 200, body: {} } : fail(404, 'not_found');
  }
  testLastSeen(principal: Principal, deviceId: string, lastSeenAt: number): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    const changed = this.ctx.storage.sql.exec('UPDATE devices SET last_seen_at = ? WHERE device_id = ? RETURNING device_id', lastSeenAt, deviceId).toArray();
    return changed.length ? { status: 200, body: {} } : fail(404, 'not_found');
  }
  private failNextRemoval = false;
  failRemovalOnce(principal: Principal): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    this.failNextRemoval = true;
    return { status: 200, body: {} };
  }
  async removeDevice(principal: Principal, deviceId: string, notice: string | null = null): Promise<Result> {
    if (principal.kind !== 'full' && principal.deviceId !== deviceId) return fail(403, 'forbidden');
    if (!this.ctx.storage.sql.exec('SELECT device_id FROM devices WHERE device_id = ?', deviceId).toArray().length) return fail(404, 'not_found');
    if (this.failNextRemoval) {
      this.failNextRemoval = false;
      return fail(502, 'bad_gateway', 'pre-revocation fault');
    }
    // Use the account's base list for both full devices and granted apps. It also
    // covers a grant whose device_bases entry was already removed by a revoke.
    const bases = this.accountBases();
    // A later removal without a notice, such as an older app's, keeps an earlier notice.
    const stored = this.ctx.storage.transactionSync(() => {
      const row = this.ctx.storage.sql.exec<{ removal_notice: string | null }>("UPDATE devices SET status = 'revoked', removal_notice = COALESCE(?, removal_notice) WHERE device_id = ? RETURNING removal_notice", notice, deviceId).one();
      this.ctx.storage.sql.exec('DELETE FROM device_bases WHERE device_id = ?', deviceId);
      return row.removal_notice;
    });
    this.approvals.close(deviceId);
    this.approvals.drop(deviceId);
    this.approvals.failAnswered(deviceId);
    const results = await Promise.allSettled(bases.map(baseId => {
      const base = this.env.BASE.get(this.env.BASE.idFromName(baseId)) as unknown as { closeDevice(id: string, removed: boolean, notice: string | null): Promise<void> };
      return base.closeDevice(deviceId, true, stored);
    }));
    if (results.some(result => result.status === 'rejected')) return fail(502, 'bad_gateway');
    return { status: 200, body: {} };
  }
  addBase(principal: Principal, baseId: string): void {
    if (principal.kind !== 'full') return;
    this.ctx.storage.sql.exec('INSERT OR IGNORE INTO bases VALUES (?, ?)', baseId, Date.now());
  }
  // The base's own access table is authoritative; device_bases only lists what an app may open.
  grantApp(principal: Principal, baseId: string, deviceId: string): Result {
    if (principal.kind !== 'full' || !this.ctx.storage.sql.exec('SELECT base_id FROM bases WHERE base_id = ?', baseId).toArray().length) return fail(403, 'forbidden');
    const device = this.ctx.storage.sql.exec<DeviceRow>("SELECT * FROM devices WHERE device_id = ? AND kind = 'app' AND status = 'active'", deviceId).toArray()[0];
    if (!device) return fail(404, 'not_found');
    this.ctx.storage.sql.exec('INSERT OR IGNORE INTO device_bases VALUES (?, ?)', deviceId, baseId);
    return { status: 200, body: {} };
  }
  ungrantApp(principal: Principal, baseId: string, deviceId: string): Result {
    if (principal.kind !== 'full') return fail(403, 'forbidden');
    this.ctx.storage.sql.exec('DELETE FROM device_bases WHERE device_id = ? AND base_id = ?', deviceId, baseId);
    return { status: 200, body: {} };
  }
  connectCreate(approvalId: string, deviceId: string, secretHash: string, request: string): Promise<Result> { return this.approvals.createApp(approvalId, deviceId, secretHash, request); }
  connectState(approvalId: string, secretHash: string): Result { return this.approvals.appState(approvalId, secretHash); }
  connectReveal(approvalId: string, secretHash: string, reveal: string): Result { return this.approvals.appReveal(approvalId, secretHash, reveal); }
  connectEnd(approvalId: string, secretHash: string, reason: ApprovalEndReason): Result { return this.approvals.appEnd(approvalId, secretHash, reason); }
  createApproval(principal: Principal, approvalId: string, request: string): Promise<Result> { return this.approvals.create(principal, approvalId, request); }
  listApprovals(principal: Principal): Result { return this.approvals.list(principal); }
  approval(principal: Principal, approvalId: string): Result { return this.approvals.state(principal, approvalId); }
  approvalStep(principal: Principal, approvalId: string, step: Step, message: string): Result { return this.approvals.step(principal, approvalId, step, message); }
  endApproval(principal: Principal, approvalId: string, reason: ApprovalEndReason): Result { return this.approvals.end(principal, approvalId, reason); }
  /** The Worker's upgrade for `/v1/approvals/live`, after it checked the device's token. */
  async fetch(request: Request): Promise<Response> {
    const deviceId = request.headers.get('BH-Device');
    const device = this.ctx.storage.sql.exec<DeviceRow>('SELECT * FROM devices WHERE device_id = ?', deviceId).toArray()[0];
    // A device revoked since the Worker's check is refused here, where revocation closes sockets.
    if (device?.kind !== 'full' || device.status === 'revoked') return error('revoked', 401, 'revoked', device?.removal_notice ?? null);
    return this.approvals.accept(device.status === 'pending' ? 'pending' : 'full', device.device_id);
  }
  webSocketMessage(): void { /* clients send only pings */ }
  async alarm(): Promise<void> { await this.approvals.prune(); }
}
