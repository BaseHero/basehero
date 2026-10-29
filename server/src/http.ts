import type { ErrorBody } from './proto/gen/ErrorBody';

export type Principal = { accountId: string; deviceId: string; kind: 'full' | 'app'; status: string; capMicroUsd?: number };
export type Env = {
  ACCOUNT: DurableObjectNamespace;
  BASE: DurableObjectNamespace;
  FILES: R2Bucket;
  DIRECTORY: DurableObjectNamespace;
  INVITES: DurableObjectNamespace;
  OPERATOR_TOKEN: string;
  PEPPER: string;
  TINFOIL_API_KEY: string;
  TINFOIL_MODELS: string;
  GATEWAY: DurableObjectNamespace;
  GATEWAY_PER_MINUTE: string;
  GATEWAY_PER_DAY: string;
  GATEWAY_DAILY_COST_USD: string;
  /** What a call whose usage never arrives counts against the daily cost cap. */
  GATEWAY_UNREPORTED_CALL_USD: string;
  /** The most output tokens any model call may produce. */
  GATEWAY_MAX_OUTPUT_TOKENS: string;
  /** Local tests' loopback model upstream, `host:port` over plain TCP; honoured only with ALLOW_TEST_BYPASS. */
  TINFOIL_CONNECT?: string;
  /** Local tests may pin the gateway clock to avoid minute-boundary races. */
  GATEWAY_NOW_MS?: string;
  BH_ENV?: string;
  ALLOW_TEST_BYPASS?: string;
  /** Local tests only: exercise the production storage guard with tiny writes. */
  STORAGE_CAP_TEST_BYTES?: string;
  /** Local tests may advance the storage guard's one-day measurement window. */
  STORAGE_NOW_MS?: string;
  /** Tests lengthen the change-rate window so its limit doesn't depend on timing. */
  CHANGE_RATE_WINDOW_MS?: string;
  /** How long the relay keeps an approval open; tests shorten it. */
  APPROVAL_TTL_MS?: string;
  /** Tests shorten the maximum age of a live socket before broadcast closes it. */
  LIVE_SOCKET_MAX_AGE_MS?: string;
  LOGIN_RATE_LIMITER?: { limit(input: { key: string }): Promise<{ success: boolean }> };
};
export type Result<T = object> = { status: number; body: T | ErrorBody };
/** A removed device, with its removal notice if the removing device sent one. */
export type Revoked = { revoked: string | null };

export class HttpError extends Error {
  constructor(public status: number, public code: string, message = code, public notice: string | null = null) { super(message); }
}
export function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', 'BH-Protocol': '1' },
  });
}
export function error(code: string, status: number, message: string, notice: string | null = null): Response {
  const body: ErrorBody = { error: code, message, ...(notice ? { notice } : {}) };
  return json(body, status);
}
export function fail(status: number, code: string, message = code): Result<never> {
  return { status, body: { error: code, message } };
}
/** A removed device's answer, with the removing device's notice if it sent one. */
export function revoked(notice: string | null): Result<never> {
  return { status: 401, body: { error: 'revoked', message: 'revoked', ...(notice ? { notice } : {}) } };
}
/** `{ notice }` from a removal's optional body; older clients send none. */
export async function removalNotice(request: Request): Promise<string | null> {
  const text = await request.text();
  if (!text) return null;
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new HttpError(400, 'bad_request'); }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new HttpError(400, 'bad_request');
  const notice = (value as Record<string, unknown>).notice;
  if (notice === undefined) return null;
  bytes(notice, 32);
  return notice as string;
}
export function answer(result: Result): Response { return json(result.body, result.status); }
/** Reads no more than `max` actual bytes, regardless of Content-Length. */
export async function limitedBytes(request: Request, max: number): Promise<Uint8Array> {
  const length = request.headers.get('Content-Length');
  if (length !== null && Number(length) > max) throw new HttpError(413, 'too_large');
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        try { await reader.cancel(); } catch { /* keep the 413 if cancellation fails */ }
        throw new HttpError(413, 'too_large');
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}
export async function body(request: Request, max = 2 * 1024 * 1024): Promise<Record<string, unknown>> {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await limitedBytes(request, max))); }
  catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, 'bad_request');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new HttpError(400, 'bad_request');
  return value as Record<string, unknown>;
}
/** Test controls are available only in the dev environment, never production. */
export function testMode(env: Env): boolean { return env.BH_ENV === 'dev' && env.ALLOW_TEST_BYPASS === '1'; }
/** True only on a server that allows test bypass, for a request carrying the operator token. */
export function testBypass(request: Request, env: Env): boolean {
  const bypass = request.headers.get('BH-Test-Bypass');
  return testMode(env) && !!env.OPERATOR_TOKEN && bypass !== null &&
    equal(new TextEncoder().encode(bypass), new TextEncoder().encode(env.OPERATOR_TOKEN));
}
export function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) throw new HttpError(400, 'bad_request');
  return value;
}
export function str(value: unknown): string {
  if (typeof value !== 'string' || !value) throw new HttpError(400, 'bad_request');
  return value;
}
export function bytes(value: unknown, length?: number): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new HttpError(400, 'bad_request');
  let decoded: Uint8Array;
  try { decoded = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0)); }
  catch { throw new HttpError(400, 'bad_request'); }
  if (b64(decoded) !== value || (length !== undefined && decoded.length !== length)) throw new HttpError(400, 'bad_request');
  return decoded;
}
export function b64(value: Uint8Array): string {
  let encoded = '';
  // Avoid passing an unbounded array as function arguments (Workers impose a limit).
  for (let start = 0; start < value.length; start += 8192) {
    encoded += String.fromCharCode(...value.subarray(start, start + 8192));
  }
  return btoa(encoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function randomBytes(length: number): Uint8Array { return crypto.getRandomValues(new Uint8Array(length)); }
export async function sha(value: string | Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? new TextEncoder().encode(value) : Uint8Array.from(value)));
}
export function hex(value: Uint8Array): string { return Array.from(value, b => b.toString(16).padStart(2, '0')).join(''); }
export async function verifier(key: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey('raw', Uint8Array.from(key), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: Uint8Array.from(salt), iterations: 100000 }, material, 256));
}
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && (crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean }).timingSafeEqual(a, b);
}
export function accountStub(env: Env, accountId: string): AccountRpc {
  return env.ACCOUNT.get(env.ACCOUNT.idFromName(id(accountId))) as unknown as AccountRpc;
}
export type AccountRpc = {
  exists(): Promise<boolean>;
  create(input: import('./proto/gen/SignupRequest').SignupRequest, token: string, tokenHash: string): Promise<Result>;
  params(): Promise<import('./proto/gen/LoginParamsResponse').LoginParamsResponse | null>;
  login(key: string, deviceId: string, token: string, tokenHash: string): Promise<Result>;
  auth(tokenHash: string, countChange: boolean): Promise<Principal | Revoked | 'rate_limited' | null>;
  activate(principal: Principal, activation: string): Promise<Result>;
  me(principal: Principal): Promise<Result>;
  account(principal: Principal): Promise<Result>;
  usageBases(principal: Principal): Promise<string[]>;
  reserveStorage(bytes: number): Promise<boolean>;
  data(principal: Principal, ciphertext: string, expectedVersion: number): Promise<Result>;
  credentials(principal: Principal, input: import('./proto/gen/CredentialsRequest').CredentialsRequest): Promise<Result>;
  addDevice(principal: Principal, deviceId: string, token: string, tokenHash: string, capMicroUsd?: number): Promise<Result>;
  setCap(principal: Principal, deviceId: string, cap: number): Promise<Result>;
  removeDevice(principal: Principal, deviceId: string, notice: string | null): Promise<Result>;
  failRemovalOnce(principal: Principal): Promise<Result>;
  testLastSeen(principal: Principal, deviceId: string, lastSeenAt: number): Promise<Result>;
  addBase(principal: Principal, baseId: string): Promise<void>;
  grantApp(principal: Principal, baseId: string, deviceId: string): Promise<Result>;
  ungrantApp(principal: Principal, baseId: string, deviceId: string): Promise<Result>;
  connectCreate(approvalId: string, deviceId: string, secretHash: string, request: string): Promise<Result>;
  connectState(approvalId: string, secretHash: string): Promise<Result>;
  connectReveal(approvalId: string, secretHash: string, reveal: string): Promise<Result>;
  connectEnd(approvalId: string, secretHash: string, reason: import('./proto/gen/ApprovalEndReason').ApprovalEndReason): Promise<Result>;
  createApproval(principal: Principal, approvalId: string, request: string): Promise<Result>;
  listApprovals(principal: Principal): Promise<Result>;
  approval(principal: Principal, approvalId: string): Promise<Result>;
  approvalStep(principal: Principal, approvalId: string, step: import('./approvals').Step, message: string): Promise<Result>;
  endApproval(principal: Principal, approvalId: string, reason: import('./proto/gen/ApprovalEndReason').ApprovalEndReason): Promise<Result>;
};
/** Authenticates the caller; `countChange` counts the request against the device's change rate. */
export async function requireDevice(request: Request, env: Env, countChange = false): Promise<Principal> {
  const match = /^Bearer ([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/.exec(request.headers.get('Authorization') ?? '');
  if (!match) throw new HttpError(401, 'unauthorized');
  const token = `${match[1]}.${match[2]}`;
  const principal = await accountStub(env, match[1]).auth(hex(await sha(token)), countChange);
  if (principal === 'rate_limited') throw new HttpError(429, 'rate_limited');
  if (!principal) throw new HttpError(401, 'unauthorized');
  if ('revoked' in principal) throw new HttpError(401, 'revoked', 'revoked', principal.revoked);
  if (principal.status === 'pending' && !pendingMayReach(request.method, new URL(request.url).pathname)) {
    throw new HttpError(403, 'pending');
  }
  return principal;
}
/** A pending device reaches only activation and its own approval's steps; `AccountDO` checks the approval is its. */
function pendingMayReach(method: string, path: string): boolean {
  if (method === 'POST' && (path === '/v1/devices/activate' || path === '/v1/approvals')) return true;
  if (method === 'GET' && path === '/v1/approvals/live') return true;
  if (/^\/v1\/approvals\/[0-9a-f]{32}$/.test(path)) return method === 'GET' || method === 'DELETE';
  return method === 'POST' && /^\/v1\/approvals\/[0-9a-f]{32}\/reveal$/.test(path);
}
