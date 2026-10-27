import type { SignupRequest } from './proto/gen/SignupRequest';
import type { LoginRequest } from './proto/gen/LoginRequest';
import type { CredentialsRequest } from './proto/gen/CredentialsRequest';
import type { HealthResponse } from './proto/gen/HealthResponse';
import { accountStub, answer, b64, body, bytes, equal, error, hex, HttpError, id, json, randomBytes, requireDevice, sha, str, testBypass, verifier } from './http';
import { handleBases } from './bases';
import { handleApprovals } from './approvals';
import type { Env, Result } from './http';
import { gatewayStub, handleModels } from './gateway';
import { accountUsage, monthQuery, storageRow } from './usage';
export { GatewayDO } from './gateway_do';
export { AccountDO } from './account';
export { BaseDO } from './base';
export { DirectoryDO } from './directory';
export { InvitesDO } from './invites';

type DirectoryRpc = { lookup(): Promise<string | null>; claim(id: string): Promise<boolean>; release(id: string): Promise<void> };
type InvitesRpc = { issue(): Promise<string>; valid(code: string): Promise<boolean>; consume(code: string, id: string): Promise<boolean> };
function invites(env: Env): InvitesRpc { return env.INVITES.get(env.INVITES.idFromName('invites')) as unknown as InvitesRpc; }
async function directory(env: Env, email: string): Promise<DirectoryRpc> {
  return env.DIRECTORY.get(env.DIRECTORY.idFromName(`email:${hex(await sha(email))}`)) as unknown as DirectoryRpc;
}
function address(email: unknown): string {
  const value = str(email).trim().toLowerCase();
  if (!value || !value.includes('@')) throw new HttpError(400, 'bad_request');
  return value;
}
function kdf(value: unknown): { opsLimit: number; memLimitKib: number } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new HttpError(400, 'bad_request');
  const { opsLimit, memLimitKib } = value as Record<string, unknown>;
  if (opsLimit !== 3 || memLimitKib !== 65536) throw new HttpError(400, 'bad_request');
  return { opsLimit, memLimitKib };
}
function token(accountId: string): string { return `${accountId}.${b64(randomBytes(32))}`; }
function operator(request: Request, env: Env): boolean {
  const supplied = request.headers.get('Authorization');
  if (!env.OPERATOR_TOKEN || !supplied?.startsWith('Bearer ')) return false;
  const a = new TextEncoder().encode(supplied.slice(7));
  const b = new TextEncoder().encode(env.OPERATOR_TOKEN);
  return equal(a, b);
}
async function limit(request: Request, env: Env): Promise<void> {
  if (testBypass(request, env)) return;
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip && env.LOGIN_RATE_LIMITER && !(await env.LOGIN_RATE_LIMITER.limit({ key: ip })).success) throw new HttpError(429, 'rate_limited');
}
async function fakeParams(env: Env, email: string) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.PEPPER), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(email)));
  return { salt: b64(hash.slice(0, 16)), kdf: { opsLimit: 3, memLimitKib: 65536 } };
}
async function listedBytes(env: Env, prefix: string): Promise<number> {
  let total = 0;
  let cursor: string | undefined;
  do {
    const page = await env.FILES.list({ prefix, cursor });
    for (const object of page.objects) total += object.size;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return total;
}
async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (request.headers.get('BH-Protocol') !== '1') throw new HttpError(426, 'needs_update', 'Protocol version 1 is required');
  if (request.method === 'GET' && path === '/v1/health') {
    const response: HealthResponse = { ok: true, protocol: 1 };
    return json(response);
  }
  if (request.method === 'POST' && path === '/v1/models/tinfoil/v1/chat/completions') return handleModels(request, env, ctx);
  if (request.method === 'GET' && path === '/v1/usage') {
    const principal = await requireDevice(request, env);
    if (principal.kind !== 'full') throw new HttpError(403, 'forbidden');
    const pinned = env.ALLOW_TEST_BYPASS === '1' && env.GATEWAY_NOW_MS !== undefined ? Number(env.GATEWAY_NOW_MS) : Date.now();
    const month = monthQuery(new URL(request.url).searchParams.get('month'), pinned);
    if (month === null) throw new HttpError(400, 'bad_request');
    const gateway = gatewayStub(env, principal.accountId);
    const [usage, bases] = await Promise.all([
      gateway.report(), accountStub(env, principal.accountId).usageBases(principal),
    ]);
    const report = accountUsage(usage.days, usage.breakdown, month);
    const current = new Date(pinned).toISOString().slice(0, 7);
    // A slow or failing base delays or fails the entire usage reply. Each R2 list
    // reads up to 1,000 objects, so very large bases take longer and cost more per read.
    const storage = await Promise.all(bases.map(async baseId => {
      const stub = env.BASE.get(env.BASE.idFromName(baseId)) as unknown as { storageBytes(): Promise<number> };
      const [sqlite, bodies, parts] = await Promise.all([
        stub.storageBytes(), listedBytes(env, `b/${baseId}/`), listedBytes(env, `f/${baseId}/`),
      ]);
      return storageRow(baseId, { sqlite, r2: bodies + parts }, current);
    }));
    report.months.push(...storage);
    return json(report);
  }
  if (request.method === 'POST' && path === '/v1/admin/test/legacy-usage' && env.ALLOW_TEST_BYPASS === '1') {
    if (!operator(request, env)) throw new HttpError(401, 'unauthorized');
    const accountId = id(new URL(request.url).searchParams.get('account'));
    await gatewayStub(env, accountId).seedLegacyDay();
    return json({});
  }
  if (request.method === 'GET' && path === '/v1/admin/usage') {
    if (!operator(request, env)) throw new HttpError(401, 'unauthorized');
    const accountId = id(new URL(request.url).searchParams.get('account'));
    return json({ days: await gatewayStub(env, accountId).usage() });
  }
  if (request.method === 'POST' && path === '/v1/admin/invites') {
    if (!operator(request, env)) throw new HttpError(401, 'unauthorized');
    await body(request);
    return json({ code: await invites(env).issue() });
  }
  if (request.method === 'POST' && (path === '/v1/signup' || path.startsWith('/v1/login'))) await limit(request, env);
  if (request.method === 'POST' && path === '/v1/signup') {
    const raw = await body(request);
    const input: SignupRequest = {
      invite: str(raw.invite), email: address(raw.email), accountId: id(raw.accountId),
      salt: str(raw.salt), kdf: kdf(raw.kdf), loginKey: str(raw.loginKey),
      accountKeyEnvelope: str(raw.accountKeyEnvelope), activationHash: str(raw.activationHash), deviceId: id(raw.deviceId),
    };
    if (!/^[0-9A-HJKMNP-TV-Z]{10}$/.test(input.invite)) throw new HttpError(400, 'bad_request');
    bytes(input.salt, 16); bytes(input.loginKey, 32); bytes(input.activationHash, 32); bytes(input.accountKeyEnvelope);
    if (!await invites(env).valid(input.invite)) throw new HttpError(409, 'invite_used');
    const dir = await directory(env, input.email);
    if (!await dir.claim(input.accountId)) throw new HttpError(409, 'email_taken');
    let registered = false;
    try {
      if (await accountStub(env, input.accountId).exists()) throw new HttpError(409, 'exists');
      if (!await invites(env).consume(input.invite, input.accountId)) throw new HttpError(409, 'invite_used');
      const value = token(input.accountId);
      const result = await accountStub(env, input.accountId).create(input, value, hex(await sha(value)));
      registered = result.status === 200;
      return answer(result);
    } finally {
      if (!registered) await dir.release(input.accountId);
    }
  }
  if (request.method === 'POST' && path === '/v1/login/params') {
    const email = address((await body(request)).email);
    const accountId = await (await directory(env, email)).lookup();
    return json(accountId ? (await accountStub(env, accountId).params() ?? await fakeParams(env, email)) : await fakeParams(env, email));
  }
  if (request.method === 'POST' && path === '/v1/login') {
    const raw = await body(request);
    const input: LoginRequest = { email: address(raw.email), loginKey: str(raw.loginKey), deviceId: id(raw.deviceId) };
    bytes(input.loginKey, 32);
    const accountId = await (await directory(env, input.email)).lookup();
    if (!accountId) {
      const salt = bytes((await fakeParams(env, input.email)).salt, 16);
      void equal(await verifier(bytes(input.loginKey, 32), salt), new Uint8Array(32));
      // Unknown emails have no account window, so they never reach the per-account 429 limit.
      return answer({ status: 401, body: { error: 'bad_credentials', message: 'bad_credentials' } });
    }
    const value = token(accountId);
    const result = await accountStub(env, accountId).login(input.loginKey, input.deviceId, value, hex(await sha(value)));
    return answer(result.status === 200 ? { status: 200, body: { ...(result.body as object), accountId } } : result);
  }
  if (!path.startsWith('/v1/')) throw new HttpError(404, 'not_found');
  if (path === '/v1/bases' || path.startsWith('/v1/bases/')) return handleBases(request, env, path);
  if (path === '/v1/approvals' || path.startsWith('/v1/approvals/')) return handleApprovals(request, env, path);
  // Unregistered routes must not turn into a token oracle.
  if (!['/v1/me', '/v1/account', '/v1/account/data', '/v1/account/credentials', '/v1/devices/activate', '/v1/devices'].includes(path) && !path.startsWith('/v1/devices/')) throw new HttpError(404, 'not_found');
  const principal = await requireDevice(request, env);
  const account = accountStub(env, principal.accountId);
  let result: Result;
  if (request.method === 'POST' && path === '/v1/devices/activate') {
    const raw = await body(request); const activation = str(raw.activation); bytes(activation, 32);
    result = await account.activate(principal, activation);
  } else if (request.method === 'GET' && path === '/v1/me') result = await account.me(principal);
  else if (request.method === 'GET' && path === '/v1/account') result = await account.account(principal);
  else if (request.method === 'PUT' && path === '/v1/account/data') {
    const raw = await body(request); const ciphertext = str(raw.ciphertext);
    const maxDataBytes = 1024 * 1024;
    if (ciphertext.length > 4 * Math.ceil(maxDataBytes / 3)) throw new HttpError(413, 'too_large');
    if (bytes(ciphertext).length > maxDataBytes) throw new HttpError(413, 'too_large');
    if (!Number.isSafeInteger(raw.expectedVersion) || (raw.expectedVersion as number) < 0) throw new HttpError(400, 'bad_request');
    result = await account.data(principal, ciphertext, raw.expectedVersion as number);
  } else if (request.method === 'PUT' && path === '/v1/account/credentials') {
    const raw = await body(request);
    const input: CredentialsRequest = { currentLoginKey: str(raw.currentLoginKey), loginKey: str(raw.loginKey), salt: str(raw.salt), kdf: kdf(raw.kdf), accountKeyEnvelope: str(raw.accountKeyEnvelope) };
    bytes(input.currentLoginKey, 32); bytes(input.loginKey, 32); bytes(input.salt, 16); bytes(input.accountKeyEnvelope);
    result = await account.credentials(principal, input);
  } else if (request.method === 'POST' && path === '/v1/devices') {
    const raw = await body(request); const deviceId = id(raw.deviceId);
    if (raw.kind !== 'app') throw new HttpError(400, 'bad_request');
    const value = token(principal.accountId);
    result = await account.addDevice(principal, deviceId, value, hex(await sha(value)));
  } else if (request.method === 'POST' && path === '/v1/devices/fail-next-removal' && testBypass(request, env)) {
    result = await account.failRemovalOnce(principal);
  } else if (request.method === 'DELETE' && path.startsWith('/v1/devices/')) {
    result = await account.removeDevice(principal, id(path.slice('/v1/devices/'.length)));
  } else throw new HttpError(404, 'not_found');
  return answer(result);
}
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try { return await route(request, env, ctx); }
    catch (e) {
      if (e instanceof HttpError) return error(e.code, e.status, e.message);
      // Do not include exception details: they may contain sensitive request data.
      return error('bad_gateway', 502, 'Internal server error');
    }
  },
};
