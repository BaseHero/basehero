import type { Created, Fetched, NewChange, Stored, StoredBody, StoredVersion } from './base';
import { handleFiles } from './files';
import type { VersionResponse } from './proto/gen/VersionResponse';
import type { FetchResponse } from './proto/gen/FetchResponse';
import type { GrantMode } from './proto/gen/GrantMode';
import type { Env, Principal, Result } from './http';
import { accountStub, answer, b64, body, bytes, HttpError, id, json, requireDevice, str, testBypass } from './http';

const MIB = 1024 * 1024;
/** The bodies of one changes request total at most this, so one change is at most this too. */
const CHANGES_BODY_MAX = 8 * MIB;
const CHANGES_MAX = 1000;
const FETCH_IDS_MAX = 200;
const SINCE_LIMIT_MAX = 1000;
const VERSIONS_LIMIT_MAX = 200;

type BaseRpc = {
  create(p: Principal, epoch: number, wrapper: string): Promise<Created>;
  key(p: Principal): Promise<Result>;
  grant(p: Principal, deviceId: string, mode: GrantMode, epoch: number, wrapper: string): Promise<Result>;
  revoke(p: Principal, deviceId: string): Promise<Result>;
  changes(p: Principal, changes: NewChange[]): Promise<Result>;
  since(p: Principal, after: number, limit: number): Promise<Result>;
  fetchObjects(p: Principal, objectIds: string[]): Promise<Result<Fetched>>;
  versions(p: Principal, objectId: string, before: number | null, limit: number): Promise<Result>;
  version(p: Principal, objectId: string, seq: number): Promise<Result<StoredVersion>>;
  stored(p: Principal, objectId: string): Promise<Result<Stored>>;
  dropNextLive(deviceId: string): Promise<void>;
  failNextClose(): Promise<void>;
  missNextFetchBody(deviceId: string): Promise<void>;
  shortNextFetchBody(deviceId: string): Promise<void>;
  holdChangeReply(deviceId: string): Promise<void>;
  takeHeldReply(deviceId: string): Promise<boolean>;
  replyHeld(deviceId: string): Promise<boolean>;
  releaseChangeReply(deviceId: string): Promise<void>;
  liveCount(): Promise<number>;
};
function baseStub(env: Env, baseId: string): BaseRpc {
  return env.BASE.get(env.BASE.idFromName(id(baseId))) as unknown as BaseRpc;
}
function epoch(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 0xffffffff) throw new HttpError(400, 'bad_request');
  return value as number;
}
function wrapper(value: unknown): string {
  const encoded = str(value);
  if (bytes(encoded).length > 1024) throw new HttpError(400, 'bad_request');
  return encoded;
}
function count(value: string | null, fallback: number): number {
  if (value === null) return fallback;
  if (!/^\d{1,15}$/.test(value)) throw new HttpError(400, 'bad_request');
  return Number(value);
}
function positiveSequence(value: string): number {
  const seq = count(value, 0);
  if (seq < 1 || !Number.isSafeInteger(seq)) throw new HttpError(400, 'bad_request');
  return seq;
}
function change(value: unknown): NewChange {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new HttpError(400, 'bad_request');
  const c = value as Record<string, unknown>;
  const changeId = id(c.changeId), objectId = id(c.objectId);
  if (c.kind !== 'update' && c.kind !== 'state') throw new HttpError(400, 'bad_request');
  const encoded = str(c.body);
  if (encoded.length > Math.ceil(CHANGES_BODY_MAX / 3) * 4) throw new HttpError(413, 'too_large');
  if (c.kind === 'update') return { changeId, objectId, kind: c.kind, body: bytes(encoded), covers: 0, keep: false };
  if (!Number.isSafeInteger(c.covers) || (c.covers as number) < 0) throw new HttpError(400, 'bad_request');
  if (c.keep !== undefined && typeof c.keep !== 'boolean') throw new HttpError(400, 'bad_request');
  return { changeId, objectId, kind: c.kind, body: bytes(encoded), covers: c.covers as number, keep: c.keep === true };
}

async function create(request: Request, env: Env): Promise<Response> {
  const principal = await requireDevice(request, env);
  const raw = await body(request);
  const baseId = id(raw.baseId);
  const input = { epoch: epoch(raw.epoch), wrapper: wrapper(raw.wrapper) };
  if (principal.kind !== 'full') throw new HttpError(403, 'forbidden');
  const outcome = await baseStub(env, baseId).create(principal, input.epoch, input.wrapper);
  // Listing it again heals an account that missed the base after an interrupted create.
  if (outcome !== 'taken') await accountStub(env, principal.accountId).addBase(principal, baseId);
  if (outcome !== 'created') throw new HttpError(409, 'exists');
  return json({});
}
async function changes(request: Request, env: Env, baseId: string): Promise<Response> {
  // The base64 bodies plus their JSON, bounded before the request is read.
  if (Number(request.headers.get('Content-Length') ?? 0) > CHANGES_BODY_MAX / 3 * 4 + MIB) throw new HttpError(413, 'too_large');
  const principal = await requireDevice(request, env, true);
  const raw = await body(request);
  if (!Array.isArray(raw.changes)) throw new HttpError(400, 'bad_request');
  if (raw.changes.length > CHANGES_MAX) throw new HttpError(413, 'too_large');
  const input = raw.changes.map(change);
  if (input.reduce((n, c) => n + c.body.length, 0) > CHANGES_BODY_MAX) throw new HttpError(413, 'too_large');
  const base = baseStub(env, baseId);
  const result = await base.changes(principal, input);
  if (testBypass(request, env) && await base.takeHeldReply(principal.deviceId)) {
    while (await base.replyHeld(principal.deviceId)) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }
  return answer(result);
}
async function fetchObjects(request: Request, env: Env, baseId: string): Promise<Response> {
  const principal = await requireDevice(request, env);
  const raw = await body(request);
  if (!Array.isArray(raw.objectIds) || raw.objectIds.length > FETCH_IDS_MAX) throw new HttpError(400, 'bad_request');
  const ids = [...new Set(raw.objectIds.map(id))];
  const result = await baseStub(env, baseId).fetchObjects(principal, ids);
  if (result.status !== 200) return answer(result);
  const fetched = result.body as Fetched;
  // A body in R2 can vanish when a newer state replaces it after the read; that object is
  // listed in `more`, and the client's next fetch gets the newer state.
  const vanished = new Set<string>();
  const encode = async (objectId: string, stored: StoredBody): Promise<string> => {
    if ('bytes' in stored) return b64(stored.bytes);
    const object = await env.FILES.get(stored.r2);
    if (!object) { vanished.add(objectId); return ''; }
    return b64(new Uint8Array(await object.arrayBuffer()));
  };
  const objects = await Promise.all(fetched.objects.map(async o => ({
    objectId: o.objectId, head: o.head,
    state: o.state && { seq: o.state.seq, covers: o.state.covers, deviceId: o.state.deviceId, body: await encode(o.objectId, o.state.body) },
    updates: await Promise.all(o.updates.map(async u => ({ seq: u.seq, deviceId: u.deviceId, body: await encode(o.objectId, u.body) }))),
  })));
  const response: FetchResponse = {
    objects: objects.filter(o => !vanished.has(o.objectId)),
    more: [...objects.filter(o => vanished.has(o.objectId)).map(o => o.objectId), ...fetched.more],
  };
  return json(response);
}

/** The `/v1/bases` routes. IDs are checked before the caller, which reveals nothing. */
export async function handleBases(request: Request, env: Env, path: string): Promise<Response> {
  if (path === '/v1/bases') {
    if (request.method !== 'POST') throw new HttpError(404, 'not_found');
    return create(request, env);
  }
  const file = /^\/v1\/bases\/([^/]+)\/files\/([^/]+)\/([^/]+)$/.exec(path);
  if (file) return handleFiles(request, env, file[1], file[2], file[3]);
  const version = /^\/v1\/bases\/([^/]+)\/objects\/([^/]+)\/versions(?:\/([^/]+))?$/.exec(path);
  if (version) {
    const base = baseStub(env, version[1]);
    const objectId = id(version[2]);
    if (request.method !== 'GET') throw new HttpError(404, 'not_found');
    const principal = await requireDevice(request, env);
    if (version[3] !== undefined) {
      const seq = positiveSequence(version[3]);
      const result = await base.version(principal, objectId, seq);
      if (result.status !== 200) return answer(result);
      const { body: stored, ...metadata } = result.body as StoredVersion;
      let encoded: string;
      if ('bytes' in stored) encoded = b64(stored.bytes);
      else {
        const object = await env.FILES.get(stored.r2);
        if (!object) throw new HttpError(404, 'not_found');
        encoded = b64(new Uint8Array(await object.arrayBuffer()));
      }
      const response: VersionResponse = { ...metadata, body: encoded };
      return json(response);
    }
    const url = new URL(request.url);
    const before = url.searchParams.get('before');
    const limit = count(url.searchParams.get('limit'), VERSIONS_LIMIT_MAX);
    if (limit < 1) throw new HttpError(400, 'bad_request');
    return answer(await base.versions(principal, objectId, before === null ? null : positiveSequence(before), Math.min(limit, VERSIONS_LIMIT_MAX)));
  }
  const match = /^\/v1\/bases\/([^/]+)\/(key|changes|since|fetch|stored|live|drop-next-live|miss-next-fetch|short-next-fetch|hold-change-reply|release-change-reply|live-count|fail-next-device-close|grants\/([^/]+))$/.exec(path);
  if (!match) throw new HttpError(404, 'not_found');
  const baseId = id(match[1]);
  const action = match[3] === undefined ? match[2] : 'grants';
  const method = request.method;
  const base = baseStub(env, baseId);
  if (action === 'live' && method === 'GET') {
    const principal = await requireDevice(request, env);
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') throw new HttpError(400, 'bad_request');
    return env.BASE.get(env.BASE.idFromName(baseId)).fetch('https://base/live', { headers: {
      Upgrade: 'websocket', 'BH-Device': principal.deviceId, 'BH-Account': principal.accountId,
      'BH-Kind': principal.kind, 'BH-Status': principal.status,
    } });
  }
  if (action === 'fail-next-device-close' && method === 'POST' && testBypass(request, env)) {
    const principal = await requireDevice(request, env);
    const access = await base.key(principal);
    if (principal.kind !== 'full' || access.status !== 200) return answer({ status: 403, body: { error: 'forbidden', message: 'forbidden' } });
    await base.failNextClose();
    return json({});
  }
  if (action === 'drop-next-live' && method === 'POST' && testBypass(request, env)) {
    const principal = await requireDevice(request, env);
    await base.dropNextLive(principal.deviceId);
    return json({});
  }
  if ((action === 'miss-next-fetch' || action === 'short-next-fetch') && method === 'POST' && testBypass(request, env)) {
    const principal = await requireDevice(request, env);
    const access = await base.key(principal);
    if (access.status !== 200) return answer(access);
    if (action === 'miss-next-fetch') await base.missNextFetchBody(principal.deviceId);
    else await base.shortNextFetchBody(principal.deviceId);
    return json({});
  }
  if ((action === 'hold-change-reply' || action === 'release-change-reply') && method === 'POST' && testBypass(request, env)) {
    const principal = await requireDevice(request, env);
    const access = await base.key(principal);
    if (access.status !== 200) return answer(access);
    if (action === 'hold-change-reply') await base.holdChangeReply(principal.deviceId);
    else await base.releaseChangeReply(principal.deviceId);
    return json({});
  }
  if (action === 'live-count' && method === 'GET' && testBypass(request, env)) {
    const principal = await requireDevice(request, env);
    const access = await base.key(principal);
    return access.status === 200 ? json({ count: await base.liveCount() }) : answer(access);
  }
  if (action === 'key' && method === 'GET') return answer(await base.key(await requireDevice(request, env)));
  if (action === 'changes' && method === 'POST') return changes(request, env, baseId);
  if (action === 'fetch' && method === 'POST') return fetchObjects(request, env, baseId);
  if (action === 'since' && method === 'GET') {
    const url = new URL(request.url);
    const after = count(url.searchParams.get('after'), 0);
    const limit = count(url.searchParams.get('limit'), SINCE_LIMIT_MAX);
    if (limit < 1) throw new HttpError(400, 'bad_request');
    return answer(await base.since(await requireDevice(request, env), after, Math.min(limit, SINCE_LIMIT_MAX)));
  }
  if (action === 'grants' && (method === 'PUT' || method === 'DELETE')) {
    const deviceId = id(match[3]);
    const principal = await requireDevice(request, env);
    const account = accountStub(env, principal.accountId);
    if (method === 'DELETE') {
      // Access goes first: the base's table is what stops the app.
      const revoked = await base.revoke(principal, deviceId);
      return answer(revoked.status === 200 ? await account.ungrantApp(principal, baseId, deviceId) : revoked);
    }
    const raw = await body(request);
    if (raw.mode !== 'rw' && raw.mode !== 'ro') throw new HttpError(400, 'bad_request');
    const input = { mode: raw.mode as GrantMode, epoch: epoch(raw.epoch), wrapper: wrapper(raw.wrapper) };
    const listed = await account.grantApp(principal, baseId, deviceId);
    if (listed.status !== 200) return answer(listed);
    return answer(await base.grant(principal, deviceId, input.mode, input.epoch, input.wrapper));
  }
  if (action === 'stored' && method === 'GET' && testBypass(request, env)) {
    const objectId = id(new URL(request.url).searchParams.get('object'));
    const result = await base.stored(await requireDevice(request, env), objectId);
    if (result.status !== 200) return answer(result);
    const listed = await env.FILES.list({ prefix: `b/${baseId}/${objectId}/` });
    return json({ ...(result.body as Stored), r2: listed.objects.map(o => o.key) });
  }
  throw new HttpError(404, 'not_found');
}
