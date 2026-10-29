import type { Env, Principal, Result } from './http';
import { accountStub, answer, HttpError, id, json, limitedBytes, requireDevice } from './http';

const FILE_PART_SEALED_MAX = 4_194_304 + 45;
type BaseRpc = { fileAccess(p: Principal, write: boolean): Promise<Result> };

/** Upload or download one opaque, write-once sealed file part without passing it through the DO. */
export async function handleFiles(request: Request, env: Env, baseId: string, objectId: string, part: string): Promise<Response> {
  baseId = id(baseId);
  objectId = id(objectId);
  if (!/^(0|[1-9]\d*)$/.test(part)) throw new HttpError(400, 'bad_request');
  const number = Number(part);
  if (number > 24) throw new HttpError(413, 'too_large');
  if (request.method !== 'PUT' && request.method !== 'GET') throw new HttpError(404, 'not_found');
  // An upload counts against the device's change rate, like a change.
  const principal = await requireDevice(request, env, request.method === 'PUT');
  const base = env.BASE.get(env.BASE.idFromName(baseId)) as unknown as BaseRpc;
  const access = await base.fileAccess(principal, request.method === 'PUT');
  if (access.status !== 200) return answer(access);
  const key = `f/${baseId}/${objectId}/${part}`;
  if (request.method === 'GET') {
    const stored = await env.FILES.get(key);
    if (!stored) throw new HttpError(404, 'not_found');
    return new Response(stored.body, { headers: { 'Content-Type': 'application/octet-stream', 'BH-Protocol': '1' } });
  }
  if (request.headers.get('Content-Type') !== 'application/octet-stream') throw new HttpError(400, 'bad_request');
  const length = request.headers.get('Content-Length');
  if (length === null || !/^(0|[1-9]\d*)$/.test(length)) throw new HttpError(400, 'bad_request');
  if (Number(length) > FILE_PART_SEALED_MAX) throw new HttpError(413, 'too_large');
  const bytes = await limitedBytes(request, FILE_PART_SEALED_MAX);
  if (bytes.byteLength !== Number(length)) throw new HttpError(400, 'bad_request');
  if (!await accountStub(env, principal.accountId).reserveStorage(bytes.byteLength)) {
    throw new HttpError(413, 'storage_limit');
  }
  const written = await env.FILES.put(key, bytes, { onlyIf: { etagDoesNotMatch: '*' } });
  if (!written) {
    // A retry of the same bytes succeeds, so a client whose reply was lost can
    // tell; different bytes never replace a part.
    const existing = await env.FILES.get(key);
    const stored = existing && new Uint8Array(await existing.arrayBuffer());
    const sent = bytes;
    if (!stored || stored.length !== sent.length || stored.some((b, i) => b !== sent[i])) {
      throw new HttpError(409, 'exists');
    }
  }
  // Parts count against the change rate. Parts are never deleted, so deleting
  // a file does not free its storage.
  return json({});
}
