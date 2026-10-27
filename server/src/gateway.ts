import { answer, error, id, requireDevice } from './http';
import type { Env, Principal, Result } from './http';
import type { Limits, Usage, UsageDay, DayTotals, Breakdown } from './gateway_do';

const UPSTREAM = 'https://inference.tinfoil.sh/v1/chat/completions';
const ENCLAVE = 'https://inference.tinfoil.sh';
const MAX_BODY = 1024 * 1024;

type GatewayRpc = {
  reserve(limits: Limits, base: string, device: string): Promise<{ ok: true } | { ok: false; retryAfter: number }>;
  record(usage: Usage | null, base: string, device: string): Promise<void>;
  usage(): Promise<UsageDay[]>;
  report(): Promise<{ days: DayTotals[]; breakdown: Breakdown[] }>;
  seedLegacyDay(): Promise<void>;
};
export function gatewayStub(env: Env, accountId: string): GatewayRpc {
  return env.GATEWAY.get(env.GATEWAY.idFromName(`gw:${accountId}`)) as unknown as GatewayRpc;
}

// Never parse the ciphertext. Only accept the reported accounting fields; malformed metrics are missing.
function parseUsage(value: string | null): Usage | null {
  if (value === null) return null;
  const parts = value.split(',').map(part => part.trim().split('='));
  if (parts.some(part => part.length !== 2)) return null;
  const fields = new Map(parts.map(([key, val]): [string, string] => [key, val]));
  if (fields.size !== parts.length) return null;
  const prompt = fields.get('prompt');
  const completion = fields.get('completion');
  const cost = fields.get('cost_usd');
  if (!prompt || !completion || !cost || !/^(0|[1-9]\d*)$/.test(prompt) ||
      !/^(0|[1-9]\d*)$/.test(completion) || !/^(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?$/.test(cost)) return null;
  const p = Number(prompt), c = Number(completion), micro = Math.round(Number(cost) * 1e6);
  if (![p, c, micro].every(Number.isSafeInteger)) return null;
  return { prompt: p, completion: c, costMicroUsd: micro };
}

export async function handleModels(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const principal = await requireDevice(request, env);
  const named = request.headers.get('BH-Base');
  const baseId = named === null ? '' : id(named);
  if (baseId) {
    const base = env.BASE.get(env.BASE.idFromName(baseId)) as unknown as { fileAccess(p: Principal, write: boolean): Promise<Result> };
    const access = await base.fileAccess(principal, false);
    if (access.status !== 200) return answer(access);
  }
  const key = request.headers.get('ehbp-encapsulated-key');
  const model = request.headers.get('x-tinfoil-model');
  if (!key || !/^[0-9a-fA-F]{64}$/.test(key) ||
      request.headers.get('x-tinfoil-enclave-url') !== ENCLAVE ||
      !model || !(env.TINFOIL_MODELS ?? '').split(',').map(s => s.trim()).includes(model)) {
    return error('bad_request', 400, 'Invalid model request');
  }
  // Bound the actual streamed bytes, not the untrusted Content-Length.
  const chunks: Uint8Array[] = [];
  const reader = request.body?.getReader();
  let size = 0;
  if (reader) {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_BODY) {
          await reader.cancel();
          return error('too_large', 413, 'Model request too large');
        }
        chunks.push(value);
      }
    } catch {
      return error('bad_request', 400, 'Invalid model request');
    } finally {
      reader.releaseLock();
    }
  }
  if (size === 0) return error('bad_request', 400, 'Empty model request');
  if (!env.TINFOIL_API_KEY) return error('bad_gateway', 502, 'Model unavailable');
  const perMinute = Number(env.GATEWAY_PER_MINUTE);
  const perDay = Number(env.GATEWAY_PER_DAY);
  const dailyCostMicroUsd = Math.round(Number(env.GATEWAY_DAILY_COST_USD) * 1e6);
  if (![perMinute, perDay].every(value => Number.isFinite(value) && value > 0) ||
      !Number.isSafeInteger(dailyCostMicroUsd) || dailyCostMicroUsd <= 0) {
    return error('bad_gateway', 502, 'Model unavailable');
  }
  const stub = gatewayStub(env, principal.accountId);
  const reserved = await stub.reserve({ perMinute, perDay, dailyCostMicroUsd }, baseId, principal.deviceId);
  if (!reserved.ok) {
    const response = error('rate_limited', 429, 'Model rate limit reached');
    response.headers.set('Retry-After', String(reserved.retryAfter));
    return response;
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  // Construct an allowlist, never clone caller headers or interpret ciphertext.
  const headers = new Headers({
    authorization: `Bearer ${env.TINFOIL_API_KEY}`,
    'ehbp-encapsulated-key': key,
    'x-tinfoil-enclave-url': ENCLAVE,
    'x-tinfoil-model': model,
    'x-tinfoil-request-usage-metrics': 'true',
    'accept-encoding': 'identity',
  });
  for (const name of ['content-type', 'accept']) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  try {
    const upstream = await fetch(UPSTREAM, { method: 'POST', headers, body, redirect: 'manual' });
    if ((upstream.status >= 300 && upstream.status < 400) ||
        upstream.status === 401 || upstream.status === 403 || upstream.headers.has('content-encoding')) {
      await upstream.body?.cancel();
      return error('bad_gateway', 502, 'Model unavailable');
    }
    ctx.waitUntil(stub.record(parseUsage(upstream.headers.get('x-tinfoil-usage-metrics')), baseId, principal.deviceId));
    const responseHeaders = new Headers({ 'BH-Protocol': '1' });
    for (const name of ['content-type', 'ehbp-response-nonce']) {
      const value = upstream.headers.get(name);
      if (value !== null) responseHeaders.set(name, value);
    }
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return error('bad_gateway', 502, 'Model unavailable');
  }
}
