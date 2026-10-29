import { answer, error, id, requireDevice, testMode } from './http';
import type { Env, Principal, Result } from './http';
import { post } from './http1';
import type { Http1Response, Target } from './http1';
import type { Limits, Usage, UsageDay, DayTotals, Breakdown } from './gateway_do';

const ENCLAVE = 'https://inference.tinfoil.sh';
const TINFOIL: Target = { hostname: 'inference.tinfoil.sh', port: 443, tls: true };
const PATH = '/v1/chat/completions';
const MAX_BODY = 1024 * 1024;

type GatewayRpc = {
  reserve(limits: Limits, base: string, device: string): Promise<{ ok: true; day: string } | { ok: false; retryAfter: number }>;
  record(usage: Usage, day: string, base: string, device: string): Promise<void>;
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

/** Tinfoil, or a loopback test upstream over plain TCP when the test bypass allows it; null if misconfigured. */
function upstreamTarget(env: Env): Target | null {
  if (env.TINFOIL_CONNECT === undefined) return TINFOIL;
  if (!testMode(env)) return null;
  const match = /^(127\.0\.0\.1|\[::1\]|localhost):(\d{1,5})$/.exec(env.TINFOIL_CONNECT);
  const port = Number(match?.[2]);
  if (!match || port < 1 || port > 65535) return null;
  return { hostname: match[1] === '[::1]' ? '::1' : match[1], port, tls: false };
}

/**
 * Passes the reply's bytes to the caller unchanged, and keeps reading if the caller leaves, so
 * Tinfoil's usage still arrives. It records usage before ending the caller's body.
 */
async function pump(upstream: Http1Response, writable: WritableStream<Uint8Array>,
    record: (usage: Usage) => Promise<void>): Promise<void> {
  const writer = writable.getWriter();
  const reader = upstream.body.getReader();
  let present = true;
  let failed = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (present) await writer.write(value).catch(() => { present = false; });
    }
  } catch {
    failed = true;
  }
  const usage = parseUsage(upstream.headers.get('x-tinfoil-usage-metrics') ??
    (await upstream.trailers)?.get('x-tinfoil-usage-metrics') ?? null);
  // A call without usage is never recorded, so it stays unreported.
  if (usage) await record(usage).catch(() => {});
  await (failed ? writer.abort(new Error('Model reply ended early')) : writer.close()).catch(() => {});
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
  const asked = request.headers.get('x-tinfoil-max-output-tokens');
  if (!key || !/^[0-9a-fA-F]{64}$/.test(key) ||
      request.headers.get('x-tinfoil-enclave-url') !== ENCLAVE ||
      !model || !(env.TINFOIL_MODELS ?? '').split(',').map(s => s.trim()).includes(model) ||
      (asked !== null && !/^[1-9]\d{0,5}$/.test(asked))) {
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
  const unreportedMicroUsd = Math.round(Number(env.GATEWAY_UNREPORTED_CALL_USD) * 1e6);
  const maxOutput = Number(env.GATEWAY_MAX_OUTPUT_TOKENS);
  if (![perMinute, perDay].every(value => Number.isFinite(value) && value > 0) ||
      ![dailyCostMicroUsd, unreportedMicroUsd, maxOutput].every(value => Number.isSafeInteger(value) && value > 0)) {
    return error('bad_gateway', 502, 'Model unavailable');
  }
  const stub = gatewayStub(env, principal.accountId);
  const reserved = await stub.reserve({ perMinute, perDay, dailyCostMicroUsd, unreportedMicroUsd, monthlyCapMicroUsd: principal.capMicroUsd }, baseId, principal.deviceId);
  if (!reserved.ok) {
    const response = error('rate_limited', 429, 'Model rate limit reached');
    response.headers.set('Retry-After', String(reserved.retryAfter));
    return response;
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  // Every upstream header is fixed or validated; caller headers are never copied.
  const headers: [string, string][] = [
    ['host', 'inference.tinfoil.sh'],
    ['authorization', `Bearer ${env.TINFOIL_API_KEY}`],
    ['ehbp-encapsulated-key', key],
    ['x-tinfoil-enclave-url', ENCLAVE],
    ['x-tinfoil-model', model],
    ['x-tinfoil-request-usage-metrics', 'true'],
    ['x-tinfoil-max-output-tokens', String(Math.min(Number(asked ?? 2048), maxOutput))],
    ['content-type', 'application/json'],
    ['accept', 'text/event-stream, application/json'],
    ['accept-encoding', 'identity'],
    ['te', 'trailers'],
    ['content-length', String(size)],
    ['connection', 'close'],
  ];
  let upstream: Http1Response;
  try {
    const target = upstreamTarget(env);
    if (!target) throw new Error('No model upstream');
    upstream = await post(target, PATH, headers, body);
  } catch {
    return error('bad_gateway', 502, 'Model unavailable');
  }
  // Tinfoil answers 3xx, 401 and 403 while checking our key, before any inference, so
  // those cost nothing. Other failures can follow billed tool-loop turns and stay unreported.
  const keyRejected = (upstream.status >= 300 && upstream.status < 400) ||
    upstream.status === 401 || upstream.status === 403;
  if (keyRejected) {
    await stub.record({ prompt: 0, completion: 0, costMicroUsd: 0 }, reserved.day, baseId, principal.deviceId)
      .catch(() => {});
  }
  if (keyRejected || upstream.headers.has('content-encoding')) {
    await upstream.body.cancel();
    return error('bad_gateway', 502, 'Model unavailable');
  }
  const piped = new TransformStream<Uint8Array, Uint8Array>();
  const { day } = reserved;
  ctx.waitUntil(pump(upstream, piped.writable, usage => stub.record(usage, day, baseId, principal.deviceId)));
  const responseHeaders = new Headers({ 'BH-Protocol': '1', 'Cache-Control': 'no-store, no-transform' });
  for (const name of ['content-type', 'ehbp-response-nonce']) {
    const value = upstream.headers.get(name);
    if (value !== null) responseHeaders.set(name, value);
  }
  return new Response(piped.readable, { status: upstream.status, headers: responseHeaders });
}
