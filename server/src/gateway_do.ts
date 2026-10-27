import { DurableObject } from 'cloudflare:workers';
import type { Env } from './http';

export type UsageDay = { day: string; requests: number; prompt: number; completion: number; costUsd: number; missing: number };
export type Usage = { prompt: number; completion: number; costMicroUsd: number };
export type Limits = { perMinute: number; perDay: number; dailyCostMicroUsd: number };

function day(now: number): string { return new Date(now).toISOString().slice(0, 10); }
function gatewayNow(env: Env): number {
  return env.ALLOW_TEST_BYPASS === '1' && env.GATEWAY_NOW_MS !== undefined
    ? Number(env.GATEWAY_NOW_MS) : Date.now();
}

export class GatewayDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS minute (start INTEGER, count INTEGER)');
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS days (day TEXT PRIMARY KEY, requests INTEGER NOT NULL, prompt INTEGER NOT NULL, completion INTEGER NOT NULL, cost_micro_usd INTEGER NOT NULL, missing INTEGER NOT NULL)');
  }
  reserve(limits: Limits): { ok: true } | { ok: false; retryAfter: number } {
    const now = gatewayNow(this.env);
    const start = Math.floor(now / 60000) * 60000;
    const today = day(now);
    const minute = this.ctx.storage.sql.exec<{ count: number }>('SELECT count FROM minute WHERE start = ?', start).toArray()[0]?.count ?? 0;
    const daily = this.ctx.storage.sql.exec<{ requests: number; cost_micro_usd: number }>('SELECT requests, cost_micro_usd FROM days WHERE day = ?', today).toArray()[0];
    if (minute >= limits.perMinute) return { ok: false, retryAfter: Math.ceil((start + 60000 - now) / 1000) };
    if ((daily?.requests ?? 0) >= limits.perDay || (daily?.cost_micro_usd ?? 0) >= limits.dailyCostMicroUsd) {
      const tomorrow = Date.parse(`${today}T00:00:00Z`) + 86400000;
      return { ok: false, retryAfter: Math.ceil((tomorrow - now) / 1000) };
    }
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec('DELETE FROM minute WHERE start != ?', start);
      this.ctx.storage.sql.exec('UPDATE minute SET count = count + 1 WHERE start = ?', start);
      if (!minute) this.ctx.storage.sql.exec('INSERT INTO minute (start, count) VALUES (?, 1)', start);
      this.ctx.storage.sql.exec('INSERT INTO days (day, requests, prompt, completion, cost_micro_usd, missing) VALUES (?, 1, 0, 0, 0, 0) ON CONFLICT(day) DO UPDATE SET requests = requests + 1', today);
    });
    return { ok: true };
  }
  record(u: Usage | null): void {
    const now = gatewayNow(this.env);
    const today = day(now);
    this.ctx.storage.sql.exec('INSERT INTO days (day, requests, prompt, completion, cost_micro_usd, missing) VALUES (?, 0, ?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET prompt = prompt + excluded.prompt, completion = completion + excluded.completion, cost_micro_usd = cost_micro_usd + excluded.cost_micro_usd, missing = missing + excluded.missing',
      today, u?.prompt ?? 0, u?.completion ?? 0, u?.costMicroUsd ?? 0, u ? 0 : 1);
  }
  usage(): UsageDay[] {
    return this.ctx.storage.sql.exec<{ day: string; requests: number; prompt: number; completion: number; cost_micro_usd: number; missing: number }>(
      'SELECT day, requests, prompt, completion, cost_micro_usd, missing FROM days ORDER BY day DESC').toArray()
      .map(row => ({ day: row.day, requests: row.requests, prompt: row.prompt, completion: row.completion, costUsd: row.cost_micro_usd / 1e6, missing: row.missing }));
  }
}
