import { DurableObject } from 'cloudflare:workers';
import type { Env } from './http';

export type UsageDay = { day: string; requests: number; prompt: number; completion: number; costUsd: number; missing: number };
export type DayTotals = { day: string; requests: number; prompt: number; completion: number; costMicroUsd: number; missing: number };
export type Breakdown = { day: string; base: string; device: string; service: string; requests: number; prompt: number; completion: number; costMicroUsd: number; missing: number };
export type Usage = { prompt: number; completion: number; costMicroUsd: number };
/** Until its usage arrives, each call counts at unreportedMicroUsd against the daily cost cap. */
export type Limits = { perMinute: number; perDay: number; dailyCostMicroUsd: number; unreportedMicroUsd: number; monthlyCapMicroUsd?: number };

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
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS usage (day TEXT NOT NULL, base TEXT NOT NULL, device TEXT NOT NULL, service TEXT NOT NULL, requests INTEGER NOT NULL, prompt INTEGER NOT NULL, completion INTEGER NOT NULL, cost_micro_usd INTEGER NOT NULL, missing INTEGER NOT NULL, PRIMARY KEY(day, base, device, service))');
  }
  /** Counts the call, as unreported until record() settles it. */
  reserve(limits: Limits, base: string, device: string): { ok: true; day: string } | { ok: false; retryAfter: number } {
    const now = gatewayNow(this.env);
    const start = Math.floor(now / 60000) * 60000;
    const today = day(now);
    const minute = this.ctx.storage.sql.exec<{ count: number }>('SELECT count FROM minute WHERE start = ?', start).toArray()[0]?.count ?? 0;
    const daily = this.ctx.storage.sql.exec<{ requests: number; cost_micro_usd: number; missing: number }>('SELECT requests, cost_micro_usd, missing FROM days WHERE day = ?', today).toArray()[0];
    if (minute >= limits.perMinute) return { ok: false, retryAfter: Math.ceil((start + 60000 - now) / 1000) };
    const cost = (daily?.cost_micro_usd ?? 0) + (daily?.missing ?? 0) * limits.unreportedMicroUsd;
    if ((daily?.requests ?? 0) >= limits.perDay || cost >= limits.dailyCostMicroUsd) {
      const tomorrow = Date.parse(`${today}T00:00:00Z`) + 86400000;
      return { ok: false, retryAfter: Math.ceil((tomorrow - now) / 1000) };
    }
    if (limits.monthlyCapMicroUsd !== undefined) {
      const month = today.slice(0, 7);
      const usage = this.ctx.storage.sql.exec<{ cost: number }>(
        'SELECT COALESCE(SUM(cost_micro_usd + missing * ?), 0) AS cost FROM usage WHERE device = ? AND day >= ?',
        limits.unreportedMicroUsd, device, `${month}-01`).toArray()[0]?.cost ?? 0;
      if (usage >= limits.monthlyCapMicroUsd) {
        const nextMonth = Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)), 1);
        return { ok: false, retryAfter: Math.ceil((nextMonth - now) / 1000) };
      }
    }
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec('DELETE FROM minute WHERE start != ?', start);
      this.ctx.storage.sql.exec('UPDATE minute SET count = count + 1 WHERE start = ?', start);
      if (!minute) this.ctx.storage.sql.exec('INSERT INTO minute (start, count) VALUES (?, 1)', start);
      this.ctx.storage.sql.exec('INSERT INTO days (day, requests, prompt, completion, cost_micro_usd, missing) VALUES (?, 1, 0, 0, 0, 1) ON CONFLICT(day) DO UPDATE SET requests = requests + 1, missing = missing + 1', today);
      this.ctx.storage.sql.exec('INSERT INTO usage (day, base, device, service, requests, prompt, completion, cost_micro_usd, missing) VALUES (?, ?, ?, ?, 1, 0, 0, 0, 1) ON CONFLICT(day, base, device, service) DO UPDATE SET requests = requests + 1, missing = missing + 1', today, base, device, 'model');
    });
    return { ok: true, day: today };
  }
  /** Adds reported usage to the day its call was reserved, and settles that call. */
  record(u: Usage, day: string, base: string, device: string): void {
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec('UPDATE days SET prompt = prompt + ?, completion = completion + ?, cost_micro_usd = cost_micro_usd + ?, missing = max(missing - 1, 0) WHERE day = ?',
        u.prompt, u.completion, u.costMicroUsd, day);
      this.ctx.storage.sql.exec('UPDATE usage SET prompt = prompt + ?, completion = completion + ?, cost_micro_usd = cost_micro_usd + ?, missing = max(missing - 1, 0) WHERE day = ? AND base = ? AND device = ? AND service = ?',
        u.prompt, u.completion, u.costMicroUsd, day, base, device, 'model');
    });
  }
  usage(): UsageDay[] {
    return this.days().map(row => ({ day: row.day, requests: row.requests, prompt: row.prompt,
      completion: row.completion, costUsd: row.costMicroUsd / 1e6, missing: row.missing }));
  }
  days(): DayTotals[] {
    return this.ctx.storage.sql.exec<{ day: string; requests: number; prompt: number; completion: number; cost_micro_usd: number; missing: number }>(
      'SELECT day, requests, prompt, completion, cost_micro_usd, missing FROM days ORDER BY day DESC').toArray()
      .map(row => ({ day: row.day, requests: row.requests, prompt: row.prompt, completion: row.completion, costMicroUsd: row.cost_micro_usd, missing: row.missing }));
  }
  /** One synchronous snapshot, so reservations cannot appear in only one table. */
  report(): { days: DayTotals[]; breakdown: Breakdown[] } {
    return { days: this.days(), breakdown: this.breakdown() };
  }
  /** Test-only simulation of a pre-breakdown day. */
  seedLegacyDay(): void {
    if (this.env.ALLOW_TEST_BYPASS !== '1') throw new Error('unavailable');
    this.ctx.storage.sql.exec('INSERT INTO days (day, requests, prompt, completion, cost_micro_usd, missing) VALUES (?, 2, 10, 5, 101, 1)', day(gatewayNow(this.env)));
  }
  breakdown(): Breakdown[] {
    return this.ctx.storage.sql.exec<{ day: string; base: string; device: string; service: string; requests: number; prompt: number; completion: number; cost_micro_usd: number; missing: number }>(
      'SELECT day, base, device, service, requests, prompt, completion, cost_micro_usd, missing FROM usage ORDER BY day DESC').toArray()
      .map(row => ({ day: row.day, base: row.base, device: row.device, service: row.service, requests: row.requests, prompt: row.prompt, completion: row.completion, costMicroUsd: row.cost_micro_usd, missing: row.missing }));
  }
}
