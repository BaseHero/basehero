import type { UsageResponse } from './proto/gen/UsageResponse';
import type { UsageRow } from './proto/gen/UsageRow';
import type { DayTotals, Breakdown } from './gateway_do';

/** Percentage added to cost for the account's displayed price. */
export const PRICE_MARKUP_PERCENT = 50;
// Cloudflare list prices, checked 2026-10-27:
// https://developers.cloudflare.com/durable-objects/platform/pricing/ (SQLite SQL stored data)
// https://developers.cloudflare.com/r2/pricing/ (R2 Standard storage).
// Marginal rates omit free allowances, which are shared across the Cloudflare account.
export const DO_SQL_GB_MONTH_USD = 0.20;
export const R2_STANDARD_GB_MONTH_USD = 0.015;

/** One month at today's stored size, using decimal GB and rounded micro-dollars. */
export function storageRow(base: string, bytes: { sqlite: number; r2: number }, period: string): UsageRow {
  const cost = Math.round((bytes.sqlite * DO_SQL_GB_MONTH_USD + bytes.r2 * R2_STANDARD_GB_MONTH_USD) / 1000);
  return { period, service: 'storage', base, device: null, requests: 0, unreported: 0,
    promptTokens: 0, completionTokens: 0, storedBytes: bytes.sqlite + bytes.r2,
    costMicroUsd: cost, priceMicroUsd: price(cost) };
}

export function monthQuery(value: string | null, now: number): string | null {
  if (value === null) return new Date(now).toISOString().slice(0, 7);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(value)) return null;
  return value;
}

function price(cost: number): number {
  return Math.round(cost * (100 + PRICE_MARKUP_PERCENT) / 100);
}

export function accountUsage(days: DayTotals[], breakdown: Breakdown[], month: string): UsageResponse {
  const rows: UsageRow[] = breakdown.map(row => ({
    period: row.day, service: row.service, base: row.base || null, device: row.device || null,
    requests: row.requests, unreported: row.missing, promptTokens: row.prompt,
    completionTokens: row.completion, storedBytes: 0, costMicroUsd: row.costMicroUsd, priceMicroUsd: price(row.costMicroUsd),
  }));
  // days remains the source of truth for the limits and older totals. Only the
  // difference has no attribution; never add all of days to the breakdown.
  for (const day of days) {
    const known = breakdown.filter(row => row.day === day.day);
    const sum = (field: keyof Breakdown) => known.reduce((n, row) => n + Number(row[field]), 0);
    const requests = day.requests - sum('requests');
    if (requests > 0) rows.push({
      period: day.day, service: 'model', base: null, device: null,
      requests, unreported: Math.max(0, day.missing - sum('missing')),
      promptTokens: Math.max(0, day.prompt - sum('prompt')),
      completionTokens: Math.max(0, day.completion - sum('completion')),
      costMicroUsd: Math.max(0, day.costMicroUsd - sum('costMicroUsd')),
      priceMicroUsd: 0, storedBytes: 0,
    });
  }
  for (const row of rows) row.priceMicroUsd = price(row.costMicroUsd);
  const months = new Map<string, UsageRow>();
  for (const row of rows) {
    const period = row.period.slice(0, 7);
    const key = JSON.stringify([period, row.service, row.base, row.device]);
    const aggregate = months.get(key);
    if (aggregate) {
      aggregate.requests += row.requests; aggregate.unreported += row.unreported;
      aggregate.promptTokens += row.promptTokens; aggregate.completionTokens += row.completionTokens;
      aggregate.costMicroUsd += row.costMicroUsd;
      aggregate.priceMicroUsd = price(aggregate.costMicroUsd);
    } else months.set(key, { ...row, period });
  }
  return {
    months: [...months.values()].sort((a, b) => b.period.localeCompare(a.period) || a.service.localeCompare(b.service)),
    days: rows.filter(row => row.period.startsWith(month)).sort((a, b) => b.period.localeCompare(a.period) || a.service.localeCompare(b.service)),
  };
}
