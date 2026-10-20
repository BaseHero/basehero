// Pairing relay: one Durable Object per pairing, named by the hash of the QR
// secret. It holds at most four opaque messages from each side (`show`, the
// device showing the QR, and `join`) for five minutes from the first message.
// It never sees the QR secret and never reads a message; the devices
// authenticate them with that secret.
import { DurableObject } from 'cloudflare:workers';

export const TTL_MS = 300_000;
export const MAX_MESSAGE = 8192;
export const MAX_PER_SIDE = 4;
const SIDES = ['show', 'join'];

const valid = (side, index) => SIDES.includes(side) && Number.isSafeInteger(index) && index >= 0;
function same(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class PairingRelay extends DurableObject {
  #now;
  constructor(ctx, env, hooks = {}) {
    super(ctx, env);
    this.#now = hooks.now ?? (() => Date.now());
  }

  // Internal RPC: store message `index` from `side`. Indices run 0-3 without
  // gaps. An exact resend is accepted again, so a lost response is safe to
  // retry; other bytes at a used index conflict.
  async put(side, index, message) {
    if (!valid(side, index) || !(message instanceof Uint8Array)) return { error: 'malformed' };
    if (index >= MAX_PER_SIDE) return { error: 'limit' };
    if (message.length === 0) return { error: 'malformed' };
    if (message.length > MAX_MESSAGE) return { error: 'size' };
    const storage = this.ctx.storage;
    const now = this.#now();
    const created = await storage.get('created');
    if (await this.#expired(created, now)) return { error: 'expired' };
    const key = `m/${side}/${index}`;
    const found = await storage.get(index > 0 ? [key, `m/${side}/${index - 1}`] : [key]);
    const existing = found.get(key);
    if (existing) return same(existing, message) ? { ok: true } : { error: 'conflict' };
    if (index > 0 && !found.has(`m/${side}/${index - 1}`)) return { error: 'conflict' };
    if (created === undefined) {
      await storage.put('created', now);
      await storage.setAlarm(now + TTL_MS);
    }
    await storage.put(key, message);
    return { ok: true };
  }

  // Internal RPC: message `index` from `side`, if it is there. Repeatable, and
  // a read of an unknown relay stores nothing.
  async get(side, index) {
    if (!valid(side, index)) return { error: 'malformed' };
    const created = await this.ctx.storage.get('created');
    if (created === undefined) return { none: true };
    if (await this.#expired(created, this.#now())) return { error: 'expired' };
    const message = await this.ctx.storage.get(`m/${side}/${index}`);
    return message ? { message } : { none: true };
  }

  async alarm() {
    const created = await this.ctx.storage.get('created');
    if (created === undefined) return;
    if (!await this.#expired(created, this.#now())) await this.ctx.storage.setAlarm(created + TTL_MS);
  }

  // An expired relay is deleted outright. A later message under the same name
  // starts a fresh relay; the devices bound a pairing's lifetime themselves.
  async #expired(created, now) {
    if (created === undefined || now - created < TTL_MS) return false;
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    return true;
  }
}
