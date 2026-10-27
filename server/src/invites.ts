import { DurableObject } from 'cloudflare:workers';
import { randomBytes } from './http';
import type { Env } from './http';

const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export class InvitesDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, used_by TEXT, created_at INTEGER NOT NULL)');
  }
  issue(): string {
    let code: string;
    do { code = Array.from(randomBytes(10), b => alphabet[b & 31]).join(''); }
    while (this.ctx.storage.sql.exec('SELECT code FROM invites WHERE code = ?', code).toArray().length !== 0);
    this.ctx.storage.sql.exec('INSERT INTO invites (code, created_at) VALUES (?, ?)', code, Date.now());
    return code;
  }
  valid(code: string): boolean {
    const row = this.ctx.storage.sql.exec<{ used_by: string | null }>('SELECT used_by FROM invites WHERE code = ?', code).toArray()[0];
    return row !== undefined && row.used_by === null;
  }
  consume(code: string, accountId: string): boolean {
    const result = this.ctx.storage.sql.exec('UPDATE invites SET used_by = ? WHERE code = ? AND used_by IS NULL', accountId, code);
    return result.rowsWritten === 1;
  }
}
