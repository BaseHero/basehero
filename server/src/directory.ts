import { DurableObject } from 'cloudflare:workers';
import { Approvals } from './approvals';
import { fail, type Env, type Result } from './http';
import type { ApprovalEndReason } from './proto/gen/ApprovalEndReason';

export class DirectoryDO extends DurableObject<Env> {
  private approvals?: Approvals;
  private relay(): Approvals { return this.approvals ??= new Approvals(this.ctx, this.env); }
  private existing(): Approvals | null {
    const table = this.ctx.storage.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'approvals'").toArray()[0];
    return table ? this.relay() : null;
  }
  connectCreate(approvalId: string, deviceId: string, secretHash: string, request: string): Promise<Result> { return this.relay().createApp(approvalId, deviceId, secretHash, request); }
  connectState(approvalId: string, secretHash: string): Result { return this.existing()?.appState(approvalId, secretHash) ?? fail(404, 'not_found'); }
  connectReveal(approvalId: string, secretHash: string, reveal: string): Result { return this.existing()?.appReveal(approvalId, secretHash, reveal) ?? fail(404, 'not_found'); }
  connectEnd(approvalId: string, secretHash: string, reason: ApprovalEndReason): Result { return this.existing()?.appEnd(approvalId, secretHash, reason) ?? fail(404, 'not_found'); }
  async alarm(): Promise<void> { await this.existing()?.prune(); }
  async lookup(): Promise<string | null> {
    return await this.ctx.storage.get<string>('accountId') ?? null;
  }
  async claim(accountId: string): Promise<boolean> {
    return this.ctx.storage.transaction(async tx => {
      if (await tx.get('accountId')) return false;
      await tx.put('accountId', accountId);
      return true;
    });
  }
  async release(accountId: string): Promise<void> {
    await this.ctx.storage.transaction(async tx => {
      if (await tx.get('accountId') === accountId) await tx.delete('accountId');
    });
  }
}
