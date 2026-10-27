import { DurableObject } from 'cloudflare:workers';

export class DirectoryDO extends DurableObject {
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
