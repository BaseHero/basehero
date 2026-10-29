import { getBackend } from './backend';
import type { BaseRef, ObjectId, ObjectSummary, TreeItem } from './backend/types';

const navigable = new Set(['core.note', 'core.folder', 'core.project']);
export function itemKind(item: ObjectSummary): string {
  const ty = item.ty as { name?: string } | undefined;
  const kind = ty?.name ?? String(item.kind ?? '');
  return kind.startsWith('core.') ? kind : `core.${kind}`;
}
export const treeKey = (base: string, parent: ObjectId | null) => `${base}:${parent ?? ''}`;

export class TreeModel {
  children = $state<Record<string, TreeItem[]>>({});
  expanded = $state<Record<string, boolean>>({});
  constructor(readonly r: BaseRef) {}
  async expand(base: string, id: ObjectId | null) {
    if (id !== null) this.expanded[treeKey(base, id)] = true;
    if (!(treeKey(base, id) in this.children)) await this.load(base, id);
  }
  collapse(base: string, id: ObjectId) { this.expanded[treeKey(base, id)] = false; }
  private async load(base: string, parent: ObjectId | null) {
    this.children[treeKey(base, parent)] = (await getBackend().treeChildren({ account: this.r.account, base }, parent))
      .filter(item => !item.deleted && navigable.has(itemKind(item)));
  }
  async refresh() {
    await Promise.all(Object.keys(this.children).map(key => {
      const split = key.indexOf(':');
      return this.load(key.slice(0, split), key.slice(split + 1) || null);
    }));
  }
  async reveal(base: string, id: ObjectId, mounts: { base: string; parent: string; folder: string }[]) {
    const seen = new Set<string>();
    let current = id;
    while (!seen.has(`${base}:${current}`)) {
      seen.add(`${base}:${current}`);
      const item = await getBackend().getObject({ account: this.r.account, base }, current);
      if (!item?.parent) break;
      await this.expand(base, item.parent);
      current = item.parent;
    }
    while (base !== this.r.base) {
      const mount = mounts.find(row => row.base === base);
      if (!mount || seen.has(`mount:${base}`)) break;
      seen.add(`mount:${base}`);
      base = mount.parent;
      await this.expand(base, mount.folder);
      current = mount.folder;
      while (true) {
        const item = await getBackend().getObject({ account: this.r.account, base }, current);
        if (!item?.parent || seen.has(`${base}:${item.parent}`)) break;
        seen.add(`${base}:${item.parent}`);
        await this.expand(base, item.parent);
        current = item.parent;
      }
    }
  }
}
