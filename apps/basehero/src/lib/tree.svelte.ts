import { getBackend } from './backend';
import type { BaseRef, ObjectId, ObjectSummary } from './backend/types';

const navigable = new Set(['core.note', 'core.folder', 'core.project']);
export function itemKind(item: ObjectSummary): string {
  const ty = item.ty as { name?: string } | undefined;
  const kind = ty?.name ?? String(item.kind ?? '');
  return kind.startsWith('core.') ? kind : `core.${kind}`;
}
const key = (parent: ObjectId | null) => parent ?? '';

export class TreeModel {
  children = $state<Record<string, ObjectSummary[]>>({});
  expanded = $state<Record<string, boolean>>({});
  constructor(readonly r: BaseRef) {}
  async expand(id: ObjectId | null) {
    if (id !== null) this.expanded[id] = true;
    const parent = key(id);
    if (!(parent in this.children)) await this.load(id);
  }
  collapse(id: ObjectId) { this.expanded[id] = false; }
  private async load(parent: ObjectId | null) {
    this.children[key(parent)] = (await getBackend().children(this.r, parent)).filter(item => !item.deleted && navigable.has(itemKind(item)));
  }
  async refresh(ids: ObjectId[]) {
    const parents = new Set<string>();
    for (const id of ids) {
      for (const [parent, items] of Object.entries(this.children)) {
        if (items.some(item => item.id === id)) parents.add(parent);
      }
      const item = await getBackend().getObject(this.r, id);
      if (item) parents.add(key(item.parent));
    }
    await Promise.all([...parents].filter(parent => parent in this.children).map(parent => this.load(parent || null)));
  }
}
