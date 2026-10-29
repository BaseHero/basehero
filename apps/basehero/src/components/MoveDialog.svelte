<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { itemKind } from '../lib/tree.svelte';
  import type { BaseRef, ObjectId, TreeItem } from '../lib/backend/types';
  let { r, item, onmove, onclose }: { r: BaseRef; item: TreeItem; onmove: (base: string, parent: ObjectId | null) => void; onclose: () => void } = $props();
  type Choice = { base: string; parent: ObjectId | null; title: string };
  let choices = $state<Choice[]>(untrack(() => [{ base: r.base, parent: null, title: 'Base root' }]));
  let selected = $state<Choice>(untrack(() => choices[0]));
  onMount(() => {
    let active = true;
    const collect = async (base: string, parent: ObjectId | null, ancestors: Set<string>) => {
      for (const child of await getBackend().treeChildren({ account: r.account, base }, parent)) {
        const key = `${child.base}:${child.id}`;
        if ((child.id === item.id && child.base === item.base) || ancestors.has(key)) continue;
        if (!['core.folder', 'core.project', 'core.note'].includes(itemKind(child))) continue;
        const next = new Set(ancestors); next.add(key);
        const destination = child.mounted ? { base: child.mounted, parent: null } : { base: child.base, parent: child.id };
        if (itemKind(child) !== 'core.note' || itemKind(item) === 'core.note') {
          if (active) choices = [...choices, { ...destination, title: child.title }];
        }
        await collect(child.base, child.id, next);
      }
    };
    void collect(r.base, null, new Set());
    return () => { active = false; };
  });
</script>
<div role="dialog" aria-label="Move to…" class="move-dialog">
  <h2>Move to…</h2>
  {#each choices as choice (`${choice.base}:${choice.parent ?? ''}`)}
    <button class:selected={selected.base === choice.base && selected.parent === choice.parent} onclick={() => selected = choice}>{choice.title}</button>
  {/each}
  <div class="actions"><button class="primary" onclick={() => onmove(selected.base, selected.parent)}>Move</button><button onclick={onclose}>Cancel</button></div>
</div>
