<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { itemKind } from '../lib/tree.svelte';
  import type { BaseRef, ObjectId, ObjectSummary } from '../lib/backend/types';
  let { r, item, onmove, onclose }: { r: BaseRef; item: ObjectSummary; onmove: (parent: ObjectId | null) => void; onclose: () => void } = $props();
  let choices = $state<{ id: ObjectId | null; title: string }[]>([{ id: null, title: 'Base root' }]);
  let selected = $state<ObjectId | null>(null);
  onMount(() => {
    let active = true;
    const collect = async (parent: ObjectId | null, ancestors: Set<string>) => {
      for (const child of await getBackend().children(r, parent)) {
        if (child.id === item.id || ancestors.has(child.id)) continue;
        if (itemKind(child) !== 'core.folder' && itemKind(child) !== 'core.project' && itemKind(child) !== 'core.note') continue;
        // Avoid offering any item in the moved subtree as a destination.
        const next = new Set(ancestors); next.add(child.id);
        if (itemKind(child) !== 'core.note' || itemKind(item) === 'core.note') {
          if (active) choices = [...choices, { id: child.id, title: child.title }];
        }
        await collect(child.id, next);
      }
    };
    void collect(null, new Set());
    return () => { active = false; };
  });
</script>
<div role="dialog" aria-label="Move to…" class="move-dialog">
  <h2>Move to…</h2>
  {#each choices as choice (choice.id)}
    <button class:selected={selected === choice.id} onclick={() => selected = choice.id}>{choice.title}</button>
  {/each}
  <div class="actions"><button class="primary" onclick={() => onmove(selected)}>Move</button><button onclick={onclose}>Cancel</button></div>
</div>
