<script lang="ts">
  import type { ObjectSummary, ObjectId } from '../lib/backend/types';
  import { itemKind, type TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { item, model, depth = 0, onopen, onmenu }: { item: ObjectSummary; model: TreeModel; depth?: number; onopen: (id: ObjectId) => void; onmenu: (item: ObjectSummary) => void } = $props();
  let expanded = $derived(model.expanded[item.id]);
  let kind = $derived(itemKind(item));
</script>
<div class="tree-row" style:padding-left={`${depth * 14}px`}>
  <button class="expander" aria-label={`${expanded ? 'Collapse' : 'Expand'} ${item.title}`} onclick={() => expanded ? model.collapse(item.id) : void model.expand(item.id)}>{expanded ? '▾' : '▸'}</button>
  <span class:project={kind === 'core.project'} class="kind-square"></span>
  <button data-testid="tree-row" class="tree-title" onclick={() => onopen(item.id)}>{item.title || 'Untitled note'}</button>
  <button class="row-menu" aria-label={`More options for ${item.title}`} onclick={() => onmenu(item)}>⋯</button>
</div>
{#if expanded}
  {#each model.children[item.id] ?? [] as child (child.id)}
    <TreeRow item={child} {model} depth={depth + 1} {onopen} {onmenu} />
  {/each}
{/if}
