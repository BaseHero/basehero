<script lang="ts">
  import type { ObjectSummary, ObjectId } from '../lib/backend/types';
  import { itemKind, type TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { item, model, mac, depth = 0, onopen, onmenu, onnewwindow }: { item: ObjectSummary; model: TreeModel; mac: boolean; depth?: number; onopen: (id: ObjectId) => void; onmenu: (item: ObjectSummary) => void; onnewwindow: (id: ObjectId) => void } = $props();
  let expanded = $derived(model.expanded[item.id]);
  let kind = $derived(itemKind(item));
</script>
<div class="tree-row" style:padding-left={`${depth * 14}px`}>
  <button class="expander" aria-label={`${expanded ? 'Collapse' : 'Expand'} ${item.title}`} onclick={() => expanded ? model.collapse(item.id) : void model.expand(item.id)}>{expanded ? '▾' : '▸'}</button>
  <span class:project={kind === 'core.project'} class="kind-square"></span>
  <button data-testid="tree-row" class="tree-title" onclick={() => onopen(item.id)}>{item.title || 'Untitled note'}</button>
  {#if mac && kind === 'core.note'}<button aria-label={`Open ${item.title || 'Untitled note'} in New Window`} onclick={() => onnewwindow(item.id)}>↗</button>{/if}
  <button class="row-menu" aria-label={`More options for ${item.title}`} onclick={() => onmenu(item)}>⋯</button>
</div>
{#if expanded}
  {#each model.children[item.id] ?? [] as child (child.id)}
    <TreeRow item={child} {model} {mac} depth={depth + 1} {onopen} {onmenu} {onnewwindow} />
  {/each}
{/if}
