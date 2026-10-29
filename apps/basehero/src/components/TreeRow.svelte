<script lang="ts">
  import type { TreeItem } from '../lib/backend/types';
  import { itemKind, treeKey, type TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { item, model, mac, depth = 0, onopen, onmenu, onnewwindow }: { item: TreeItem; model: TreeModel; mac: boolean; depth?: number; onopen: (item: TreeItem) => void; onmenu: (item: TreeItem) => void; onnewwindow: (item: TreeItem) => void } = $props();
  let expanded = $derived(model.expanded[treeKey(item.base, item.id)]);
  let kind = $derived(itemKind(item));
</script>
<div class="tree-row" style:padding-left={`${depth * 14}px`}>
  <button class="expander" aria-label={`${expanded ? 'Collapse' : 'Expand'} ${item.title}`} onclick={() => expanded ? model.collapse(item.base, item.id) : void model.expand(item.base, item.id)}>{expanded ? '▾' : '▸'}</button>
  <span class:project={kind === 'core.project'} class="kind-square"></span>
  <div class="tree-label">
    <button data-testid="tree-row" class="tree-title" onclick={() => onopen(item)}>{item.title || 'Untitled note'}</button>
    {#if item.mounted && item.readers.length}<small>Shared with {item.readers.join(', ')}</small>{/if}
  </div>
  {#if mac && kind === 'core.note'}<button aria-label={`Open ${item.title || 'Untitled note'} in New Window`} onclick={() => onnewwindow(item)}>↗</button>{/if}
  <button class="row-menu" aria-label={`More options for ${item.title}`} onclick={() => onmenu(item)}>⋯</button>
</div>
{#if expanded}
  {#each model.children[treeKey(item.base, item.id)] ?? [] as child (`${child.base}:${child.id}`)}
    <TreeRow item={child} {model} {mac} depth={depth + 1} {onopen} {onmenu} {onnewwindow} />
  {/each}
{/if}
<style>
  .tree-label { flex: 1; min-width: 0; }
  .tree-label .tree-title { width: 100%; }
  .tree-label small { display: block; padding-left: .3rem; font-size: .65rem; color: var(--muted); }
</style>
