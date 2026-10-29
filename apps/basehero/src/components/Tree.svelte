<script lang="ts">
  import type { ObjectId, TreeItem } from '../lib/backend/types';
  import { treeKey, type TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { model, mac, onopen, onmenu, onnewwindow }: { model: TreeModel; mac: boolean; onopen: (item: TreeItem) => void; onmenu: (item: TreeItem) => void; onnewwindow: (item: TreeItem) => void } = $props();
</script>
<nav aria-label="Tree">
  {#each model.children[treeKey(model.r.base, null)] ?? [] as item (`${item.base}:${item.id}`)}
    <TreeRow {item} {model} {mac} {onopen} {onmenu} {onnewwindow} />
  {/each}
</nav>
