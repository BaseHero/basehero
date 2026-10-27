<script lang="ts">
  import type { ObjectId, ObjectSummary } from '../lib/backend/types';
  import type { TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { model, mac, onopen, onmenu, onnewwindow }: { model: TreeModel; mac: boolean; onopen: (id: ObjectId) => void; onmenu: (item: ObjectSummary) => void; onnewwindow: (id: ObjectId) => void } = $props();
</script>
<nav aria-label="Tree">
  {#each model.children[''] ?? [] as item (item.id)}
    <TreeRow {item} {model} {mac} {onopen} {onmenu} {onnewwindow} />
  {/each}
</nav>
