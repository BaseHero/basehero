<script lang="ts">
  import type { ObjectId, ObjectSummary } from '../lib/backend/types';
  import type { TreeModel } from '../lib/tree.svelte';
  import TreeRow from './TreeRow.svelte';
  let { model, onopen, onmenu }: { model: TreeModel; onopen: (id: ObjectId) => void; onmenu: (item: ObjectSummary) => void } = $props();
</script>
<nav aria-label="Tree">
  {#each model.children[''] ?? [] as item (item.id)}
    <TreeRow {item} {model} {onopen} {onmenu} />
  {/each}
</nav>
