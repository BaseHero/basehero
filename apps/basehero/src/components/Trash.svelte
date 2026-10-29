<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import type { BaseRef, TreeItem } from '../lib/backend/types';
  let { r, onrestore, onclose }: { r: BaseRef; onrestore: (item: TreeItem) => Promise<void>; onclose: () => void } = $props();
  let items = $state<TreeItem[]>([]);
  let busy = $state<string | null>(null);
  let error = $state('');
  onMount(() => { void getBackend().trash(r).then(list => items = list).catch(cause => error = errorMessage(cause)); });
  async function restore(item: TreeItem) {
    if (busy) return;
    busy = item.id;
    error = '';
    try {
      await onrestore(item);
      items = items.filter(row => row.base !== item.base || row.id !== item.id);
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = null; }
  }
</script>
<section class="trash"><h2>Trash</h2><button onclick={onclose}>Close Trash</button>
  {#if error}<p role="alert">{error}</p>{/if}
  {#each items as item (`${item.base}:${item.id}`)}
    <div>{item.title || 'Untitled note'} <button aria-label={`Restore ${item.title}`} disabled={busy !== null} onclick={() => void restore(item)}>Restore</button></div>
  {/each}
</section>
