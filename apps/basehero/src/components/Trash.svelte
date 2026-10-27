<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import type { BaseRef, ObjectId, ObjectSummary } from '../lib/backend/types';
  let { r, onrestore, onclose }: { r: BaseRef; onrestore: (id: ObjectId) => Promise<void>; onclose: () => void } = $props();
  let items = $state<ObjectSummary[]>([]);
  let busy = $state<string | null>(null);
  let error = $state('');
  onMount(() => { void getBackend().trash(r).then(list => items = list).catch(cause => error = errorMessage(cause)); });
  async function restore(id: ObjectId) {
    if (busy) return;
    busy = id;
    error = '';
    try {
      await onrestore(id);
      items = items.filter(item => item.id !== id);
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = null; }
  }
</script>
<section class="trash"><h2>Trash</h2><button onclick={onclose}>Close Trash</button>
  {#if error}<p role="alert">{error}</p>{/if}
  {#each items as item (item.id)}
    <div>{item.title || 'Untitled note'} <button aria-label={`Restore ${item.title}`} disabled={busy !== null} onclick={() => void restore(item.id)}>Restore</button></div>
  {/each}
</section>
