<script lang="ts">
  import type { SyncStatus } from '../lib/sync.svelte';
  import { getBackend } from '../lib/backend';
  let { sync, mac }: { sync: SyncStatus; mac: boolean } = $props();
  let expanded = $state(false);
  function time(timestamp: number): string {
    const date = new Date(timestamp);
    return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
  }
</script>

<div class="sync-container">
  <button class="sync-dot" class:offline={sync.state?.online === false} type="button" aria-label="Sync status" aria-expanded={expanded} onclick={() => expanded = !expanded}>●</button>
  <div class:expanded class="sync-text" role="status" aria-live="polite">
    {#if sync.state}
      <span>{sync.state.online ? 'ONLINE' : 'OFFLINE'}</span>
      {#if sync.state.pending > 0}<span>{sync.state.pending} CHANGES WAITING</span>{/if}
      {#if sync.state.lastSyncedAt !== null}<span>SYNCED {time(sync.state.lastSyncedAt)}</span>{/if}
    {/if}
  </div>
</div>
{#if sync.needsUpdate}
  <div class="sync-update">
    <span role="alert">This version of BaseHero is too old to sync. Update it.</span>
    {#if mac}<button type="button" onclick={() => void getBackend().updateInstall()}>Restart to update</button>{/if}
  </div>
{/if}

<style>
  .sync-container { display: flex; align-items: center; gap: .8rem; }
  .sync-text { display: flex; flex-wrap: wrap; gap: .8rem; font: 500 .72rem var(--mono); color: var(--on-bar-2); }
  .sync-dot { display: none; padding: .25rem; background: none; border: 0; color: var(--ok); }
  .sync-dot.offline { color: var(--yellow); }
  .sync-update { padding: .8rem 1rem; background: var(--yellow); color: var(--on-yellow); font: 500 .8rem var(--mono); }
  .sync-update button { margin-left: 1rem; }
  @media (max-width: 600px) {
    .sync-dot { display: block; }
    .sync-text { display: none; }
    .sync-text.expanded { display: flex; position: absolute; z-index: 2; right: 0; top: 100%; padding: 1rem; background: var(--bar); border: 1px solid var(--bar-line); }
  }
</style>
