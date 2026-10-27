<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../../lib/backend';
  import type { AccountId, BaseSummary } from '../../lib/backend/types';
  import { drainAll, resumeAll } from '../../lib/editor/host';
  import { errorMessage } from '../../lib/errors';
  import UnlockDialog from '../hidden/UnlockDialog.svelte';
  import CreateHiddenDialog from '../hidden/CreateHiddenDialog.svelte';
  let { account, email = '', onopen = () => {} }: { account: AccountId; email?: string; onopen?: (base: string) => void } = $props();
  let unlocked = $state<BaseSummary[]>([]);
  let dialog = $state<'unlock' | 'create' | null>(null);
  let error = $state('');
  let busy = $state(false);
  async function refresh() { unlocked = (await getBackend().bases(account)).filter(base => base.hidden); }
  onMount(() => {
    let active = true;
    void refresh().catch(cause => error = errorMessage(cause));
    let stop = () => {};
    void getBackend().onEvent(event => {
      if (active && event.account === account && event.kind.toLowerCase() === 'account' &&
          (event.event === 'BasesChanged' || (typeof event.event === 'object' && event.event !== null && 'BasesChanged' in event.event))) {
        void refresh().catch(cause => error = errorMessage(cause));
      }
    }).then(unsubscribe => { if (active) stop = unsubscribe; else unsubscribe(); });
    return () => { active = false; stop(); };
  });
  async function lock(base?: string) {
    if (busy) return;
    busy = true; error = '';
    try {
      await drainAll('lock');
      if (base) await getBackend().lockHidden(account, base);
      else await getBackend().lockAllHidden();
      await refresh();
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; resumeAll('lock'); }
  }
</script>
<section aria-label="Hidden bases" class="hidden-bases">
  <h2 class="eyebrow">HIDDEN BASES</h2>
  <div class="hidden-actions"><button onclick={() => dialog = 'unlock'}>Unlock…</button><button onclick={() => dialog = 'create'}>New hidden base…</button></div>
  {#if unlocked.length}
    <ul>{#each unlocked as base (base.id)}<li><button onclick={() => onopen(base.id)}>{base.name}</button><button disabled={busy} aria-label={`Lock ${base.name}`} onclick={() => lock(base.id)}>Lock</button></li>{/each}</ul>
    <button disabled={busy} onclick={() => lock()}>Lock all</button>
  {/if}
  {#if error}<p role="alert">{error}</p>{/if}
</section>
{#if dialog === 'unlock'}<UnlockDialog {account} onclose={() => dialog = null} />{/if}
{#if dialog === 'create'}<CreateHiddenDialog {account} {email} onclose={() => dialog = null} />{/if}
<style>
  .hidden-bases { border-top: 1px solid var(--line); margin-top: 2rem; padding-top: 1rem; }
  .hidden-bases h2 { margin: 0 0 1rem; }
  .hidden-actions { display: flex; flex-wrap: wrap; gap: .5rem; }
  li { display: flex; align-items: center; gap: 1rem; margin: .5rem 0; }
  li button:first-child { flex: 1; text-align: left; }
</style>
