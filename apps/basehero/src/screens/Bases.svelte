<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { AccountId, BaseSummary } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import HiddenBases from '../components/hooks/HiddenBases.svelte';
  let { account, email = '', onopen }: { account: AccountId; email?: string; onopen: (base: string) => void } = $props();
  let bases = $state<BaseSummary[]>([]);
  let name = $state('');
  let error = $state('');
  onMount(() => {
    let active = true;
    const refresh = () => { void getBackend().bases(account).then(list => { if (active) bases = list.filter(base => !base.hidden && !base.mount); }).catch(e => error = errorMessage(e)); };
    refresh();
    let stop = () => {};
    void getBackend().onEvent(event => {
      if (active && event.account === account && event.kind.toLowerCase() === 'account' &&
          (event.event === 'BasesChanged' || (typeof event.event === 'object' && event.event !== null && 'BasesChanged' in event.event))) refresh();
    }).then(unsubscribe => { if (active) stop = unsubscribe; else unsubscribe(); });
    return () => { active = false; stop(); };
  });
  async function create(event: SubmitEvent) {
    event.preventDefault();
    try { const base = await getBackend().createBase(account, name.trim()); bases = (await getBackend().bases(account)).filter(item => !item.hidden && !item.mount); name = ''; onopen(base.id); }
    catch (cause) { error = errorMessage(cause); }
  }
</script>
<section class="bases-screen"><span class="eyebrow">YOUR SPACE</span><h1>Bases</h1>
  {#if error}<p role="alert">{error}</p>{/if}
  <ul>{#each bases as base (base.id)}<li><button onclick={() => onopen(base.id)}>{base.name}</button></li>{/each}</ul>
  <form onsubmit={create}><label>Base name<input bind:value={name} required /></label><button class="primary">Create base</button></form>
  <HiddenBases {account} {email} {onopen} />
</section>
