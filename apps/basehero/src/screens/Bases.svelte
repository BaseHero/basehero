<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { AccountId, BaseSummary } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import HiddenBases from '../components/hooks/HiddenBases.svelte';
  let { account, onopen }: { account: AccountId; onopen: (base: string) => void } = $props();
  let bases = $state<BaseSummary[]>([]);
  let name = $state('');
  let error = $state('');
  onMount(() => { void getBackend().bases(account).then(list => bases = list).catch(e => error = errorMessage(e)); });
  async function create(event: SubmitEvent) {
    event.preventDefault();
    try { const base = await getBackend().createBase(account, name.trim()); bases = [...bases, base]; name = ''; onopen(base.id); }
    catch (cause) { error = errorMessage(cause); }
  }
</script>
<section class="bases-screen"><span class="eyebrow">YOUR SPACE</span><h1>Bases</h1>
  {#if error}<p role="alert">{error}</p>{/if}
  <ul>{#each bases as base (base.id)}<li><button onclick={() => onopen(base.id)}>{base.name}</button></li>{/each}</ul>
  <form onsubmit={create}><label>Base name<input bind:value={name} required /></label><button class="primary">Create base</button></form>
  <HiddenBases {account} />
</section>
