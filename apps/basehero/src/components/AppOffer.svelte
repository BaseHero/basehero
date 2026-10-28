<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { dollars, microDollars, type AccountId, type AppChoiceInput, type AppOffer, type BaseSummary } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';

  let { account, offer, onconnect, ondecline }: {
    account: AccountId; offer: AppOffer;
    onconnect: (choice: AppChoiceInput) => Promise<void>;
    ondecline: () => Promise<void>;
  } = $props();
  let bases = $state<BaseSummary[]>([]);
  let selected = $state<Record<string, boolean>>({});
  let modes = $state<Record<string, 'readWrite' | 'readOnly'>>({});
  let newName = $state('');
  let cap = $state('');
  let removeOld = $state(false);
  let busy = $state(false);
  let error = $state('');
  onMount(() => {
    selected = Object.fromEntries(offer.bases.map(grant => [grant.base, true]));
    modes = Object.fromEntries(offer.bases.map(grant => [grant.base, grant.mode]));
    cap = dollars(offer.capMicroUsd);
    removeOld = offer.removeOld;
    let active = true;
    void getBackend().bases(account).then(list => { if (active) bases = list.filter(base => !base.hidden); })
      .catch(cause => { if (active) error = errorMessage(cause); });
    return () => { active = false; };
  });
  async function connect(event: SubmitEvent) {
    event.preventDefault();
    if (busy || (!bases.some(base => selected[base.id]) && !newName.trim())) return;
    busy = true; error = '';
    try {
      const choice: AppChoiceInput = {
        bases: bases.filter(base => selected[base.id]).map(base => ({ base: base.id, mode: modes[base.id] ?? 'readWrite' })),
        capMicroUsd: microDollars(cap),
        replaces: offer.old && removeOld ? offer.old.deviceId : null,
      };
      if (newName.trim()) choice.bases.push({ newName: newName.trim(), mode: 'readWrite' });
      await onconnect(choice);
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function decline() {
    if (busy) return;
    busy = true; error = '';
    try { await ondecline(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<h3>{offer.name}</h3>
<p>Not verified</p>
<p>Joins your account as {offer.deviceName}.</p>
<p>Approve only an app you're setting up right now.</p>
<form onsubmit={connect}>
  {#each bases as base (base.id)}
    <div class="actions">
      <label><input type="checkbox" checked={selected[base.id] ?? false} onchange={event => selected[base.id] = event.currentTarget.checked} />{base.name}</label>
      <select aria-label={`${base.name} access`} value={modes[base.id] ?? 'readWrite'} onchange={event => modes[base.id] = event.currentTarget.value as 'readWrite' | 'readOnly'} disabled={!selected[base.id]}>
        <option value="readWrite">Read-write</option><option value="readOnly">Read-only</option>
      </select>
    </div>
  {/each}
  <label>New base<input bind:value={newName} /></label>
  <label>Monthly cap (USD)<input type="number" min="0" step="0.01" required bind:value={cap} /></label>
  {#if offer.old}
    <label><input type="checkbox" bind:checked={removeOld} />Remove the old connection, {offer.old.name}, last seen {new Date(offer.old.lastSeenAt).toLocaleDateString()}</label>
  {/if}
  <div class="actions"><button type="submit" disabled={busy || (!bases.some(base => selected[base.id]) && !newName.trim())}>Connect app</button><button type="button" disabled={busy} onclick={decline}>Decline request</button></div>
</form>
{#if error}<p role="alert">{error}</p>{/if}
