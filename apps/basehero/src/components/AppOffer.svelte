<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { dollars, microDollars, type AccountId, type AppChoiceInput, type AppOffer, type BaseChoiceInput, type BaseSummary } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import GrantPicker from './GrantPicker.svelte';

  let { account, offer, onconnect, ondecline }: {
    account: AccountId; offer: AppOffer;
    onconnect: (choice: AppChoiceInput) => Promise<void>;
    ondecline: () => Promise<void>;
  } = $props();
  let grants = $state<{ choice: BaseChoiceInput; label: string }[]>([]);
  let picker = $state(false);
  let cap = $state('');
  let removeOld = $state(false);
  let busy = $state(false);
  let error = $state('');
  onMount(() => {
    cap = dollars(offer.capMicroUsd);
    removeOld = offer.removeOld;
    let active = true;
    void getBackend().bases(account).then((bases: BaseSummary[]) => {
      if (!active) return;
      grants = offer.bases.filter(grant => bases.some(base => base.id === grant.base && !base.hidden))
        .map(grant => ({ choice: { base: grant.base, mode: grant.mode }, label: bases.find(base => base.id === grant.base)!.name }));
    }).catch(cause => { if (active) error = errorMessage(cause); });
    return () => { active = false; };
  });
  function add(choice: BaseChoiceInput, label: string) {
    const index = grants.findIndex(grant => grant.choice.base === choice.base && grant.choice.folder === choice.folder);
    if (index < 0) grants = [...grants, { choice, label }];
    else grants[index] = { choice, label };
    picker = false;
  }
  async function connect(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !grants.length) return;
    busy = true; error = '';
    try {
      await onconnect({
        bases: grants.map(grant => grant.choice),
        capMicroUsd: microDollars(cap),
        replaces: offer.old && removeOld ? offer.old.deviceId : null,
      });
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
  {#each grants as grant, index (index)}
    <div class="actions">
      <span>{grant.label}</span>
      <select aria-label={`${grant.label} access`} bind:value={grant.choice.mode} disabled={busy}>
        <option value="readWrite">Read-write</option><option value="readOnly">Read-only</option>
      </select>
      <button type="button" disabled={busy} onclick={() => grants = grants.filter(row => row !== grant)}>Remove {grant.label}</button>
    </div>
  {/each}
  <button type="button" disabled={busy} onclick={() => picker = true}>Add a base or folder</button>
  {#if picker}<GrantPicker {account} onpick={add} oncancel={() => picker = false} />{/if}
  <label>Monthly cap (USD)<input type="number" min="0" step="0.01" required bind:value={cap} /></label>
  {#if offer.old}
    <label><input type="checkbox" bind:checked={removeOld} />Remove the old connection, {offer.old.name}, last seen {new Date(offer.old.lastSeenAt).toLocaleDateString()}</label>
  {/if}
  <div class="actions"><button type="submit" disabled={busy || !grants.length}>Connect app</button><button type="button" disabled={busy} onclick={decline}>Decline request</button></div>
</form>
{#if error}<p role="alert">{error}</p>{/if}
