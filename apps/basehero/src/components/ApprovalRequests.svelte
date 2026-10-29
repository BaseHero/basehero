<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { AccountId, AppChoiceInput, AppOffer as Offer, ApprovalRequest, OpenedRequest } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import AppOffer from './AppOffer.svelte';
  let { account }: { account: AccountId } = $props();
  let requests = $state<ApprovalRequest[]>([]);
  let opened = $state<(OpenedRequest & { kind: ApprovalRequest['kind'] }) | null>(null);
  let offer = $state<Offer | null>(null);
  let digits = $state('');
  let busy = $state(false);
  let error = $state('');
  let connected = $state('');
  let oldKept = $state(false);
  onMount(() => {
    let active = true;
    let unsubscribe: (() => void) | undefined;
    // Events received while a snapshot is in flight are newer than that snapshot.
    const changes = new Map<string, ApprovalRequest | null>();
    void getBackend().onEvent(event => {
      // Removed clears the session before this runs, so check the event's shape before `account`.
      if (!active || event.kind.toLowerCase() !== 'account' || typeof event.event !== 'object' || event.event === null || event.account !== account) return;
      if ('ApprovalRequested' in event.event) {
        const request = event.event.ApprovalRequested as ApprovalRequest;
        changes.set(request.id, request);
        requests = [...requests.filter(r => r.id !== request.id), request];
      } else if ('ApprovalClosed' in event.event) {
        const id = event.event.ApprovalClosed as string;
        changes.set(id, null);
        requests = requests.filter(r => r.id !== id);
        if (opened?.id === id) { opened = null; offer = null; digits = ''; }
      }
    }).then(async stop => {
      if (!active) { stop(); return; }
      unsubscribe = stop;
      try {
        const items = await getBackend().approvalRequests(account);
        if (active) requests = [
          ...items.filter(item => !changes.has(item.id)),
          ...[...changes.values()].filter((item): item is ApprovalRequest => item !== null),
        ];
      } catch (cause) { if (active) error = errorMessage(cause); }
    }).catch(cause => { if (active) error = errorMessage(cause); });
    return () => { active = false; unsubscribe?.(); };
  });
  async function open(id: string) {
    if (busy) return;
    busy = true; error = ''; connected = ''; oldKept = false;
    try {
      const kind = requests.find(request => request.id === id)?.kind ?? 'Device';
      const result = kind === 'App' ? await getBackend().connectOpen(account, id) : await getBackend().approvalOpen(account, id);
      opened = { ...result, kind }; offer = null; digits = '';
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function approve(event: SubmitEvent) {
    event.preventDefault();
    if (!opened || busy) return;
    busy = true; error = '';
    try {
      await getBackend().approvalApprove(account, opened.id, digits);
      requests = requests.filter(r => r.id !== opened?.id);
      opened = null; digits = '';
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function check(event: SubmitEvent) {
    event.preventDefault();
    if (!opened || busy) return;
    busy = true; error = '';
    try { offer = await getBackend().connectCheck(account, opened.id, digits); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function connect(choice: AppChoiceInput) {
    if (!opened || !offer) return;
    const id = opened.id;
    const name = offer.deviceName;
    const [, removed] = await getBackend().connectApprove(account, id, choice);
    connected = name;
    oldKept = choice.replaces !== null && !removed;
    requests = requests.filter(request => request.id !== id);
    opened = null; offer = null; digits = '';
  }
  async function decline(id: string) {
    if (busy) return;
    busy = true; error = '';
    try { await getBackend().approvalDecline(account, id); requests = requests.filter(r => r.id !== id); if (opened?.id === id) { opened = null; offer = null; digits = ''; } }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
{#if connected}
  <p role="status">Connected {connected}.</p>
  {#if oldKept}<p role="alert">The old connection couldn't be removed; disconnect it in Devices.</p>{/if}
{/if}
{#if requests.length || opened}
  <section class="approval-requests" aria-label="Approval requests">
    <h2>Approval requests</h2>
    {#each requests as request (request.id)}
      {#if request.id !== opened?.id || !offer}
        <div class="actions">
          <span>{request.kind === 'App' ? 'An app wants to connect.' : 'A new device is asking to sign in.'}</span>
          <button disabled={busy} onclick={() => open(request.id)}>Open request</button>
          <button disabled={busy} onclick={() => decline(request.id)}>Decline request</button>
        </div>
      {/if}
    {/each}
    {#if opened?.kind === 'App'}
      {#if offer}
        <AppOffer {account} {offer} onconnect={connect} ondecline={() => decline(opened!.id)} />
      {:else}
        <p>Type the six digits the app shows. Approve only an app you're setting up right now.</p>
        <form onsubmit={check}>
          <label>Digits shown in the app<input required autocomplete="one-time-code" inputmode="numeric" bind:value={digits} /></label>
          <button disabled={busy} type="submit">Check digits</button>
        </form>
      {/if}
    {:else if opened}
      <p>Type the six digits shown on the new device.</p>
      <form onsubmit={approve}>
        <label>Digits shown on the new device<input required autocomplete="one-time-code" inputmode="numeric" bind:value={digits} /></label>
        <button disabled={busy} type="submit">Approve device</button>
      </form>
    {/if}
    {#if error}<p role="alert">{error}</p>{/if}
  </section>
{/if}
