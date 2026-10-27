<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { AccountId, ApprovalRequest, OpenedRequest } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  let { account }: { account: AccountId } = $props();
  let requests = $state<ApprovalRequest[]>([]);
  let opened = $state<OpenedRequest | null>(null);
  let digits = $state('');
  let busy = $state(false);
  let error = $state('');
  onMount(() => {
    let active = true;
    let unsubscribe: (() => void) | undefined;
    // Events received while a snapshot is in flight are newer than that snapshot.
    const changes = new Map<string, ApprovalRequest | null>();
    void getBackend().onEvent(event => {
      if (!active || event.kind.toLowerCase() !== 'account' || event.account !== account || typeof event.event !== 'object' || event.event === null) return;
      if ('ApprovalRequested' in event.event) {
        const request = event.event.ApprovalRequested as ApprovalRequest;
        changes.set(request.id, request);
        requests = [...requests.filter(r => r.id !== request.id), request];
      } else if ('ApprovalClosed' in event.event) {
        const id = event.event.ApprovalClosed as string;
        changes.set(id, null);
        requests = requests.filter(r => r.id !== id);
        if (opened?.id === id) { opened = null; digits = ''; }
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
    busy = true; error = '';
    try { opened = await getBackend().approvalOpen(account, id); }
    catch (cause) { error = errorMessage(cause); }
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
  async function decline(id: string) {
    if (busy) return;
    busy = true; error = '';
    try { await getBackend().approvalDecline(account, id); requests = requests.filter(r => r.id !== id); if (opened?.id === id) { opened = null; digits = ''; } }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
{#if requests.length || opened}
  <section class="approval-requests" aria-label="Device approval requests">
    <h2>Device approval requests</h2>
    {#each requests as request (request.id)}
      <div class="actions">
        <span>A new device is asking to sign in.</span>
        <button disabled={busy} onclick={() => open(request.id)}>Open request</button>
        <button disabled={busy} onclick={() => decline(request.id)}>Decline request</button>
      </div>
    {/each}
    {#if opened}
      <p>Type the six digits shown on the new device.</p>
      <form onsubmit={approve}>
        <label>Digits shown on the new device<input required autocomplete="one-time-code" inputmode="numeric" bind:value={digits} /></label>
        <button disabled={busy} type="submit">Approve device</button>
      </form>
    {/if}
    {#if error}<p role="alert">{error}</p>{/if}
  </section>
{/if}
