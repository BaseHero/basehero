<script lang="ts">
  import { getBackend } from '../lib/backend';
  import type { AccountSummary } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import ApprovalPanel from '../components/hooks/ApprovalPanel.svelte';
  let { pending, onapproved, oncancel }: { pending: string; onapproved: (a: AccountSummary) => void; oncancel: () => void } = $props();
  let kit = $state('');
  let error = $state('');
  let busy = $state(false);
  async function useKit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    try { onapproved(await getBackend().signInWithKit(pending, kit)); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<main class="entry-grid"><section class="entry-panel">
  <span class="eyebrow">ACCOUNT / 03</span><h1>Open this device</h1>
  <ApprovalPanel {pending} {onapproved} />
  <div class="separator">OR USE YOUR KIT</div>
  <form onsubmit={useKit}>
    <label>Recovery kit<input required autocomplete="off" autocapitalize="characters" spellcheck="false" bind:value={kit} /></label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="actions"><button class="primary" type="submit" disabled={busy}>Use kit</button><button type="button" onclick={oncancel}>Cancel</button></div>
  </form>
</section></main>
