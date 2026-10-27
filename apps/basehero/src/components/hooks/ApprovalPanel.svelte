<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../../lib/backend';
  import type { AccountSummary } from '../../lib/backend/types';
  import { errorMessage } from '../../lib/errors';
  let { pending, onapproved, onrestart }: { pending: string; onapproved: (a: AccountSummary) => void; onrestart: () => void } = $props();
  let digits = $state('');
  let error = $state('');
  onMount(() => {
    let active = true;
    async function begin() {
      try {
        await getBackend().approvalStart(pending);
        if (!active) return;
        digits = await getBackend().approvalDigits(pending);
        if (!active) return;
        onapproved(await getBackend().approvalWait(pending));
      } catch (cause) { if (active) { digits = ''; error = errorMessage(cause); } }
    }
    void begin();
    return () => { active = false; };
  });
</script>
<section class="approval-panel" aria-label="Approval in the app">
  <h2>Approval in the app</h2>
  {#if digits}
    <p>Type these digits on a device already signed in to BaseHero:</p>
    <strong class="approval-digits" data-testid="approval-digits">{digits}</strong>
    <p>Waiting for approval…</p>
  {:else if error}
    <p role="alert">{error}</p>
    <button type="button" onclick={onrestart}>Start again</button>
  {:else}
    <p>Waiting for your other device to open the request…</p>
  {/if}
</section>
<style>.approval-digits { display: block; font-size: 2.5rem; letter-spacing: .1em; font-variant-numeric: tabular-nums; margin: 1rem 0; }</style>
