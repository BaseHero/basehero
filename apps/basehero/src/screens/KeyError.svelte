<script lang="ts">
  let { kind, message, onreset }: { kind: string; message: string; onreset: () => Promise<void> } = $props();
  let confirming = $state(false);
  let busy = $state(false);
  let error = $state('');
  async function reset() {
    if (busy) return;
    busy = true;
    error = '';
    try { await onreset(); }
    catch (cause) { error = cause instanceof Error ? cause.message : 'Reset failed. Try again.'; }
    finally { busy = false; }
  }
</script>

<main role="alert">
  <h1>BaseHero can't reach its key on this device.</h1>
  <p>Close BaseHero and open it again. If this keeps happening, restart the device.</p>
  {#if kind === 'KeyUnavailable' && confirming}
    <p>Erases BaseHero's data on this device. Everything that synced stays in your account. Unsynced changes are lost. To sign in again, you'll need another signed-in device or your recovery kit.</p>
    <div class="actions"><button class="primary" disabled={busy} onclick={reset}>Erase and reset</button><button disabled={busy} onclick={() => { confirming = false; error = ''; }}>Cancel</button></div>
  {:else if kind === 'KeyUnavailable'}
    <div class="actions"><button onclick={() => { confirming = true; }}>Reset this device</button></div>
  {/if}
  {#if error}<p role="status">{error}</p>{/if}
  <details>
    <summary>Technical details</summary>
    <p>{kind}: {message}</p>
  </details>
</main>

<style>
  h1 { font-size: 1.75rem; max-width: 22ch; margin-inline: auto; }
</style>
