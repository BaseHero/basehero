<script lang="ts">
  import { errorMessage } from '../lib/errors';
  let { kit, oncontinue, onback }: { kit: string; oncontinue: () => Promise<void>; onback: () => void } = $props();
  let saved = $state(false);
  let busy = $state(false);
  let copyError = $state('');
  let continueError = $state('');
  async function continueAfterSaving() {
    if (busy) return;
    busy = true; continueError = '';
    try { await oncontinue(); }
    catch (cause) { continueError = errorMessage(cause); }
    finally { busy = false; }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(kit); copyError = ''; }
    catch { copyError = "Couldn't copy. Select and save the kit instead."; }
  }
</script>
<main class="entry-grid"><section class="entry-panel kit-panel">
  <span class="eyebrow">ACCOUNT / 02</span><h1>Save your recovery kit</h1>
  <p>Your password and this kit together open your account on a new device. Keep the kit somewhere safe, apart from your password. BaseHero can't show it again.</p>
  <div class="kit-code" data-testid="kit">{kit}</div>
  <div class="actions"><button onclick={copy}>Copy</button><button onclick={() => window.print()}>Print</button></div>
  {#if copyError}<p role="alert">{copyError}</p>{/if}
  <label class="confirm"><input type="checkbox" bind:checked={saved} />I've saved my kit</label>
  {#if continueError}<p class="error" role="alert">{continueError}</p>{/if}
  <div class="actions"><button class="primary" disabled={!saved || busy} onclick={continueAfterSaving}>Continue</button><button onclick={onback}>Back</button></div>
</section></main>
