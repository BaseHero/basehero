<script lang="ts">
  import { errorMessage } from '../lib/errors';
  let { kit, mac, notice, onsaved, onlater }: {
    kit: string; mac: boolean; notice: string;
    onsaved: () => Promise<void>; onlater: () => void;
  } = $props();
  let busy = $state(false);
  let copyError = $state('');
  let saveError = $state('');
  async function save() {
    if (busy) return;
    busy = true; saveError = '';
    try { await onsaved(); }
    catch (cause) { saveError = errorMessage(cause); }
    finally { busy = false; }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(kit); copyError = ''; }
    catch { copyError = "Couldn't copy. Select and save the kit instead."; }
  }
</script>
<main class="entry-grid"><section class="entry-panel kit-panel">
  <span class="eyebrow">ACCOUNT / RECOVERY</span><h1>Your recovery kit</h1>
  <p>Your password and this kit together open your account on a new device. Keep it somewhere safe, apart from your password.</p>
  <div class="kit-code" data-testid="kit">{kit}</div>
  {#if notice}<p class="error" role="alert">{notice}</p>{/if}
  <div class="actions"><button onclick={copy}>Copy</button>{#if mac}<button onclick={() => window.print()}>Print</button>{/if}</div>
  {#if copyError}<p role="alert">{copyError}</p>{/if}
  {#if saveError}<p class="error" role="alert">{saveError}</p>{/if}
  <div class="actions"><button class="primary" disabled={busy} onclick={save}>I've saved it</button><button onclick={onlater}>Later</button></div>
</section></main>
