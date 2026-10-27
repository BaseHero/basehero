<script lang="ts">
  import { getBackend } from '../../lib/backend';
  import { errorMessage } from '../../lib/errors';
  let { account, onclose }: { account: string; onclose: () => void } = $props();
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  function close() { password = ''; onclose(); }
  async function unlock(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    const entered = password;
    password = '';
    try { await getBackend().unlockHidden(account, entered); close(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<div class="hidden-dialog-backdrop" role="presentation">
  <div role="dialog" tabindex="-1" aria-modal="true" aria-labelledby="unlock-title" class="hidden-dialog">
    <span class="eyebrow">HIDDEN BASES</span><h2 id="unlock-title">Unlock hidden bases</h2>
    <form onsubmit={unlock}>
      <label>Extra password<input type="password" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" bind:value={password} required /></label>
      {#if error}<p role="alert" class="error">{error}</p>{/if}
      <div class="actions"><button class="primary" disabled={busy || !password}>{busy ? 'Unlocking…' : 'Unlock'}</button><button type="button" onclick={close}>Cancel</button></div>
    </form>
  </div>
</div>
