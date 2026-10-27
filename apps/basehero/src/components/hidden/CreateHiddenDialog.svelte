<script lang="ts">
  import { getBackend } from '../../lib/backend';
  import { errorMessage } from '../../lib/errors';
  import StrengthMeter from './StrengthMeter.svelte';
  let { account, email, onclose }: { account: string; email: string; onclose: () => void } = $props();
  let name = $state('');
  let password = $state('');
  let again = $state('');
  let acknowledged = $state(false);
  let busy = $state(false);
  let error = $state('');
  function close() { password = ''; again = ''; onclose(); }
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!name.trim() || !password || password !== again || !acknowledged || busy) return;
    busy = true; error = '';
    const entered = password;
    password = ''; again = '';
    try { await getBackend().createHiddenBase(account, name.trim(), entered); close(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<div class="hidden-dialog-backdrop" role="presentation">
  <div role="dialog" tabindex="-1" aria-modal="true" aria-labelledby="create-hidden-title" class="hidden-dialog">
    <span class="eyebrow">HIDDEN BASES</span><h2 id="create-hidden-title">New hidden base</h2>
    <form onsubmit={create}>
      <label>Name<input bind:value={name} required /></label>
      <label>Extra password<input type="password" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" bind:value={password} required /></label>
      <StrengthMeter {password} {email} {name} />
      <label>Type it again<input type="password" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" bind:value={again} required /></label>
      {#if again && password !== again}<p role="alert">The passwords don't match.</p>{/if}
      <p>BaseHero can't recover this password. If you forget it, this base stays locked for good.</p>
      <p>Hidden bases that share an extra password open together.</p>
      <label class="acknowledge"><input type="checkbox" bind:checked={acknowledged} />I understand this password can't be recovered</label>
      {#if error}<p role="alert" class="error">{error}</p>{/if}
      <div class="actions"><button class="primary" disabled={busy || !name.trim() || !password || password !== again || !acknowledged}>{busy ? 'Creating…' : 'Create'}</button><button type="button" onclick={close}>Cancel</button></div>
    </form>
  </div>
</div>
