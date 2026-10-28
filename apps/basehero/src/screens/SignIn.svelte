<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  let { deviceName, onpending, onback }: { deviceName: string; onpending: (id: string) => void; onback: () => void } = $props();
  let email = $state('');
  let password = $state('');
  let device = $state('');
  let deviceEdited = $state(false);
  $effect(() => { if (!deviceEdited) device = deviceName; });
  let error = $state('');
  let busy = $state(false);
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    try {
      const pending = await getBackend().signInStart({ email, password, deviceName: device });
      onpending(pending);
    }
    catch (cause) { error = errorMessage(cause); }
    finally { password = ''; busy = false; }
  }
</script>
<main class="entry-grid"><section class="entry-panel">
  <span class="eyebrow">ACCOUNT / 02</span><h1>Sign in</h1>
  <p>Enter your password, then use another device or your recovery kit.</p>
  <form onsubmit={submit}>
    <label>Email<input type="email" required autocomplete="username" bind:value={email} /></label>
    <label>Password<input type="password" required autocomplete="current-password" bind:value={password} /></label>
    <label>Device name<input required autocomplete="off" bind:value={device} oninput={() => { deviceEdited = true; }} /></label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="actions"><button class="primary" type="submit" disabled={busy}>Continue</button><button type="button" onclick={onback}>Back</button></div>
  </form>
</section></main>
