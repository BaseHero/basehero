<script lang="ts">
  import { getBackend } from '../lib/backend';
  import type { SignedUp } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  let { deviceName, oncreated, onback }: { deviceName: string; oncreated: (result: SignedUp) => void; onback: () => void } = $props();
  let invite = $state('');
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
    try { oncreated(await getBackend().signUp({ invite, email, password, deviceName: device })); }
    catch (cause) { error = errorMessage(cause); }
    finally { password = ''; busy = false; }
  }
</script>
<main class="entry-grid"><section class="entry-panel">
  <span class="eyebrow">ACCOUNT / 01</span>
  <h1>Create account</h1>
  <p>Enter your invite to get started.</p>
  <form onsubmit={submit}>
    <label>Invite code<input required autocomplete="off" bind:value={invite} /></label>
    <label>Email<input type="email" required autocomplete="username" bind:value={email} /></label>
    <label>Password<input type="password" required autocomplete="new-password" bind:value={password} /></label>
    <label>Device name<input required autocomplete="off" bind:value={device} oninput={() => { deviceEdited = true; }} /></label>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="actions"><button class="primary" type="submit" disabled={busy}>Create account</button><button type="button" onclick={onback}>Back</button></div>
  </form>
</section></main>
