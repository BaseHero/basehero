<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import type { DeviceSummary } from '../lib/backend/types';
  let { account }: { account: string } = $props();
  let devices = $state<DeviceSummary[]>([]);
  let error = $state('');
  let busy = $state(false);
  async function refresh() {
    try {
      devices = (await getBackend().devices(account)).sort((a, b) => Number(b.thisDevice) - Number(a.thisDevice));
    } catch (cause) { error = errorMessage(cause); }
  }
  $effect(() => { account; void refresh(); });
  async function remove(device: DeviceSummary) {
    if (busy || !window.confirm(`Remove ${device.name} from your account?`)) return;
    busy = true; error = '';
    try { await getBackend().removeDevice(account, device.id); await refresh(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<main class="workspace"><h1>Devices</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <ul>{#each devices as device (device.id)}
    <li data-device-id={device.id}>
      <div><strong>{device.name}</strong> {#if device.thisDevice}<small>This device</small>{/if}
        <p>{device.kind} · Last seen {device.lastSeenAt === null ? 'never' : new Date(device.lastSeenAt).toLocaleString()}</p></div>
      <button type="button" disabled={busy} onclick={() => remove(device)}>Remove</button>
    </li>
  {/each}</ul>
</main>
<style>
  ul { list-style: none; padding: 0; }
  li { display: flex; justify-content: space-between; gap: 1rem; align-items: center; padding: 1rem 0; border-top: 1px solid var(--line); }
  li p { margin: .3rem 0 0; }
  small { margin-left: .5rem; }
</style>
