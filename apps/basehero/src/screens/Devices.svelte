<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import { dollars, microDollars, type DeviceSummary, type KitStatus } from '../lib/backend/types';
  let { account, kitRevision, onshow, onnewkit }: { account: string; kitRevision: number; onshow: () => Promise<void>; onnewkit: (kit: string) => Promise<void> } = $props();
  let devices = $state<DeviceSummary[]>([]);
  let error = $state('');
  let busy = $state(false);
  let kitStatus = $state<KitStatus>({ known: false, saved: false, madeAt: null });
  let password = $state('');
  let makingKit = $state(false);
  let changingCap = $state<string | null>(null);
  let cap = $state('');
  async function refresh() {
    try {
      const [list, status] = await Promise.all([getBackend().devices(account), getBackend().kitStatus(account)]);
      devices = list.sort((a, b) => Number(b.thisDevice) - Number(a.thisDevice));
      kitStatus = status;
    } catch (cause) { error = errorMessage(cause); }
  }
  $effect(() => { account; kitRevision; void refresh(); });
  async function makeKit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    try {
      const kit = await getBackend().newKit(account, password);
      password = ''; makingKit = false;
      await onnewkit(kit);
    } catch (cause) { error = errorMessage(cause); }
    finally { password = ''; busy = false; }
  }
  async function saveCap(event: SubmitEvent, device: DeviceSummary) {
    event.preventDefault();
    if (busy) return;
    busy = true; error = '';
    try {
      await getBackend().setAppCap(account, device.id, microDollars(cap));
      changingCap = null;
      await refresh();
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function remove(device: DeviceSummary) {
    const question = device.kind.toLowerCase() === 'app'
      ? `Disconnect ${device.name}? It erases its copy of your data.`
      : `Remove ${device.name} from your account?`;
    if (busy || !window.confirm(question)) return;
    busy = true; error = '';
    try { await getBackend().removeDevice(account, device.id); await refresh(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
</script>
<main class="workspace"><h1>Devices</h1>
  <section class="recovery-row" aria-label="Recovery kit"><div><h2>Recovery kit</h2>
    {#if kitStatus.known}<p>{kitStatus.saved ? 'Saved' : 'Keep it somewhere safe, apart from your password.'}</p>{/if}
  </div>
    {#if kitStatus.known}<button type="button" onclick={onshow}>Show</button>
    {:else}<button type="button" onclick={() => { makingKit = true; error = ''; }}>Make a new kit</button>{/if}
  </section>
  {#if makingKit}
    <form onsubmit={makeKit}><p>Your old kit stops working.</p>
      <label>Password<input type="password" required autocomplete="current-password" bind:value={password} /></label>
      <div class="actions"><button type="submit" class="primary" disabled={busy}>Make kit</button><button type="button" onclick={() => { makingKit = false; password = ''; error = ''; }}>Cancel</button></div>
    </form>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <ul>{#each devices as device (device.id)}
    <li data-device-id={device.id}>
      <div><strong>{device.name}</strong> {#if device.thisDevice}<small>This device</small>{/if}
        <p>{device.kind} · Last seen {device.lastSeenAt === null ? 'never' : new Date(device.lastSeenAt).toLocaleString()}</p>
        {#if device.kind.toLowerCase() === 'app' && device.capMicroUsd !== null}
          <p>Cap ${dollars(device.capMicroUsd)} a month</p>
          {#if changingCap === device.id}
            <form onsubmit={event => saveCap(event, device)}>
              <label>Monthly cap (USD)<input type="number" min="0" step="0.01" required bind:value={cap} /></label>
              <button type="submit" disabled={busy}>Save</button>
            </form>
          {:else}
            <button type="button" disabled={busy} onclick={() => { cap = dollars(device.capMicroUsd!); changingCap = device.id; }}>Change cap</button>
          {/if}
        {/if}
      </div>
      <button type="button" disabled={busy} onclick={() => remove(device)}>{device.kind.toLowerCase() === 'app' ? 'Disconnect' : 'Remove'}</button>
    </li>
  {/each}</ul>
</main>
<style>
  ul { list-style: none; padding: 0; }
  .recovery-row { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 1rem 0; border-top: 1px solid var(--line); }
  .recovery-row h2 { margin: 0 0 .4rem; }
  .recovery-row p { margin: 0; }
  form { max-width: 28rem; margin-bottom: 1.5rem; }
  li { display: flex; justify-content: space-between; gap: 1rem; align-items: center; padding: 1rem 0; border-top: 1px solid var(--line); }
  li p { margin: .3rem 0 0; }
  small { margin-left: .5rem; }
</style>
