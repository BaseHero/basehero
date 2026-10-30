<script lang="ts">
  import { tick } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import { dollars, microDollars, type AppSummary, type BaseChoiceInput, type BaseSummary, type DeviceSummary, type KitStatus } from '../lib/backend/types';
  import GrantPicker from '../components/GrantPicker.svelte';
  let { account, kitRevision, newKitRevision = 0, onshow, onnewkit }: { account: string; kitRevision: number; newKitRevision?: number; onshow: () => Promise<void>; onnewkit: (kit: string) => Promise<void> } = $props();
  let devices = $state<DeviceSummary[]>([]);
  let apps = $state<AppSummary[]>([]);
  let bases = $state<BaseSummary[]>([]);
  let picking = $state<string | null>(null);
  let error = $state('');
  let busy = $state(false);
  let kitStatus = $state<KitStatus>({ known: false, saved: false, madeAt: null });
  let password = $state('');
  let makingKit = $state(false);
  let removing = $state<string | null>(null);
  let removePassword = $state('');
  let removalPasswordInput: HTMLInputElement;
  let changingCap = $state<string | null>(null);
  let cap = $state('');
  async function refresh() {
    try {
      const [list, status, appList, baseList] = await Promise.all([
        getBackend().devices(account), getBackend().kitStatus(account), getBackend().apps(account), getBackend().bases(account),
      ]);
      devices = list.filter(device => device.status === 'active' || device.pendingRemoval)
        .sort((a, b) => Number(b.thisDevice) - Number(a.thisDevice));
      if (devices.find(device => device.id === changingCap)?.pendingRemoval) changingCap = null;
      if (devices.find(device => device.id === picking)?.pendingRemoval) picking = null;
      kitStatus = status;
      apps = appList;
      bases = baseList;
    } catch (cause) { error = errorMessage(cause); }
  }
  $effect(() => { account; kitRevision; void refresh(); });
  $effect(() => { if (newKitRevision > 0) makingKit = true; });
  $effect(() => {
    const current = account;
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    void getBackend().onEvent(event => {
      if (event.account === current && event.kind.toLowerCase() === 'account' && event.event === 'DevicesChanged') void refresh();
    }).then(stop => { if (disposed) stop(); else unsubscribe = stop; });
    return () => { disposed = true; unsubscribe?.(); };
  });
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
    if (busy || device.pendingRemoval || devices.find(current => current.id === device.id)?.pendingRemoval) return;
    busy = true; error = '';
    try {
      await getBackend().setAppCap(account, device.id, microDollars(cap));
      changingCap = null;
      await refresh();
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  function grantLabel(baseId: string): string {
    const base = bases.find(base => base.id === baseId);
    if (!base) return baseId;
    const parent = bases.find(candidate => candidate.id === base.mount?.parent);
    return parent ? `${base.name} in ${parent.name}` : base.name;
  }
  async function addGrant(device: DeviceSummary, choice: BaseChoiceInput) {
    if (busy || device.pendingRemoval || devices.find(current => current.id === device.id)?.pendingRemoval) return;
    busy = true; error = '';
    try {
      await getBackend().appGrantAdd(account, device.id, choice);
      picking = null;
      await refresh();
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function removeGrant(device: DeviceSummary, base: string) {
    const label = grantLabel(base);
    if (busy || !window.confirm(`Remove ${apps.find(app => app.deviceId === device.id)?.name ?? device.name}'s access to ${label}? The app erases its copy of it.`)) return;
    busy = true; error = '';
    try { await getBackend().appGrantRemove(account, device.id, base); await refresh(); }
    catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function remove(device: DeviceSummary, lost?: boolean) {
    if (busy || device.pendingRemoval) return;
    const app = device.kind.toLowerCase() === 'app';
    if (lost === undefined && !device.thisDevice && !app) {
      removing = device.id; removePassword = ''; error = '';
      await tick();
      removalPasswordInput?.focus();
      return;
    }
    if (lost === undefined && !window.confirm(app
      ? `Disconnect ${device.name}? It erases its copy of your data.`
      : `Remove ${device.name} from your account?`)) return;
    busy = true; error = '';
    const secret = removePassword;
    removePassword = '';
    try {
      const result = await getBackend().removeDevice(account, device.id, lost === undefined ? undefined : { password: secret, lost });
      removing = null;
      await refresh();
      if (result.newKit) await onnewkit(result.newKit);
    } catch (cause) { error = errorMessage(cause); }
    finally {
      removePassword = ''; busy = false;
      if (removing === device.id) {
        await tick();
        removalPasswordInput?.focus();
      }
    }
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
        {#if device.pendingRemoval || (busy && removing === device.id)}<p role="status">Removing…</p>{/if}
        <p>{device.kind} · Last seen {device.lastSeenAt === null ? 'never' : new Date(device.lastSeenAt).toLocaleString()}</p>
        {#if device.kind.toLowerCase() === 'app' && device.capMicroUsd !== null}
          <p>Cap ${dollars(device.capMicroUsd)} a month</p>
          {#if changingCap === device.id && !device.pendingRemoval}
            <form onsubmit={event => saveCap(event, device)}>
              <label>Monthly cap (USD)<input type="number" min="0" step="0.01" required bind:value={cap} /></label>
              <button type="submit" disabled={busy}>Save</button>
            </form>
          {:else}
            <button type="button" disabled={busy || device.pendingRemoval} onclick={() => { cap = dollars(device.capMicroUsd!); changingCap = device.id; }}>Change cap</button>
          {/if}
          {#if device.kind.toLowerCase() === 'app'}
            {#each apps.find(app => app.deviceId === device.id)?.bases ?? [] as grant (grant.base)}
              <div class="actions"><span>{grantLabel(grant.base)} · {grant.mode === 'readOnly' ? 'Read-only' : 'Read-write'}</span>
                <button type="button" disabled={busy || device.pendingRemoval} onclick={() => removeGrant(device, grant.base)}>Remove {grantLabel(grant.base)}</button>
              </div>
            {/each}
            <button type="button" disabled={busy || device.pendingRemoval} onclick={() => picking = device.id}>Add a base or folder</button>
            {#if picking === device.id && !device.pendingRemoval}<GrantPicker {account} onpick={(choice) => { void addGrant(device, choice); }} oncancel={() => picking = null} />{/if}
          {/if}
        {/if}
      </div>
      <button type="button" disabled={busy || device.pendingRemoval} onclick={() => remove(device)}>{device.kind.toLowerCase() === 'app' ? 'Disconnect' : 'Remove'}</button>
      {#if removing === device.id}
        <form class="removal-form" onsubmit={event => event.preventDefault()}>
          <label>Password<input type="password" autocomplete="current-password" required bind:value={removePassword} bind:this={removalPasswordInput} /></label>
          <p>Do you still have this device?</p>
          <div class="actions">
            <button type="button" class="primary" disabled={busy || !removePassword} onclick={() => remove(device, false)}>I still have it</button>
            <button type="button" class="primary" disabled={busy || !removePassword} onclick={() => remove(device, true)}>It's lost or stolen</button>
            <button type="button" disabled={busy} onclick={() => { removing = null; removePassword = ''; error = ''; }}>Cancel</button>
          </div>
        </form>
      {/if}
    </li>
  {/each}</ul>
</main>
<style>
  ul { list-style: none; padding: 0; }
  .recovery-row { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 1rem 0; border-top: 1px solid var(--line); }
  .recovery-row h2 { margin: 0 0 .4rem; }
  .recovery-row p { margin: 0; }
  form { max-width: 28rem; margin-bottom: 1.5rem; }
  li { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 1rem; align-items: center; padding: 1rem 0; border-top: 1px solid var(--line); }
  li > div:first-child { flex: 1; min-width: 0; }
  li > .removal-form { flex: 0 0 100%; max-width: none; margin: 0; }
  .removal-form label { display: block; max-width: 28rem; }
  li p { margin: .3rem 0 0; }
  small { margin-left: .5rem; }
</style>
