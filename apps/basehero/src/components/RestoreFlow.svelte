<script lang="ts">
  import { onDestroy } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { BackendError, type BackupBase, type BackupListing, type BackupLocation, type CheckReport, type RestoreSummary, type SignedUp } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';

  let { account, deviceName, oncancel, oncreated }: { account: string | null; deviceName: string; oncancel: () => void; oncreated?: (result: SignedUp) => void } = $props();
  let stage = $state<'folder' | 'list' | 'credentials' | 'point' | 'signup' | 'done'>('folder');
  let location = $state<BackupLocation | null>(null);
  let listings = $state<BackupListing[]>([]);
  let listing = $state<BackupListing | null>(null);
  let password = $state('');
  let kit = $state('');
  let extra = $state('');
  let handle = $state<string | null>(null);
  let points = $state<number[]>([]);
  let at = $state(0);
  let bases = $state<BackupBase[]>([]);
  let chosen = $state<string[]>([]);
  let check = $state<CheckReport | null>(null);
  function openedLine(unreadable: number, ignored: number) {
    const n = unreadable + ignored;
    return n ? `${count(n, 'record')} couldn't be opened or applied` : 'Everything opened';
  }
  function count(n: number, thing: string) { return `${n} ${thing}${n === 1 ? '' : 's'}`; }
  function when(ms: number) { return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); }
  let summary = $state<RestoreSummary | null>(null);
  let signedResult = $state<(SignedUp & { error: { kind: string; message: string } | null }) | null>(null);
  let restoredNames = $state<string[]>([]);
  let error = $state('');
  let busy = $state(false);
  let server = $state('');
  let invite = $state('');
  let email = $state('');
  let newPassword = $state('');
  let newDevice = $state('');
  $effect(() => { if (!newDevice) newDevice = deviceName; });
  const backend = getBackend();
  void backend.appInfo().then(info => { server = info.server; }).catch(() => {});
  let cancelled = false;
  onDestroy(() => { cancelled = true; void closeHandle(); });
  function cancel() { cancelled = true; void closeHandle(); oncancel(); }
  async function run(action: () => Promise<void>) {
    if (busy) return;
    busy = true; error = '';
    try { await action(); } catch (cause) { error = cause instanceof BackendError && cause.kind === 'BadKit' ? 'Wrong password or recovery kit' : errorMessage(cause); }
    finally { busy = false; }
  }
  async function closeHandle() {
    const opened = handle;
    handle = null;
    if (opened) await backend.restoreClose(opened).catch(() => {});
  }
  async function pick() {
    await run(async () => {
      const picked = await backend.pickBackupFolder();
      if (!picked) return;
      await closeHandle();
      const found = await backend.restoreList(picked);
      location = picked; listings = found; listing = null; stage = 'list';
    });
  }
  async function open(event: SubmitEvent) {
    event.preventDefault();
    if (!listing || !location) return;
    await run(async () => {
      await closeHandle();
      const opened = await backend.restoreOpen(location!, listing!, password, kit);
      if (cancelled) { await backend.restoreClose(opened); return; }
      handle = opened;
      try {
        points = await backend.restorePoints(opened);
        at = points[0] ?? 0;
        if (!points.length) throw new BackendError('NotFound', 'No points in this backup');
        await loadPoint();
        if (cancelled) return;
        password = ''; kit = ''; stage = 'point';
      } catch (cause) {
        await closeHandle();
        throw cause;
      }
    });
  }
  async function loadPoint() {
    if (!handle) return;
    const [available, report] = await Promise.all([backend.restoreBases(handle, at), backend.restoreCheck(handle, at)]);
    bases = available; check = report;
    chosen = available.map(base => base.id);
  }
  async function unlock(event: SubmitEvent) {
    event.preventDefault();
    if (!handle) return;
    await run(async () => { await backend.restoreUnlock(handle!, extra); extra = ''; await loadPoint(); });
  }
  async function restore() {
    if (!handle || !account) return;
    await run(async () => {
      const selected = bases.filter(base => chosen.includes(base.id));
      if (!selected.length) throw new BackendError('Invalid', 'Choose at least one base');
      const label = `restored ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}`;
      summary = await backend.restoreInto(handle!, account!, at, selected.map(base => base.id), label);
      restoredNames = selected.map(base => `${base.name} (${label})`);
      stage = 'done'; await closeHandle();
    });
  }
  async function signup(event: SubmitEvent) {
    event.preventDefault();
    if (!handle) return;
    await run(async () => {
      const label = `restored ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}`;
      const result = await backend.restoreSignUp(handle!, { invite, email, password: newPassword, deviceName: newDevice }, at, label);
      newPassword = '';
      summary = result.summary;
      const restored = new Set(result.summary?.restored.map(([source]) => source) ?? []);
      restoredNames = bases.filter(base => restored.has(base.id)).map(base => `${base.name} (${label})`);
      signedResult = result;
      stage = 'done'; await closeHandle();
    });
  }
</script>
<section class="restore-flow" aria-label="Restore from a backup">
  <span class="eyebrow">RESTORE / {stage.toUpperCase()}</span>
  <h2>Restore from a backup</h2>
  {#if error}<p role="alert" class="error">{error}</p>{/if}
  {#if stage === 'folder'}
    <p>Choose the folder that holds your backup.</p><button type="button" disabled={busy} onclick={pick}>Pick folder…</button>
  {:else if stage === 'list'}
    <p>Backups in {location?.label}</p>
    {#each listings as item (item.account + item.device)}
      <button type="button" class="listing" onclick={() => { listing = item; email = ''; stage = 'credentials'; }}>{item.email} · {item.device} · {when(item.writtenAt)}</button>
    {:else}<p>No backups in this folder.</p>{/each}
    <button type="button" disabled={busy} onclick={pick}>Choose another folder</button>
  {:else if stage === 'credentials'}
    <p>{listing?.email} · {listing?.device}</p>
    <form onsubmit={open}>
      <label>Password<input type="password" autocomplete="off" required bind:value={password} /></label>
      <label>Recovery kit<input autocomplete="off" required bind:value={kit} /></label>
      <div class="actions"><button class="primary" type="submit" disabled={busy}>Open backup</button><button type="button" onclick={() => stage = 'list'}>Back</button></div>
    </form>
  {:else if stage === 'point' || stage === 'signup'}
    <label>Point in time<select bind:value={at} disabled={busy} onchange={() => void run(loadPoint)}>{#each points as point}<option value={point}>{when(point)}</option>{/each}</select></label>
    <ul>{#each bases as base (base.id)}<li>
      {#if account}<label><input type="checkbox" checked={chosen.includes(base.id)} onchange={(event) => chosen = event.currentTarget.checked ? [...chosen, base.id] : chosen.filter(id => id !== base.id)} />{base.name}</label>
      {:else}<strong>{base.name}</strong>{/if}
      <small>{count(base.notes, 'note')} · {count(base.records, 'record')} · {count(base.files, 'file')}</small>
    </li>{/each}</ul>
    {#if check && check.locked > 0}<p>{check.locked} {check.locked === 1 ? 'base needs its extra password' : 'bases need their extra password'}. Any left unopened will be skipped.</p>
      <form onsubmit={unlock}><label>Extra password<input type="password" autocomplete="off" bind:value={extra} required /></label><button type="submit" disabled={busy}>Open bases</button></form>
    {/if}
    {#if check}<p>{openedLine(check.bases.reduce((total, base) => total + base.unreadable, 0), check.ignoredFiles.length)}</p>
      {#if check.missing}<p>{check.missing} {check.missing === 1 ? 'base' : 'bases'} without a snapshot.</p>{/if}
      {#if check.bases.some(base => base.missingFiles.length)}<p>{count(check.bases.reduce((total, base) => total + base.missingFiles.length, 0), 'missing file')}.</p>{/if}
    {/if}
    {#if stage === 'point'}
      {#if account}<button class="primary" type="button" disabled={busy} onclick={restore}>Restore selected</button>
      {:else}<button class="primary" type="button" onclick={() => stage = 'signup'}>Continue to sign up</button>{/if}
    {:else}
      <form onsubmit={signup}>
        <label>Server<input type="url" bind:value={server} readonly /></label>
        <small>The new account uses this app's configured server.</small>
        <label>Invite code<input bind:value={invite} /></label>
        <label>Email<input type="email" bind:value={email} required /></label>
        <label>New password<input type="password" autocomplete="new-password" bind:value={newPassword} required /></label>
        <label>Device name<input bind:value={newDevice} required /></label>
        <button class="primary" type="submit" disabled={busy}>Sign up and restore</button>
      </form>
    {/if}
  {:else if stage === 'done' && (summary || signedResult)}
    <h3>{summary ? 'Restore complete' : 'Your new account is ready'}</h3>
    {#if signedResult?.error}<p role="alert">The restore didn't finish: {signedResult.error.message}. You can restore again from Backup.</p>
      <p>Your recovery kit: <strong>{signedResult.kit}</strong></p>{/if}
    {#if restoredNames.length}<p>Restored {restoredNames.join(', ')}.</p>{/if}
    {#if summary}<p>{openedLine(summary.unreadable, summary.ignoredFiles.length)}</p>
      {#if summary.locked + summary.missing}<p>{count(summary.locked + summary.missing, 'base')} skipped.</p>{/if}
      {#if summary.missingFiles.length}<p>{count(summary.missingFiles.length, 'missing file')}.</p>{/if}{/if}
    <button type="button" onclick={() => { if (signedResult) oncreated?.(signedResult); else cancel(); }}>Done</button>
  {/if}
  {#if stage !== 'done'}<div class="actions"><button type="button" onclick={cancel}>Cancel restore</button></div>{/if}
</section>
<style>
  .restore-flow { border: 1px solid var(--line-strong); background: var(--panel); padding: clamp(1rem, 3vw, 2rem); max-width: 42rem; }
  h2 { margin: .5rem 0 1.25rem; }
  ul { list-style: none; padding: 0; }
  li { display: flex; justify-content: space-between; flex-wrap: wrap; gap: .5rem; padding: .8rem 0; border-bottom: 1px solid var(--line); }
  li label { margin: 0; }
  small { color: var(--text-3); }
  .listing { display: block; margin: .5rem 0; text-align: left; }
  .actions { display: flex; gap: .75rem; margin: 1rem 0; }
  form { max-width: 30rem; }
</style>
