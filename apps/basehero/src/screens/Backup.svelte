<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import { backupSize } from '../lib/backup-size';
  import type { BackupLocation, BackupStatus } from '../lib/backend/types';
  import BackupStatusLine from '../components/BackupStatusLine.svelte';
  import RestoreFlow from '../components/RestoreFlow.svelte';
  let { account, platform, status, onrefresh, onnewkit }: { account: string; platform: string; status: BackupStatus | null; onrefresh: () => Promise<void>; onnewkit: () => void } = $props();
  let candidate = $state<BackupLocation | null>(null);
  let estimate = $state(0);
  let restoring = $state(false);
  let busy = $state(false);
  let error = $state('');
  $effect(() => { account; void onrefresh(); });
  async function change() {
    if (busy) return;
    busy = true; error = '';
    try {
      const folder = await getBackend().pickBackupFolder();
      if (!folder) return;
      if (platform === 'android') {
        candidate = folder;
        estimate = await getBackend().backupEstimate(account);
      } else {
        await getBackend().setBackup(account, folder);
        await onrefresh();
      }
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function start() {
    if (!candidate || busy) return;
    busy = true; error = '';
    try {
      await getBackend().setBackup(account, candidate);
      candidate = null;
      await getBackend().backupNow(account);
      await onrefresh();
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function off() {
    error = '';
    try { await getBackend().setBackup(account, null); await onrefresh(); }
    catch (cause) { error = errorMessage(cause); }
  }
</script>
<main class="workspace backup-screen">
  <span class="eyebrow">ACCOUNT / BACKUP</span><h1>Backup</h1>
  {#if error}<p role="alert" class="error">{error}</p>{/if}
  {#if restoring}
    <RestoreFlow {account} deviceName={platform === 'android' ? 'Android' : 'Mac'} oncancel={() => { restoring = false; void onrefresh(); }} />
  {:else if candidate}
    <section class="panel"><p>This will write about {backupSize(estimate)} to {candidate.label}</p>
      <div class="actions"><button type="button" class="primary" disabled={busy} onclick={start}>Start</button><button type="button" onclick={() => candidate = null}>Cancel</button></div>
    </section>
  {:else}
    <section class="panel">
      {#if status}<p><BackupStatusLine {status} {onnewkit} /></p>{/if}
      {#if platform === 'android' && !status?.enabled}<p>Choose a folder, perhaps one named BaseHero, on your phone or drive.</p>{/if}
      <div class="actions">
        <button type="button" disabled={busy} onclick={change}>{status?.enabled ? 'Change folder…' : 'Back up to a folder…'}</button>
        <button type="button" onclick={() => restoring = true}>Restore…</button>
        {#if status?.enabled}<button type="button" onclick={off}>Off</button>{/if}
      </div>
    </section>
  {/if}
</main>
<style>
  h1 { margin: .4rem 0 1.5rem; }
  .panel { border: 1px solid var(--line-strong); padding: 1.5rem; background: var(--panel); }
  .actions { display: flex; gap: .65rem; flex-wrap: wrap; margin-top: 1rem; }
</style>
