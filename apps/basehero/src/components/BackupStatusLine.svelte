<script lang="ts">
  import type { BackupStatus } from '../lib/backend/types';
  import { backupSize } from '../lib/backup-size';
  let { status, onnewkit }: { status: BackupStatus; onnewkit?: () => void } = $props();
  function ago(at: number): string {
    const minutes = Math.max(1, Math.round((Date.now() - at) / 60_000));
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
    const days = Math.round(hours / 24);
    return `${days} day${days === 1 ? '' : 's'} ago`;
  }
  let label = $derived(status.location?.label ?? 'your backup folder');
  let drive = $derived(label.split(' › ')[0]);
</script>
{#if status.enabled}
  <span class="backup-status" role="status">
    {#if status.problem?.kind === 'unreachable'}Backup paused: can't reach {label}. {status.lastRunAt === null ? 'No backup yet.' : `Last backup ${ago(status.lastRunAt)}.`}
    {:else if status.problem?.kind === 'permissionLost'}Choose the backup folder again.
    {:else if status.problem?.kind === 'full'}Backup paused: {drive} is full.
    {:else if status.problem?.kind === 'usingLastChecked'}Backup is using the sign-in details it last confirmed.
    {:else if status.problem?.kind === 'noKitRecord'}Make a new recovery kit so your backup can be checked.
    {:else if status.lastRunAt !== null}Backed up {ago(status.lastRunAt)}, {backupSize(status.bytes)} in {label}
    {:else}Backup has not finished yet in {label}.
    {/if}
  </span>
  {#if status.problem?.kind === 'noKitRecord' && onnewkit}<button type="button" onclick={onnewkit}>Make a new kit</button>{/if}
{:else}<span class="backup-status">Backup is off.</span>{/if}
<style>
  .backup-status { font: .78rem/1.5 var(--mono); color: var(--text-2); }
</style>
