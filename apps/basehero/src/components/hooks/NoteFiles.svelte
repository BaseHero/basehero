<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../../lib/backend';
  import type { BaseRef, FileInfo, FileStatus, ObjectId } from '../../lib/backend/types';
  import { errorMessage } from '../../lib/errors';

  let { r, id }: { r: BaseRef; id: ObjectId } = $props();
  let files = $state<FileInfo[]>([]);
  let error = $state('');
  let picker: HTMLInputElement;
  let busy = $state(false);
  let generation = 0;
  async function refresh() {
    const current = ++generation;
    try {
      const listed = await getBackend().files(r, id);
      if (current === generation) { files = listed; error = ''; }
    } catch (cause) { if (current === generation) error = errorMessage(cause); }
  }
  onMount(() => {
    let active = true;
    void refresh();
    let stop = () => {};
    void getBackend().onEvent(event => {
      if (!active || (event.kind !== 'base' && event.kind !== 'Base') || event.account !== r.account || event.base !== r.base) return;
      const change = event.event as { filesChanged?: string[]; FilesChanged?: string[]; objectsChanged?: string[]; ObjectsChanged?: string[] };
      if (change?.filesChanged || change?.FilesChanged || change?.objectsChanged || change?.ObjectsChanged) void refresh();
    }).then(unsubscribe => { if (active) stop = unsubscribe; else unsubscribe(); });
    return () => { active = false; generation++; stop(); };
  });
  function size(bytes: number) {
    if (bytes < 1000) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let value = bytes;
    let unit = '';
    for (const next of units) { value /= 1000; unit = next; if (value < 1000) break; }
    return `${value.toFixed(1)} ${unit}`;
  }
  function status(file: FileInfo, state: FileStatus = file.status): string {
    switch (state.kind) {
      case 'here': return size(file.size);
      case 'sending': return `Uploading ${state.done} of ${state.parts}`;
      case 'fetching': return `Downloading ${state.done} of ${state.parts}`;
      case 'remote': return 'Not on this device';
      case 'waiting': return 'Waiting for the device that added it';
      case 'broken': return "Can't open this file";
    }
  }
  async function add(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const chosen = [...(input.files ?? [])];
    input.value = '';
    busy = true;
    for (const file of chosen) {
      try {
        await getBackend().fileAdd(r, id, file.name, file.type || 'application/octet-stream', new Uint8Array(await file.arrayBuffer()));
        await refresh();
      } catch (cause) { error = errorMessage(cause); }
    }
    busy = false;
  }
  async function open(file: FileInfo) {
    try { error = ''; await getBackend().fileOpen(r, file.id); await refresh(); }
    catch (cause) { error = errorMessage(cause); await refresh(); }
  }
  async function remove(file: FileInfo) {
    try { await getBackend().deleteObject(r, file.id); await refresh(); }
    catch (cause) { error = errorMessage(cause); }
  }
</script>
<section class="note-files" aria-label="Files">
  <header><h2>Files</h2><button type="button" disabled={busy} onclick={() => picker.click()}>Add file</button></header>
  <input bind:this={picker} aria-label="Add file" type="file" multiple hidden onchange={add} />
  {#if error}<p role="alert">{error}</p>{/if}
  {#if files.length === 0}<p>No files in this note.</p>{/if}
  <ul>{#each files as file (file.id)}
    <li><span class="file-name">{file.name}</span><small>{status(file)}</small>
      <button type="button" onclick={() => open(file)}>Open</button>
      <button type="button" onclick={() => remove(file)}>Delete</button></li>
  {/each}</ul>
</section>
<style>
  .note-files { padding: .8rem; min-width: min(24rem, 85vw); }
  header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  h2 { margin: 0; font-size: 1.1rem; }
  ul { list-style: none; padding: 0; margin: .7rem 0 0; }
  li { display: flex; align-items: center; gap: .6rem; border-top: 1px solid var(--line); padding: .6rem 0; flex-wrap: wrap; }
  .file-name { overflow-wrap: anywhere; flex: 1; min-width: 7rem; }
  small { color: var(--text-3); }
</style>
