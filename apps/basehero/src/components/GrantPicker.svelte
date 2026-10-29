<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { AccountId, BaseChoiceInput, BaseSummary, TreeItem } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import { itemKind } from '../lib/tree.svelte';

  let { account, onpick, oncancel }: {
    account: AccountId;
    onpick: (choice: BaseChoiceInput, label: string) => void;
    oncancel: () => void;
  } = $props();
  let bases = $state<BaseSummary[]>([]);
  let baseId = $state('');
  let folders = $state<{ item: TreeItem; depth: number }[]>([]);
  let folderId = $state('');
  let newBaseName = $state('');
  let newFolderName = $state('');
  let mode = $state<'readWrite' | 'readOnly'>('readWrite');
  let busy = $state(false);
  let error = $state('');
  onMount(() => {
    let active = true;
    void getBackend().bases(account).then(list => {
      if (!active) return;
      bases = list.filter(base => !base.hidden && !base.mount);
      baseId = bases[0]?.id ?? 'new';
    }).catch(cause => { if (active) error = errorMessage(cause); });
    return () => { active = false; };
  });
  async function loadFolders(base: string) {
    const rows: { item: TreeItem; depth: number }[] = [];
    async function visit(currentBase: string, parent: string | null, depth: number) {
      for (const item of await getBackend().treeChildren({ account, base: currentBase }, parent)) {
        if (itemKind(item) !== 'core.folder' && itemKind(item) !== 'core.project') continue;
        rows.push({ item, depth });
        await visit(item.base, item.id, depth + 1);
      }
    }
    await visit(base, null, 0);
    if (baseId === base) folders = rows;
  }
  $effect(() => {
    const base = baseId;
    folders = []; folderId = '';
    if (base && base !== 'new') void loadFolders(base).catch(cause => error = errorMessage(cause));
  });
  async function createBase() {
    if (!newBaseName.trim() || busy) return;
    busy = true; error = '';
    try {
      const base = await getBackend().createBase(account, newBaseName.trim());
      bases = [...bases, base]; baseId = base.id; newBaseName = '';
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  async function createFolder() {
    if (!newFolderName.trim() || busy) return;
    busy = true; error = '';
    try {
      const parent = folders.find(row => row.item.id === folderId)?.item;
      if (folderId && !parent) return;
      const base = parent?.mounted ?? parent?.base ?? baseId;
      const id = await getBackend().createObject({ account, base }, {
        kind: 'folder', parent: parent?.mounted ? null : (parent?.id ?? null), after: null, name: newFolderName.trim(),
      });
      await loadFolders(baseId);
      folderId = id; newFolderName = '';
    } catch (cause) { error = errorMessage(cause); }
    finally { busy = false; }
  }
  function pick() {
    const base = bases.find(base => base.id === baseId);
    if (!base || busy) return;
    const folder = folders.find(row => row.item.id === folderId)?.item;
    if (folderId && !folder) return;
    if (!folder) onpick({ base: base.id, mode }, base.name);
    else onpick(folder.mounted
      ? { base: folder.mounted, mode }
      : { base: folder.base, folder: folder.id, mode }, `${folder.title} in ${base.name}`);
  }
</script>
<div class="grant-picker">
  <label>Base
    <select aria-label="Base" bind:value={baseId} disabled={busy}>
      {#each bases as base (base.id)}<option value={base.id}>{base.name}</option>{/each}
      <option value="new">New base</option>
    </select>
  </label>
  {#if baseId === 'new'}
    <div>
      <label>New base name<input bind:value={newBaseName} /></label>
      <button type="button" disabled={busy || !newBaseName.trim()} onclick={createBase}>Create base</button>
    </div>
  {:else if baseId}
    <fieldset><legend>Folder</legend>
      <label class="folder-choice"><input type="radio" name="folder" value="" bind:group={folderId} />Whole base</label>
      {#each folders as { item, depth } (item.id)}
        <label class="folder-choice" style:padding-left={`${depth + 1}rem`}>
          <input type="radio" name="folder" value={item.id} bind:group={folderId} />{item.title}
        </label>
      {/each}
    </fieldset>
    <div>
      <label>New folder name<input bind:value={newFolderName} /></label>
      <button type="button" disabled={busy || !newFolderName.trim()} onclick={createFolder}>Create folder</button>
    </div>
    <label>Access
      <select aria-label="Access" bind:value={mode}><option value="readWrite">Read-write</option><option value="readOnly">Read-only</option></select>
    </label>
  {/if}
  <div class="actions"><button type="button" disabled={busy || !baseId || baseId === 'new' || (folderId !== '' && !folders.some(row => row.item.id === folderId))} onclick={pick}>Add</button><button type="button" onclick={oncancel}>Cancel</button></div>
  {#if error}<p role="alert">{error}</p>{/if}
</div>
<style>
  .grant-picker { max-width: 28rem; padding: 1rem; border: 1px solid var(--line); border-radius: .5rem; }
  fieldset { border: 0; padding: .5rem 0; margin: .5rem 0; }
  .folder-choice { display: flex; align-items: center; gap: .5rem; margin: .4rem 0; }
  .folder-choice input { width: auto; margin: 0; }
</style>
