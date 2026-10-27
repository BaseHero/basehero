<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { BaseRef, ObjectId, ObjectSummary, ItemKind } from '../lib/backend/types';
  import { errorMessage } from '../lib/errors';
  import { TreeModel, itemKind } from '../lib/tree.svelte';
  import Tree from '../components/Tree.svelte';
  import LocationBar from '../components/LocationBar.svelte';
  import MoveDialog from '../components/MoveDialog.svelte';
  import Trash from '../components/Trash.svelte';
  import NoteFiles from '../components/hooks/NoteFiles.svelte';
  import NoteHistory from '../components/hooks/NoteHistory.svelte';
  import NoteEditor from '../components/NoteEditor.svelte';
  import HeroPanel from '../lib/hero/HeroPanel.svelte';

  let { r, id, onleave, retryleave }: { r: BaseRef; id: ObjectId | null; onleave: (hook: () => Promise<boolean>) => () => void; retryleave: () => void } = $props();
  const model = untrack(() => new TreeModel(r));
  let baseName = $state('Base');
  let hidden = $state(false);
  let drawer = $state(false);
  let heroOpen = $state(false);
  let menu = $state<ObjectSummary | null>(null);
  let noteMenu = $state(false);
  let move = $state<ObjectSummary | null>(null);
  let renaming = $state<ObjectSummary | null>(null);
  let newName = $state('');
  let revision = $state(0);
  let trashOpen = $state(false);
  let creating = $state<ItemKind | null>(null);
  let name = $state('');
  let error = $state('');
  let mac = $state(false);
  let current = $state<ObjectSummary | null>(null);
  let project = $state<ObjectId | null>(null);
  $effect(() => {
    const selected = id;
    let active = true;
    const load = async () => {
      let item = selected ? await getBackend().getObject(r, selected) : null;
      if (active) current = item;
      let projectId: ObjectId | null = null;
      const seen = new Set<string>();
      while (item && !seen.has(item.id)) {
        seen.add(item.id);
        if (itemKind(item) === 'core.project') { projectId = item.id; break; }
        item = item.parent ? await getBackend().getObject(r, item.parent) : null;
      }
      if (active) project = projectId;
    };
    void load();
    return () => { active = false; };
  });
  onMount(() => {
    let active = true;
    void getBackend().bases(r.account).then(bases => { if (active) { const base = bases.find(base => base.id === r.base); baseName = base?.name ?? 'Base'; hidden = base?.hidden ?? false; } }).catch(e => error = errorMessage(e));
    void getBackend().appInfo().then(info => { if (active) mac = info.platform === 'macos'; });
    void model.expand(null).catch(e => error = errorMessage(e));
    let unsubscribe = () => {};
    void getBackend().onEvent(event => {
      if ((event.kind !== 'base' && event.kind !== 'Base') || event.account !== r.account || event.base !== r.base) return;
      const change = event.event as { kind?: string; ids?: string[]; objectsChanged?: string[]; ObjectsChanged?: { ids?: string[] } | string[] };
      const ids = change.objectsChanged ?? (Array.isArray(change.ObjectsChanged) ? change.ObjectsChanged : change.ObjectsChanged?.ids) ?? (change.kind === 'ObjectsChanged' ? change.ids : undefined);
      if (ids?.length) void model.refresh(ids).catch(e => error = errorMessage(e));
    }).then(stop => { if (active) unsubscribe = stop; else stop(); });
    return () => { active = false; unsubscribe(); };
  });
  function open(id: ObjectId | null) {
    drawer = false; menu = null; noteMenu = false; trashOpen = false;
    location.hash = id ? `#/a/${r.account}/b/${r.base}/n/${id}` : `#/a/${r.account}/b/${r.base}`;
  }
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!creating) return;
    try {
      const parent = creating === 'project' ? null : id;
      const created = await getBackend().createObject(r, { kind: creating, name: name.trim(), parent, after: null });
      await model.refresh([created]);
      if (parent) await model.expand(parent);
      creating = null; name = '';
    } catch (cause) { error = errorMessage(cause); }
  }
  async function doMove(parent: ObjectId | null) {
    if (!move) return;
    try { const id = move.id; await getBackend().moveObject(r, id, parent, null); await model.refresh([id]); move = null; menu = null; }
    catch (cause) { error = errorMessage(cause); }
  }
  function startRename() {
    if (!menu) return;
    renaming = menu;
    newName = menu.title;
    menu = null;
  }
  async function rename(event: SubmitEvent) {
    event.preventDefault();
    if (!renaming || !newName.trim()) return;
    try {
      const target = renaming.id;
      await getBackend().renameObject(r, target, newName.trim());
      await model.refresh([target]);
      if (id === target) { current = await getBackend().getObject(r, target); revision++; }
      renaming = null;
      menu = null;
    } catch (cause) { error = errorMessage(cause); }
  }
  async function remove() {
    if (!menu) return;
    try { const target = menu.id; await getBackend().deleteObject(r, target); await model.refresh([target]); menu = null; if (target === id) open(null); }
    catch (cause) { error = errorMessage(cause); }
  }
  async function restore(target: ObjectId) {
    await getBackend().restoreObject(r, target);
    await model.refresh([target]);
  }
</script>
<main class="base-shell">
  <header class="base-header">
    <button aria-label="Open tree" class="drawer-button" onclick={() => drawer = !drawer}>☰</button>
    <h1>{baseName}</h1>
    <a href={`#/a/${r.account}`}>Bases</a>
  </header>
  {#if error}<p role="alert">{error}</p>{/if}
  <div class="base-layout">
    <aside class:drawer-open={drawer} class="tree-panel">
      <div class="tree-heading"><span class="eyebrow">CONTENT</span><button class="close-drawer" onclick={() => drawer = false}>Close tree</button></div>
      <div class="tree-actions">
        <button onclick={() => { creating = 'folder'; name = ''; }}>New folder</button>
        <button onclick={() => { creating = 'project'; name = ''; }}>New project</button>
        <button onclick={() => { creating = 'note'; name = ''; }}>New note</button>
      </div>
      {#if creating}
        <form class="create-item" onsubmit={create}><label>Name<input bind:value={name} required /></label><button class="primary" type="submit">Create</button><button type="button" onclick={() => creating = null}>Cancel</button></form>
      {/if}
      <Tree {model} {mac} onopen={open} onmenu={item => { menu = item; noteMenu = false; }} onnewwindow={note => {
        void getBackend().openWindow(`#/a/${r.account}/b/${r.base}/n/${note}`).catch(cause => error = errorMessage(cause));
      }} />
      <button onclick={() => trashOpen = !trashOpen}>Trash</button>
    </aside>
    <section class="content-panel">
      <LocationBar {r} {baseName} {hidden} {id} {revision} onopen={open} />
      {#if menu}<div class="item-menu"><span>{menu.title}</span><button onclick={startRename}>Rename</button><button onclick={() => { move = menu; menu = null; }}>Move to…</button><button onclick={remove}>Delete</button><button onclick={() => menu = null}>Close menu</button></div>{/if}
      {#if renaming}<form onsubmit={rename}><label>New name <input bind:value={newName} required /></label><button type="submit">Save name</button><button type="button" onclick={() => renaming = null}>Cancel</button></form>{/if}
      {#if move}<MoveDialog {r} item={move} onmove={doMove} onclose={() => move = null} />{/if}
      {#if trashOpen}<Trash {r} onrestore={restore} onclose={() => trashOpen = false} />{/if}
      {#if id}
        <div class="note-area">
          <div class="note-content">
            <button aria-label="Note options" onclick={() => noteMenu = !noteMenu}>⋯</button>
            {#if noteMenu}<div class="item-menu"><NoteFiles {r} {id} /><NoteHistory {r} {id} /></div>{/if}
            {#key id}<NoteEditor {r} {id} readOnly={false} onnavigate={(ref, target) => { if (ref.account === r.account) location.hash = `#/a/${ref.account}/b/${ref.base}/n/${target}`; }} {onleave} {retryleave} />{/key}
          </div>
          <div class:hero-open={heroOpen} class="hero-container">
            <button class="hero-close" onclick={() => heroOpen = false}>Close Hero</button>
            <HeroPanel account={r.account} base={r.base} focus={id} {project} />
          </div>
          <button class="hero-toggle" aria-expanded={heroOpen} onclick={() => heroOpen = !heroOpen}>Hero</button>
        </div>
      {:else}
        <p>Select a note, folder or project, or create one to start.</p>
      {/if}
    </section>
  </div>
</main>
