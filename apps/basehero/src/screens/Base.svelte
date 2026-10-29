<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { BaseRef, ObjectId, ObjectSummary, TreeItem, Mount, ItemKind } from '../lib/backend/types';
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

  let { r, id, filesOpen, onleave, retryleave }: { r: BaseRef; id: ObjectId | null; filesOpen: boolean; onleave: (hook: () => Promise<boolean>) => () => void; retryleave: () => void } = $props();
  let root = $state<BaseRef>(untrack(() => r));
  let model = $state(untrack(() => new TreeModel(r)));
  let mounts = $state<Mount[]>([]);
  let family = $state<string[]>(untrack(() => [r.base]));
  let baseName = $state('Base');
  let hidden = $state(false);
  let drawer = $state(false);
  let heroOpen = $state(false);
  let menu = $state<TreeItem | null>(null);
  let noteMenu = $state(false);
  $effect(() => { if (filesOpen) noteMenu = true; });
  let move = $state<TreeItem | null>(null);
  let renaming = $state<TreeItem | null>(null);
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
  $effect(() => {
    const selected = id;
    const account = r.account;
    const source = r.base;
    const tree = model;
    const outer = root.base;
    const knownMounts = mounts;
    let active = true;
    if (selected) void getBackend().locate({ account, base: source }, selected).then(located => {
      if (!active) return;
      if (located !== source) {
        // Replace the stale route rather than opening the moved item's marker.
        history.replaceState(null, '', `${location.pathname}${location.search}#/a/${account}/b/${located}/n/${selected}`);
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      } else if (tree.r.base === outer) {
        void tree.reveal(located, selected, knownMounts).catch(cause => error = errorMessage(cause));
      }
    }).catch(cause => { if (active) error = errorMessage(cause); });
    return () => { active = false; };
  });
  async function updateFamily() {
    const bases = await getBackend().bases(r.account);
    const byId = new Map(bases.map(base => [base.id, base]));
    let outer = r.base;
    const seen = new Set<string>();
    while (byId.get(outer)?.mount && !seen.has(outer)) {
      seen.add(outer);
      outer = byId.get(outer)!.mount!.parent;
    }
    const descendants = new Set([outer]);
    for (let changed = true; changed;) {
      changed = false;
      for (const base of bases) if (base.mount && descendants.has(base.mount.parent) && !descendants.has(base.id)) {
        descendants.add(base.id); changed = true;
      }
    }
    mounts = bases.flatMap(base => base.mount ? [base.mount] : []);
    family = [...descendants];
    root = { account: r.account, base: outer };
    baseName = byId.get(outer)?.name ?? 'Base';
    hidden = byId.get(outer)?.hidden ?? false;
    if (model.r.base !== outer) model = new TreeModel(root);
    await model.expand(outer, null);
  }
  onMount(() => {
    let active = true;
    const account = r.account;
    void updateFamily().catch(e => error = errorMessage(e));
    void getBackend().appInfo().then(info => { if (active) mac = info.platform === 'macos'; });

    let unsubscribe = () => {};
    void getBackend().onEvent(event => {
      if (event.account !== account) return;
      if (event.kind.toLowerCase() === 'account') {
        if (event.event === 'BasesChanged' || (typeof event.event === 'object' && event.event !== null && 'BasesChanged' in event.event)) void updateFamily().catch(e => error = errorMessage(e));
        return;
      }
      if (event.kind.toLowerCase() !== 'base' || !event.base || !family.includes(event.base)) return;
      void updateFamily().then(() => model.refresh()).catch(e => error = errorMessage(e));
    }).then(stop => { if (active) unsubscribe = stop; else stop(); });
    return () => { active = false; unsubscribe(); };
  });
  function open(id: ObjectId | null, base = root.base) {
    drawer = false; menu = null; noteMenu = false; trashOpen = false;
    location.hash = id ? `#/a/${r.account}/b/${base}/n/${id}` : `#/a/${r.account}/b/${base}`;
  }
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!creating) return;
    try {
      const selected = creating === 'project' ? null : id;
      const mount = mounts.find(mount => mount.parent === r.base && mount.folder === selected);
      const parent = mount ? null : selected;
      const target = mount ? { account: r.account, base: mount.base } : parent ? r : root;
      const created = await getBackend().createObject(target, { kind: creating, name: name.trim(), parent, after: null });
      await model.refresh();
      if (selected) await model.expand(r.base, selected);
      creating = null; name = '';
    } catch (cause) { error = errorMessage(cause); }
  }
  async function doMove(base: string, parent: ObjectId | null) {
    if (!move) return;
    try {
      const source = move;
      await getBackend().moveObject({ account: r.account, base: source.base }, source.id, base, parent, null);
      await model.refresh();
      if (id === source.id && r.base !== base) open(id, base);
      move = null; menu = null;
    } catch (cause) { error = errorMessage(cause); }
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
      await getBackend().renameObject({ account: r.account, base: renaming.base }, target, newName.trim());
      await model.refresh();
      if (id === target) { current = await getBackend().getObject(r, target); revision++; }
      renaming = null;
      menu = null;
    } catch (cause) { error = errorMessage(cause); }
  }
  async function remove() {
    if (!menu) return;
    try { const target = menu.id; await getBackend().deleteObject({ account: r.account, base: menu.base }, target); await model.refresh(); menu = null; if (target === id) open(null); }
    catch (cause) { error = errorMessage(cause); }
  }
  async function restore(item: TreeItem) {
    await getBackend().restoreObject({ account: r.account, base: item.base }, item.id);
    await model.refresh();
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
      <Tree {model} {mac} onopen={item => open(item.id, item.base)} onmenu={item => { menu = item; noteMenu = false; }} onnewwindow={note => {
        void getBackend().openWindow(`#/a/${r.account}/b/${note.base}/n/${note.id}`).catch(cause => error = errorMessage(cause));
      }} />
      <button onclick={() => trashOpen = !trashOpen}>Trash</button>
    </aside>
    <section class="content-panel">
      <LocationBar {r} {root} {mounts} {baseName} {hidden} {id} {revision} onopen={open} />
      {#if menu}<div class="item-menu"><span>{menu.title}</span><button onclick={startRename}>Rename</button><button onclick={() => { move = menu; menu = null; }}>Move to…</button><button onclick={remove}>Delete</button><button onclick={() => menu = null}>Close menu</button></div>{/if}
      {#if renaming}<form onsubmit={rename}><label>New name <input bind:value={newName} required /></label><button type="submit">Save name</button><button type="button" onclick={() => renaming = null}>Cancel</button></form>{/if}
      {#if move}<MoveDialog r={root} item={move} onmove={doMove} onclose={() => move = null} />{/if}
      {#if trashOpen}<Trash r={root} onrestore={restore} onclose={() => trashOpen = false} />{/if}
      {#if id}
        {@const mounted = mounts.find(mount => mount.parent === r.base && mount.folder === id)?.base ?? null}
        <div class="note-area">
          <div class="note-content">
            <button aria-label="Note options" onclick={() => noteMenu = !noteMenu}>⋯</button>
            {#if noteMenu}<div class="item-menu"><NoteFiles {r} {id} {mounted} /><NoteHistory {r} {id} {mounted} /></div>{/if}
            {#key `${r.base}:${id}:${mounted ?? ''}`}<NoteEditor {r} {id} {mounted} readOnly={false} onnavigate={(ref, target) => { if (ref.account === r.account) location.hash = `#/a/${ref.account}/b/${ref.base}/n/${target}`; }} {onleave} {retryleave} />{/key}
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
