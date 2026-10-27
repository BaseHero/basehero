<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../../lib/backend';
  import { BackendError, type BaseRef, type ObjectId, type ObjectVersion } from '../../lib/backend/types';
  import { errorMessage } from '../../lib/errors';
  import { staticHost, type NoteHost } from '../../lib/editor/host';
  import NoteEditor from '../NoteEditor.svelte';

  let { r, id }: { r: BaseRef; id: ObjectId } = $props();
  let versions = $state<ObjectVersion[]>([]);
  let more = $state(false);
  let selected = $state<number | null>(null);
  let preview = $state<NoteHost | null>(null);
  let confirming = $state(false);
  let loading = $state(false);
  let error = $state('');
  let generation = 0;

  async function load(before: number | null = null) {
    if (loading) return;
    loading = true;
    const current = generation;
    try {
      const page = await getBackend().versions(r, id, before);
      if (current !== generation) return;
      versions = before === null ? page.versions : [...versions, ...page.versions];
      more = page.more;
      error = '';
    } catch (cause) {
      if (current === generation) error = cause instanceof BackendError && cause.kind === 'Network'
        ? 'Version history needs a connection.' : errorMessage(cause);
    } finally { if (current === generation) loading = false; }
  }
  onMount(() => {
    void load();
    return () => { generation++; };
  });
  async function choose(version: ObjectVersion) {
    const current = ++generation;
    selected = version.seq;
    confirming = false;
    preview = null;
    try {
      const state = await getBackend().versionState(r, id, version.seq);
      if (current === generation) { preview = staticHost(state); error = ''; }
    } catch (cause) { if (current === generation) error = errorMessage(cause); }
  }
  async function restore() {
    if (selected === null) return;
    loading = true;
    try {
      await getBackend().versionRestore(r, id, selected);
      confirming = false;
      selected = null;
      preview = null;
      loading = false;
      await load();
    } catch (cause) { loading = false; error = errorMessage(cause); }
  }
  const date = (at: number) => new Date(at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
</script>
<section class="note-history" aria-label="Versions">
  <header><h2>Versions</h2></header>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if !error && !loading && versions.length === 0}<p>No earlier versions yet. BaseHero keeps one after you pause editing, at most hourly.</p>{/if}
  <ul>
    <li><button type="button" class:active={selected === null} onclick={() => { generation++; selected = null; preview = null; confirming = false; }}>Current</button></li>
    {#each versions as version (version.seq)}
      <li data-seq={version.seq}>
        <button type="button" class:active={selected === version.seq} onclick={() => choose(version)}>{date(version.at)} · {version.deviceName ?? 'Unknown device'}</button>
      </li>
    {/each}
  </ul>
  {#if more}<button type="button" disabled={loading} onclick={() => load(versions.at(-1)!.seq)}>Show older</button>{/if}
  {#if selected !== null && preview}
    {#key selected}
      <NoteEditor {r} {id} host={preview} readOnly={true} onnavigate={() => {}} onleave={() => () => {}} retryleave={() => {}} />
    {/key}
    {#if confirming}
      <p>Restore this version? The current text is kept as a version too, so you can switch back.</p>
      <button type="button" disabled={loading} onclick={restore}>Confirm restore</button>
      <button type="button" onclick={() => confirming = false}>Cancel</button>
    {:else}
      <button type="button" onclick={() => confirming = true}>Restore this version</button>
    {/if}
  {/if}
</section>
<style>
  .note-history { padding: .8rem; min-width: min(24rem, 85vw); }
  h2 { margin: 0; font-size: 1.1rem; }
  ul { list-style: none; padding: 0; margin: .7rem 0; }
  li { border-top: 1px solid var(--line); padding: .4rem 0; }
  li button { text-align: left; width: 100%; }
  .active { font-weight: 700; }
  .note-history :global(.note-pane > section) { padding: 1rem; }
</style>
