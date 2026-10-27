<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import { BackendError, type BaseRef, type ObjectId } from '../lib/backend/types';
  import { createNoteEditor } from '../lib/editor/editor.mjs';
  import { noteHost, trackEditor } from '../lib/editor/host';
  import '../lib/editor/editor.css';

  let { r, id, readOnly, onnavigate, onleave, retryleave }: {
    r: BaseRef; id: ObjectId; readOnly: boolean;
    onnavigate: (r: BaseRef, id: ObjectId) => void;
    onleave: (leave: () => Promise<boolean>) => () => void;
    retryleave: () => void;
  } = $props();
  let root: HTMLElement;
  let error = $state('');
  onMount(() => {
    let cancelled = false;
    let stop = () => {};
    let editor: Awaited<ReturnType<typeof createNoteEditor>> | undefined;
    const host = noteHost(getBackend(), r, id);
    const opening = createNoteEditor(root, host, {
      baseId: r.base,
      get readOnly() { return readOnly || host.readOnly; },
      navigate: (base: string, note: string) => onnavigate({ account: r.account, base }, note),
    }).then(opened => {
      editor = opened;
      stop = trackEditor(opened);
      if (cancelled) {
        void opened.drain(Date.now() + 30_000).then(saved => { if (saved) { stop(); opened.close(); } });
      }
      return opened;
    });
    void opening.catch(e => {
      error = e instanceof BackendError && e.kind === 'NeedsUpdate'
        ? 'This note needs a newer version of BaseHero. Update the app to open it.'
        : String(e);
    });
    const unregister = onleave(async () => {
      // An unsuccessful open has no session or edits to drain. The visible
      // open error stays until leaving, but must not trap navigation.
      let opened: Awaited<typeof opening>;
      try { opened = await opening; }
      catch { return true; }
      try {
        if (!await opened.drain(Date.now() + 30_000)) {
          opened.resume();
          error = 'Could not save note before leaving.';
          return false;
        }
        stop(); opened.close(); editor = undefined;
        error = '';
        return true;
      } catch (e) {
        error = `Could not save note before leaving: ${String(e)}`;
        return false;
      }
    });
    return () => {
      unregister();
      cancelled = true;
      if (editor) {
        const closing = editor;
        void closing.drain(Date.now() + 30_000).then(saved => {
          if (saved) { stop(); closing.close(); }
        });
      }
    };
  });
</script>

<div class="note-pane"><section bind:this={root} aria-label="Note editor"></section></div>
{#if error}<p role="alert">{error}</p><button type="button" onclick={retryleave}>Retry leaving note</button>{/if}
