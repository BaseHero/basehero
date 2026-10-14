// Bundled bridge only. The page cannot supply its account, base, audience or
// window identity; the native session supplies the note ID, and native IPC
// derives the actual calling WebView. No web storage or remote content.
const invoke = window.__TAURI_INTERNALS__?.invoke;
if (invoke) {
  try {
    const note = await invoke('note_binding');
    if (note) {
      const { createNoteEditor } = await import('./note-editor.js');
      const main = document.querySelector('main');
      let release = () => {}, activeGeneration;
      const host = {
        async open(onUpdate) {
          // Listen before snapshot; deliveries occurring while IPC is in flight
          // stay buffered in the editor until its copy has applied the snapshot.
          let generation, sequence = 0, closed = false;
          const waiting = [];
          const incoming = event => {
            const packet = event.detail;
            if (!packet || !Array.isArray(packet.update)) return;
            if (generation === undefined) { waiting.push(packet); return; }
            if (!closed && packet.generation === generation && packet.sequence > sequence) {
              sequence = packet.sequence;
              onUpdate(new Uint8Array(packet.update));
            }
          };
          window.addEventListener('bh-note-update', incoming);
          let opened;
          try { opened = await invoke('note_open', { note }); }
          catch (error) { window.removeEventListener('bh-note-update', incoming); throw error; }
          generation = opened.generation;
          activeGeneration = generation;
          sequence = opened.sequence;
          for (const packet of waiting) incoming({detail:packet});
          waiting.length = 0;
          release = () => {
            if (closed) return;
            closed = true;
            window.removeEventListener('bh-note-update', incoming);
            void invoke('note_close', { generation }).catch(() => {});
          };
          return {state:new Uint8Array(opened.state), unsubscribe:release};
        },
        async commit(update, requestId) {
          // A resolved matching requestId is the *only* source of Saved.
          return invoke('note_commit', { generation:activeGeneration, requestId, update:Array.from(update) });
        },
      };
      const root = document.createElement('section');
      root.setAttribute('aria-label', 'Note');
      try {
        await createNoteEditor(root, host);
      } catch (error) { release(); throw error; }
      main.replaceChildren(root);
      main.classList.add('note-workspace');
      document.querySelector('header strong').textContent = 'NOTE';
      document.querySelector('footer').textContent = 'LOCAL NOTE · DEVICE SAVE';
      window.addEventListener('pagehide', () => release(), {once:true});
    }
  } catch {
    // No usable native session: leave the truthful setup screen intact.
  }
}
