// Bundled bridge only. The page cannot supply its account, base, audience or
// window identity; the native session supplies the note ID, and native IPC
// derives the actual calling WebView. No web storage or remote content.
const invoke = window.__TAURI_INTERNALS__?.invoke;
if (invoke) {
  let boundNote = false, retryOpen;
  try {
    const binding = await invoke('note_binding');
    boundNote = Boolean(binding);
    if (binding) {
      const {note, surface} = binding;
      // A reload gives a different JS global and a new native binding.
      Object.defineProperty(window, '__bhNotePage', {value:surface, configurable:false});
      const { createNoteEditor } = await import('./note-editor.js');
      const main = document.querySelector('main');
      let release = () => {}, activeGeneration, peerListener = () => {};
      window.__bhNotePeers = message => peerListener(message);
      const host = {
        onPeers(callback) {peerListener=callback;return ()=>{peerListener=()=>{};};},
        async selection(anchor,head) {
          return invoke('note_selection',{generation:activeGeneration,surface,anchor,head});
        },
        async open(onUpdate) {
          // Listen before snapshot; deliveries occurring while IPC is in flight
          // stay buffered in the editor until its copy has applied the snapshot.
          let generation, sequence = 0, closed = false;
          const waiting = [];
          let waitingBytes=0, waitingOverflow=false;
          const receive = packet => {
            if (!packet || !Array.isArray(packet.update) || closed) return 'stale';
            if (generation === undefined) {
              if (waitingOverflow || waiting.length >= 256 || waitingBytes + packet.update.length > 256 * 1024) {
                // A fresh native open below obtains all committed bytes.
                waitingOverflow=true;waiting.length=0;waitingBytes=0;
                return 'failed';
              }
              waiting.push(packet);waitingBytes+=packet.update.length;
              return 'buffered';
            }
            if (packet.generation !== generation || packet.sequence <= sequence) return 'stale';
            try {
              // Both deltas and resyncs merge into the same live document.
              onUpdate(new Uint8Array(packet.update));
              sequence = packet.sequence;
              return 'accepted';
            } catch { return 'failed'; }
          };
          const incoming = event => receive(event.detail);
          window.__bhNoteDelivery = receive;
          window.addEventListener('bh-note-update', incoming);
          let opened;
          try {
            for (let snapshot = 0; snapshot < 3; snapshot++) {
              // Any earlier generation's buffered packets are already in the
              // durable snapshot being requested. Keep only its new arrivals.
              waiting.length=0;waitingBytes=0;waitingOverflow=false;
              for (let attempt = 0; attempt < 4; attempt++) {
                try { opened = await invoke('note_open', { note }); break; }
                catch (error) {
                  if (!String(error).includes('retry open') || attempt === 3) throw error;
                  await new Promise(resolve => setTimeout(resolve, 50 * (attempt + 1)));
                }
              }
              if (!waitingOverflow) break;
              if (snapshot === 2) throw new Error('note snapshot arrivals exceeded buffer');
            }
          } catch (error) {
            window.removeEventListener('bh-note-update', incoming);
            if (window.__bhNoteDelivery === receive) delete window.__bhNoteDelivery;
            throw error;
          }
          generation = opened.generation;
          activeGeneration = generation;
          sequence = opened.sequence;
          release = () => {
            if (closed) return;
            closed = true;
            window.removeEventListener('bh-note-update', incoming);
            if (window.__bhNoteDelivery === receive) delete window.__bhNoteDelivery;
            delete window.__bhNotePeers;
            void invoke('note_close', { generation }).catch(() => {});
          };
          // A pre-open packet reported as buffered is processed only after
          // snapshot acquisition. Failure here cannot leave an editable view
          // whose native sender already considered that packet delivered.
          for (const packet of waiting) {
            if (receive(packet) === 'failed') throw new Error('note update failed during open');
          }
          waiting.length = 0;waitingBytes=0;
          return {state:new Uint8Array(opened.state), unsubscribe:release};
        },
        async commit(update, requestId) {
          // A resolved matching requestId is the *only* source of Saved.
          return invoke('note_commit', { generation:activeGeneration, requestId, update:Array.from(update) });
        },
      };
      retryOpen = async () => {
        window.__bhNotePeers = message => peerListener(message);
        const root = document.createElement('section');
        root.setAttribute('aria-label', 'Note');
        try { await createNoteEditor(root, host); }
        catch (error) { release(); throw error; }
        main.replaceChildren(root);
        main.classList.add('note-workspace');
        document.querySelector('header strong').textContent = 'NOTE';
        document.querySelector('footer').textContent = 'LOCAL NOTE · DEVICE SAVE';
        window.addEventListener('pagehide', () => release(), {once:true});
      };
      await retryOpen();
    }
  } catch {
    if (boundNote) {
      // A bound but unavailable note is not an editable empty
      // document or another account's setup screen. No draft exists yet.
      const main=document.querySelector('main');
      const status=document.createElement('p');status.setAttribute('role','status');
      status.textContent='Note unavailable';
      const retry=document.createElement('button');retry.type='button';retry.textContent='Retry opening note';
      retry.addEventListener('click',async()=>{
        retry.disabled=true;
        try {await retryOpen();}
        catch {retry.disabled=false;}
      });
      main.replaceChildren(status,retry);
      document.querySelector('header strong').textContent='NOTE';
    }
    // With no native authority, leave the truthful setup screen intact.
  }
}
