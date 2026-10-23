// Bundled bridge only. The page cannot supply its account, base, audience or
// window identity; the native session supplies the note ID, and native IPC
// derives the actual calling WebView. No web storage or remote content.
import { pairingButton, syncLine } from './pairing.js';
import { devicesButton, openDevices } from './devices.js';
const invoke = window.__TAURI_INTERNALS__?.invoke;
if (invoke) {
  let boundNote = false, retryOpen, currentPage, currentNote, editor, closeLoad = () => {};
  let navigating = false, catalogueVersion = 0, catalogueTimer;
  Object.defineProperty(window, '__bhNotePage', {get:()=>currentPage, configurable:false});
  const main = document.querySelector('main');
  const html = document.documentElement;
  const mac = /Mac|iP(hone|[oa]d)/.test(navigator.platform);
  const icon = (...paths) => {
    const node=document.createElementNS('http://www.w3.org/2000/svg','svg');
    node.setAttribute('viewBox','0 0 16 16');node.setAttribute('aria-hidden','true');node.setAttribute('class','i');
    for (const d of paths) {const path=document.createElementNS('http://www.w3.org/2000/svg','path');path.setAttribute('d',d);node.append(path);}
    return node;
  };
  // The notes list: a sidebar beside the page, or over it in a narrow window.
  const side = document.createElement('aside');side.id='notes-side';side.className='side';side.setAttribute('aria-label','Notes');
  const sideHead = document.createElement('p');sideHead.className='side-head label';sideHead.textContent='Notes';
  const nav = document.createElement('nav');nav.setAttribute('aria-label','Notes');
  nav.className='note-list';
  side.append(sideHead,nav);
  const scrim = document.createElement('div');scrim.className='scrim';
  const notePane = document.createElement('article');notePane.className='note-pane';
  const notice = document.createElement('p');notice.className='note-notice';notice.setAttribute('role','alert');notice.hidden=true;
  const tools = document.createElement('span');tools.className='bar-tools';
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const here = document.querySelector('header strong');
  const say = text => {notice.textContent=text;notice.hidden=!text;};
  const sameNote = (a,b) => JSON.stringify(a)===JSON.stringify(b);
  const button = (text, action) => {
    const node=document.createElement('button');node.type='button';node.textContent=text;
    node.addEventListener('click',()=>void action());return node;
  };
  const iconButton = (label, keys, glyph, action) => {
    const node=document.createElement('button');node.type='button';node.className='ib';
    node.setAttribute('aria-label',label);node.title=`${label} (${mac?keys[0]:keys[1]})`;node.append(glyph);
    node.addEventListener('click',()=>void action());return node;
  };
  // The open note's literal title names the window in its bar.
  let currentTitle = '';
  const showTitle = title => {currentTitle=title;here.textContent=title;};
  // Shown or hidden per window; the last choice is remembered natively for
  // the next window. A narrow window's overlay is never remembered.
  const narrow = matchMedia('(max-width: 640px)');
  let sidebarShown = true, overlayOpen = false, workspace = false;
  const sidebarVisible = () => narrow.matches ? overlayOpen : sidebarShown;
  const drawSidebar = () => {
    html.dataset.sidebar = sidebarVisible() ? 'shown' : 'hidden';
    sidebarToggle.setAttribute('aria-expanded', String(sidebarVisible()));
  };
  const setSidebar = shown => {
    if (narrow.matches) overlayOpen = shown;
    else if (shown !== sidebarShown) {
      sidebarShown = shown;
      invoke('window_sidebar',{shown}).catch(() => {});
    }
    drawSidebar();
  };
  narrow.addEventListener('change',()=>{overlayOpen=false;drawSidebar();});
  sidebarToggle.addEventListener('click',()=>setSidebar(!sidebarVisible()));
  scrim.addEventListener('click',()=>setSidebar(false));
  document.getElementById('update-chip').addEventListener('click',()=>setSidebar(true));
  // After this window's own save or an accepted delivery for its note, one
  // first catalogue page once changes pause: titles follow typing without a
  // note load, poll or per-keystroke read. A quiet refresh failure keeps the
  // shown list; open, focus and navigation still offer the explicit retry.
  const refreshSoon = () => {
    clearTimeout(catalogueTimer);
    catalogueTimer=setTimeout(()=>{if(boundNote && !navigating) void listNotes(null,true);},500);
  };
  async function listNotes(after=null, quiet=false) {
    const version = after ? catalogueVersion : ++catalogueVersion;
    try {
      const rows=await invoke('note_list',{after});
      if (version!==catalogueVersion) return;
      if (!after) nav.replaceChildren();
      nav.querySelector('.note-more')?.remove();
      for (const row of rows) {
        const item=button(row.title || 'Untitled',()=>navigate(()=>row.note,row.title || 'Untitled'));
        if (sameNote(row.note,currentNote)) {item.setAttribute('aria-current','true');showTitle(row.title || 'Untitled');}
        nav.append(item);
      }
      if (rows.length===50) {
        const last=rows.at(-1);
        const more=button('More notes',()=>listNotes({touched:last.touched,note:last.note}));
        more.className='note-more';nav.append(more);
      }
    } catch {
      if (version!==catalogueVersion || quiet) return;
      if (!after) nav.replaceChildren();
      nav.append(button('Retry note list',()=>listNotes(after)));
    }
  }
  // Native close, Quit and update hold this page under a fence: finish and
  // save its writing, reply, and stay held until native resumes it. A reply
  // native refuses (late, or another page) resumes editing here at once.
  let drainFence = null, drainReason = 'close', drainedEditor = null;
  window.__bhDrain = ({page, fence, timeoutMs, reason} = {}) => {
    if (page === undefined || page !== currentPage || typeof fence !== 'string' ||
        !Number.isFinite(timeoutMs) || timeoutMs <= 0) return 'stale';
    void drainFor(page, fence, timeoutMs, reason === 'update' ? 'update' : 'close');
    return 'accepted';
  };
  async function drainFor(page, fence, timeoutMs, reason) {
    drainFence = fence;drainReason = reason;
    const held = drainedEditor = editor;
    const saved = !held || await held.drain(Date.now() + timeoutMs, reason);
    if (drainFence !== fence || currentPage !== page) return;
    let accepted = false;
    try {
      accepted = await invoke(saved ? 'note_drained' : 'note_drain_failed',
        saved ? {surface: page, fence, view: held?.view() ?? null} : {surface: page, fence});
    } catch { /* native refuses the drain at its own deadline */ }
    if (!accepted && drainFence === fence) {drainFence = null; drainedEditor?.resume();rearmReload();}
  }
  window.__bhResumeEditing = fence => {
    if (fence === drainFence) {drainFence = null; drainedEditor?.resume();rearmReload();}
    return 'accepted';
  };
  const rebind = async () => {
    const binding=await invoke('note_binding');
    if (!binding) throw Error('note unavailable');
    await openNote(binding);
  };
  async function navigate(destination, title='') {
    if (navigating || drainFence) return;
    navigating=true;say('');clearTimeout(catalogueTimer);
    if (narrow.matches) setSidebar(false);
    let disposed=false;
    try {
      const note=await destination();
      if (sameNote(note,currentNote)) return;
      // The same safe drain as closing a window: never destroy accepted
      // writing. Composition finishes and every save lands before closing.
      if (editor && !await editor.drain(Date.now() + 10000, 'close')) {
        if (!drainFence) editor.resume();
        say('Your writing isn’t saved yet, so this note stays open. Try again.');return;
      }
      if (drainFence) return; // a native drain now holds this editor
      editor?.close();editor=null;disposed=true;
      await closeLoad();
      await invoke('note_show',{note});
      showTitle(title);
      const binding=await invoke('note_binding');
      if (!binding) throw Error('note unavailable');
      await openNote(binding);
    } catch {
      if (!disposed) {if (!drainFence) editor?.resume();say('Note unavailable. Your writing is still open; try again.');return;}
      // A rejected route may leave the previous note bound. Retain a retry
      // through native binding, never synthesize an empty editing document.
      retryOpen=rebind;
      unavailable();
    } finally {navigating=false;rearmReload();}
  }
  // Native rebuilt this note from its accepted state, with a structure the
  // open copy cannot reach by merging. Reopen it after the same safe drain
  // as navigating; writing that cannot save yet keeps the merged copy open.
  // A marker that arrives while navigating or under a drain fence waits for
  // that to end; opening a note fresh satisfies it.
  let reloadWanted = false;
  function rearmReload() {
    if (reloadWanted && !navigating && !drainFence) setTimeout(() => void reloadNote(), 0);
  }
  async function reloadNote() {
    if (!editor) return;
    if (navigating || drainFence) {reloadWanted=true;return;}
    reloadWanted=false;
    navigating=true;
    let disposed=false;
    try {
      if (!await editor.drain(Date.now() + 10000, 'close')) {
        if (!drainFence) editor.resume();
        return;
      }
      if (drainFence) return;
      editor.close();editor=null;disposed=true;
      await closeLoad();
      const binding=await invoke('note_binding');
      if (!binding) throw Error('note unavailable');
      await openNote(binding);
    } catch {
      if (!disposed) {if (!drainFence) editor?.resume();return;}
      retryOpen=rebind;
      unavailable();
    } finally {navigating=false;rearmReload();}
  }
  const newNote = () => navigate(()=>invoke('note_create'),'Untitled');
  const newWindow = async () => {
    try {await invoke('note_new_window',{note:currentNote});say('');}
    catch {say('New window unavailable. Try again.');}
  };
  // Adding a device needs this account's cloud sync; shown only once native
  // says it has one, never in a local-only build.
  const addDevice = pairingButton(invoke,icon('M3.5 1.5h6v13h-6z','M6 12.5h1','M12.5 5v5M10 7.5h5'));
  addDevice.hidden = true;
  const devices = devicesButton(invoke);
  devices.hidden = true;
  window.__bhDevices = () => openDevices(invoke);
  tools.append(
    iconButton('New note',['⌘N','Ctrl+N'],icon('M8 2.5H2.5v11h11V8','M6.5 9.5l.5-2.5 6-6 2 2-6 6z'),newNote),
    iconButton('New window',['⌥⌘N','Ctrl+Alt+N'],icon('M1.5 4.5h10v9h-10z','M4.5 4.5v-3h10v9h-3'),newWindow),
    addDevice, devices);
  // The same actions from the native menu (File, View) and their shortcuts.
  const actions = {sidebar:()=>setSidebar(!sidebarVisible()), 'new-note':newNote, 'new-window':newWindow,devices:()=>openDevices(invoke)};
  window.__bhMenu = action => {
    if (!workspace || !Object.hasOwn(actions, action)) return 'ignored';
    void actions[action]();
    return 'accepted';
  };
  document.addEventListener('keydown',event=>{
    if (!workspace) return;
    if (event.key==='Escape' && narrow.matches && overlayOpen) {event.preventDefault();setSidebar(false);return;}
    // On a Mac these are the app menu's own shortcuts, and it calls __bhMenu.
    if (mac || event.repeat || event.shiftKey) return;
    const action = event.code==='KeyS' && event.ctrlKey && event.metaKey && !event.altKey ? 'sidebar'
      : event.code==='KeyN' && event.ctrlKey && !event.metaKey ? (event.altKey ? 'new-window' : 'new-note') : null;
    if (!action) return;
    event.preventDefault();
    void actions[action]();
  });
  window.addEventListener('pagehide',()=>{editor?.close();void closeLoad();});
  window.addEventListener('focus',()=>{if(boundNote && !navigating) void listNotes();});
  function unavailable() {
    const status=document.createElement('p');status.setAttribute('role','status');status.textContent='Note unavailable';
    const retry=button('Retry opening note',async()=>{
      retry.disabled=true;
      try {await retryOpen();} catch {retry.disabled=false;}
    });
    notePane.replaceChildren(notice,status,retry);
    mountWorkspace();
    showTitle('Notes');
    footerLocal.replaceChildren();
  }
  // The window around the page: bar tools, the list, one status line.
  const footer = document.querySelector('footer');
  const footerLocal = document.createElement('span');footerLocal.className='local';
  const cloud = document.createElement('span');cloud.className='cloud';
  // The network's view of this account, apart from the editor's local save.
  const line = syncLine(cloud, invoke, view => {
    addDevice.hidden = !(view.network === 'on' && view.account === 'active');
    devices.hidden = view.account !== 'active';
  });
  cloud.append(icon('M4.5 12.5h7a3 3 0 00.4-6A4 4 0 004.4 6 3.3 3.3 0 004.5 12.5z'), ...line.nodes);
  let preference;
  function mountWorkspace() {
    if (!workspace) {
      workspace=true;
      document.querySelector('header .crumb').textContent='My base';
      document.querySelector('header').append(tools);
      sidebarToggle.hidden=false;
      footer.className='status';footer.replaceChildren(footerLocal,cloud);
      side.append(document.getElementById('update-banner'));
      preference ??= invoke('window_sidebar',{}).then(shown=>{
        if (typeof shown==='boolean' && !narrow.matches) sidebarShown=shown;
        drawSidebar();
      },()=>{});
      drawSidebar();
    }
    if (main.firstChild!==side) main.replaceChildren(side,notePane,scrim);
    main.className='note-workspace';
  }
  const openNote = async binding => {
    reloadWanted = false;
    boundNote = Boolean(binding);
    if (binding) {
      const {note, surface, view} = binding;
      // Each in-place navigation rotates the token too. Already-posted evals
      // compare against this getter before constructing any plaintext payload.
      currentPage=surface;currentNote=note;
      // Status posts reach this page from now on. Ask for the one native
      // published before, which no post brought here; the newer of the two
      // stays, and nothing from an earlier page.
      line.follow();
      invoke('sync_status',{surface}).then(status=>{if(currentPage===surface) line.render(status);},()=>{});
      const { createNoteEditor } = await import('./note-editor.js');
      const main = document.querySelector('main');
      let release = () => {}, activeGeneration, activeWriterToken, peerListener = () => {};
      window.__bhNotePeers = message => peerListener(message);
      const host = {
        onPeers(callback) {peerListener=callback;return ()=>{peerListener=()=>{};};},
        async selection(anchor,head,anchorRel,headRel) {
          return invoke('note_selection',{generation:activeGeneration,surface,anchor,head,anchorRel,headRel});
        },
        async open(onUpdate, options) {
          // A capacity rollover, after the editor drained, names this view's
          // current writer for native to retire. Ordinary opens never do.
          let retireWriter = options?.retire ? activeWriterToken : undefined;
          if (options?.retire && !retireWriter) throw new Error('no writer to retire');
          // Listen before snapshot; deliveries occurring while IPC is in flight
          // stay buffered in the editor until its copy has applied the snapshot.
          let generation, sequence = 0, closed = false;
          const waiting = [];
          let waitingBytes=0, waitingOverflow=false;
          // A delta is one update; a resync is the native note as ordered
          // updates, applied in turn: merging them into one could integrate
          // concurrent text in a different order.
          const updatesOf = packet => packet.resync ? packet.updates : [packet.update];
          const receive = packet => {
            if (!packet || closed) return 'stale';
            const updates = updatesOf(packet);
            if (!Array.isArray(updates) || !updates.every(Array.isArray)) return 'stale';
            const size = updates.reduce((total, update) => total + update.length, 0);
            if (generation === undefined) {
              if (waitingOverflow || waiting.length >= 256 || waitingBytes + size > 256 * 1024) {
                // A fresh native open below obtains all committed bytes.
                waitingOverflow=true;waiting.length=0;waitingBytes=0;
                return 'failed';
              }
              waiting.push(packet);waitingBytes+=size;
              return 'buffered';
            }
            if (packet.generation !== generation || packet.sequence <= sequence) return 'stale';
            try {
              // Both deltas and resyncs merge into the same live document.
              for (const update of updates) onUpdate(new Uint8Array(update));
              sequence = packet.sequence;
              refreshSoon();
              // Native rebuilt the note in an order merging cannot reach.
              if (packet.reload) setTimeout(() => void reloadNote(), 0);
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
                try {
                  opened = await invoke('note_open', retireWriter ? { note, retireWriter } : { note });
                  // Native has replaced this window's writer even if this open
                  // fails below; a later rollover must name the new token.
                  activeWriterToken = opened.writerToken;
                  break;
                }
                catch (error) {
                  if (!String(error).includes('retry open') || attempt === 3) throw error;
                  await new Promise(resolve => setTimeout(resolve, 50 * (attempt + 1)));
                }
              }
              if (!waitingOverflow) break;
              if (snapshot === 2) throw new Error('note snapshot arrivals exceeded buffer');
              // That open already replaced the writer; a fresh snapshot must
              // not fall back to an ordinary, possibly near-end, slot.
              if (retireWriter) retireWriter = opened.writerToken;
            }
          } catch (error) {
            window.removeEventListener('bh-note-update', incoming);
            if (window.__bhNoteDelivery === receive) delete window.__bhNoteDelivery;
            throw error;
          }
          generation = opened.generation;
          activeGeneration = generation;
          sequence = opened.sequence;
          let closing;
          release = () => {
            if (closed) return closing;
            closed = true;
            window.removeEventListener('bh-note-update', incoming);
            if (window.__bhNoteDelivery === receive) {
              delete window.__bhNoteDelivery;
              delete window.__bhNotePeers;
            }
            closing=invoke('note_close', { generation }).catch(() => {});
            return closing;
          };
          // A pre-open packet reported as buffered is processed only after
          // snapshot acquisition. Failure here cannot leave an editable view
          // whose native sender already considered that packet delivered.
          for (const packet of waiting) {
            if (receive(packet) === 'failed') throw new Error('note update failed during open');
          }
          waiting.length = 0;waitingBytes=0;
          // The note's updates in native's integration order, applied in turn.
          return {state:opened.updates.map(update=>new Uint8Array(update)), clientId:opened.clientId, unsubscribe:release};
        },
        async commit(update, requestId) {
          // A resolved matching requestId is the *only* source of Saved.
          const ack = await invoke('note_commit', { generation:activeGeneration, writerToken:activeWriterToken, requestId, update:Array.from(update) });
          refreshSoon();
          return ack;
        },
      };
      retryOpen = async () => {
        window.__bhNotePeers = message => peerListener(message);
        const root = document.createElement('section');
        root.setAttribute('aria-label', 'Note');
        // A restored window's selection and reading position: a hint only.
        try { editor=await createNoteEditor(root, host, {view, statusBar:footerLocal}); }
        catch (error) { release(); throw error; }
        // A drain that found this page still loading told native it had
        // nothing to save: hold the new editor before it is shown, until
        // that drain's own resume.
        if (drainFence) {editor.hold(drainReason);drainedEditor=editor;}
        closeLoad=release;
        notePane.replaceChildren(notice,root);
        mountWorkspace();
        showTitle(currentTitle);
        await listNotes();
      };
      await retryOpen();
    }
  };
  try {
    let note, busy = false;
    try { note = await invoke('note_binding'); }
    catch (error) {
      // A new window that loads while others save for close, Quit or update
      // keeps its note natively; it can try again once they finish.
      if (!String(error).includes('note busy')) throw error;
      busy = true;
    }
    if (busy) {retryOpen=rebind;unavailable();}
    else if (note) await openNote(note);
    else {
      const { mountSignup } = await import('./signup.js');
      await mountSignup(document.querySelector('main'), invoke, async () => {
        const bound = await invoke('note_binding');
        if (!bound) throw new Error('note unavailable');
        await openNote(bound);
      });
    }
  } catch {
    if (boundNote) {
      // A bound but unavailable note is not an editable empty
      // document or another account's setup screen. No draft exists yet.
      unavailable();
    }
    // With no native authority, leave the truthful setup screen intact.
  }
}
