// @ts-nocheck
import * as Y from 'yjs';
import { Editor, Extension } from '@tiptap/core';
import { Plugin, PluginKey, TextSelection } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { ySyncPlugin, yUndoPlugin, ySyncPluginKey, yUndoPluginKey, undo, redo,
  absolutePositionToRelativePosition, relativePositionToAbsolutePosition } from '@tiptap/y-tiptap';
import { extensions, createPreflightMirror, supportsProseMirror, safeViewNode, inventory, withinEditingLimit, editingPositions, isLeafNode } from './schema.mjs';
import { SaveQueue } from './save-queue.mjs';

const TOO_LARGE='This note has reached its size limit, about one million characters. That change wasn’t added.';
const PAUSED='Editing is paused until your writing is saved. It picks up again by itself in a moment.';
// Other devices' preset hues; yellow stays this person's own accent.
const REMOTE_COLOURS=['#1b5fd9','#c2185b','#087a4c','#7a3fd1','#c4520f','#00838f'];
const LABEL_HIDE_MS=3000;
const MAX_LABEL=24;

// An open's state is one Yjs update or a list of them, applied in its order:
// merging the list first can integrate concurrent text in a different order.
export function applyUpdates(doc, list, origin) {
  for (const update of [list].flat()) Y.applyUpdate(doc, update, origin);
}

// A host supplies an already-authorized note, not a base/account/path selector.
// Contract: open(onUpdate)->{state,clientId,unsubscribe} is an atomic
// snapshot + subscription from the already-bound host.
// commit(update,requestId)->{requestId} only after durable core commit. No
// Tauri commands here. options.view is an untrusted restart hint from drain's
// view(): encoded relative selection and the head's offset in the visible
// scroll area, applied once if valid. options.statusBar, if given, is where
// the save status and its Retry are shown instead of under the note.
// Known limit: one giant paragraph can still lag during browser layout; the
// incremental preflight mirror does not reduce that rendering cost.
export async function createNoteEditor(root, host, options={}) {
  if (!host || typeof host.open!=='function' || typeof host.commit!=='function') throw new TypeError('bound note host required');
  const buffered=[];
  let receive=bytes=>buffered.push(bytes);
  const opened=await host.open(bytes=>receive(bytes));
  if (!opened || typeof opened.unsubscribe!=='function') throw new TypeError('atomic bound note open required');
  let {unsubscribe}=opened;
  let doc=new Y.Doc();
  try { applyUpdates(doc,opened.state,'initial'); }
  catch(error) {unsubscribe();doc.destroy();throw error;}
  // 0 and 1 are reserved for sync and Hero; each editor gets a distinct Yjs origin.
  doc.clientID=opened.clientId;
  let fragment=doc.getXmlFragment(inventory.fragment);
  let mirror;
  try {mirror=createPreflightMirror(doc);} catch {mirror=null;}
  let editor=null, closed=false, working=false, failed=false, flushing=null;
  // A note over the shared editing size stays readable; local authoring stops.
  let tooLarge=false, editable=null, held=null;
  const canAuthor=()=>!!editor && !options.readOnly && !tooLarge && !held;
  // Wakes drain waits on each save outcome, composition end and close.
  const waiters=new Set();
  const changed=()=>{for(const wake of waiters)wake();waiters.clear();};
  // True on the next change (or after `minimum` ms), false at the deadline.
  function wait(deadline,minimum=0) {
    const remaining=deadline-Date.now();
    if(remaining<=0 || remaining<minimum)return Promise.resolve(false);
    return new Promise(resolve=>{
      let timer,soon;
      const finish=ok=>{clearTimeout(timer);clearTimeout(soon);waiters.delete(wake);resolve(ok);};
      const wake=()=>finish(true);
      timer=setTimeout(()=>finish(false),remaining);
      if(minimum)soon=setTimeout(()=>finish(true),minimum);else waiters.add(wake);
    });
  }
  function syncEditable() {
    if(!editor || closed)return;
    const next=canAuthor();
    if(next!==editable){editable=next;editor.setEditable(next);}
    if(!next){closeLink(false);placeBubble();}
  }
  function checkSize() {
    if(!editor || closed)return;
    const over=!withinEditingLimit(editor.state.doc);
    if(over!==tooLarge){tooLarge=over;syncEditable();setStatus();}
  }
  const peerKey=new PluginKey('bhPeerSelections');
  let peerTimer=null;
  const peerHideTimers=new Map();
  let peerRefresh=false;
  // A local edit's PM transaction renders before the Y binding has updated its
  // type mapping; one follow-up pass resolves the remote carets against the
  // projected document, and does nothing when nothing changed.
  const refreshPeers=()=>{
    if(peerRefresh)return;
    peerRefresh=true;
    setTimeout(()=>{
      peerRefresh=false;
      if(editor && !closed) editor.view.dispatch(editor.state.tr.setMeta(peerKey,{type:'refresh'}));
    },0);
  };
  const remoteColour=index=>REMOTE_COLOURS[Math.max(0,Math.min(5,Number.isInteger(index)?index:0))];
  const positionBytes=value=>Array.isArray(value) && value.length>0 && value.length<=96 &&
    value.every(byte=>Number.isInteger(byte) && byte>=0 && byte<256);
  // The approved label is at most 24 characters, with an ellipsis when longer.
  const labelText=value=>{
    const characters=Array.from(String(value??''));
    return characters.length>MAX_LABEL?characters.slice(0,MAX_LABEL-1).join('')+'…':characters.join('');
  };
  // A remote caret is a Yjs relative position: it resolves against the live
  // document each time, so typing and remote batches move it with its words.
  const resolvePeer=(state,bytes)=>{
    const binding=ySyncPluginKey.getState(state)?.binding;
    if(!binding || !fragment)return null;
    try {
      const decoded=Y.decodeRelativePosition(Uint8Array.from(bytes));
      // A root position names a type by string. Only this editor's own fragment
      // may be named: resolving another root would define it in the document.
      if(!decoded.type && !decoded.item && decoded.tname!==inventory.fragment)return null;
      const pos=relativePositionToAbsolutePosition(doc,fragment,decoded,binding.mapping);
      return Number.isInteger(pos)&&pos>=0&&pos<=state.doc.content.size?pos:null;
    } catch {return null;}
  };
  const hasRemote=state=>{
    for (const peer of peerKey.getState(state)?.values()??[]) if (peer.kind==='remote') return true;
    return false;
  };
  const hidePeerLabel=id=>{
    clearTimeout(peerHideTimers.get(id));
    peerHideTimers.set(id,setTimeout(()=>{
      peerHideTimers.delete(id);
      if(editor && !closed) editor.view.dispatch(editor.state.tr.setMeta(peerKey,{type:'label',id,visible:false}));
    },LABEL_HIDE_MS));
  };
  const receivePeer=event=>{
    if (!editor || closed || !event?.id) return;
    if (event.type==='remote' || (event.type==='label' && event.visible)) hidePeerLabel(event.id);
    else if (event.type==='remove') {clearTimeout(peerHideTimers.get(event.id));peerHideTimers.delete(event.id);}
    editor.view.dispatch(editor.state.tr.setMeta(peerKey,event));
  };
  const stopPeers=host.onPeers?.(receivePeer)??(()=>{});
  function sendSelection() {
    if (peerTimer || !host.selection || !editor || closed) return;
    peerTimer=setTimeout(()=>{
      peerTimer=null;
      if (!editor || closed) return;
      const {anchor,head}=editor.state.selection;
      const binding=ySyncPluginKey.getState(editor.state)?.binding;
      const anchorRel=binding?relative(anchor,binding):null;
      const headRel=binding?relative(head,binding):null;
      void Promise.resolve(host.selection(anchor,head,anchorRel,headRel)).then(peers=>{
        if (Array.isArray(peers)) for (const peer of peers) receivePeer({type:'set',...peer});
      }).catch(()=>{});
    },50);
  }
  function rebuildMirror() {
    // Any uncertain state must be checked on a disposable copy, while the
    // binding is suspended. Never project the live editing document.
    if (editor) {editor.destroy();editor=null;}
    mirror?.destroy();
    try {mirror=createPreflightMirror(doc);} catch {mirror=null;}
    refresh(mirror?.supported??false);
  }
  const requestId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('');
  const pending=new SaveQueue();
  let savingSince=0, savingTimer=null;
  let underway={id:undefined,allowed:true};
  const pendingCount=()=>pending.count;
  root.replaceChildren();
  const status=document.createElement('p');status.dataset.status='';status.setAttribute('role','status');
  const retryButton=document.createElement('button');retryButton.type='button';retryButton.textContent='Retry';
  retryButton.setAttribute('aria-label','Retry save');retryButton.className='note-retry';retryButton.hidden=true;
  const content=document.createElement('div');content.className='note-content';
  // An IME composition is live input: a drain lets it finish first.
  let composingNow=false;
  content.addEventListener('compositionstart',()=>{composingNow=true;});
  content.addEventListener('compositionend',()=>{composingNow=false;changed();});
  // Why a local change was not taken. Cleared by the next accepted edit.
  const notice=document.createElement('p');notice.className='note-refusal';notice.setAttribute('role','alert');notice.hidden=true;
  const say=text=>{
    if(notice.textContent===text)return;
    // The pause leads with what happened, then that it resolves by itself.
    const [lead,rest]=text===PAUSED?[PAUSED.slice(0,PAUSED.indexOf('.')+1),PAUSED.slice(PAUSED.indexOf('.')+1)]:[null,text];
    if(lead){const strong=document.createElement('strong');strong.textContent=lead;notice.replaceChildren(strong,rest);}
    else notice.textContent=rest;
    notice.hidden=!text;
  };
  // Over the editing size: the note stays readable and copyable.
  const large=document.createElement('p');large.className='note-large';large.hidden=true;
  const largeHead=document.createElement('strong');largeHead.textContent='Read-only · Too large to edit.';
  large.append(largeHead,' This note is over about one million characters. Everything in it is kept, and you can read and copy it.');
  for (const type of ['click','auxclick']) content.addEventListener(type,event=>{
    const link=event.target instanceof Element && event.target.closest('a');
    if(!link)return;
    event.preventDefault();
    try {
      const url=new URL(link.getAttribute('href'));
      if(!['http:','https:'].includes(url.protocol))return;
      const match=url.origin==='https://basehero.com' && /^\/open\/([^/]+)\/([^/]+)\/?$/.exec(url.pathname);
      if(match) options.navigate?.(match[1],match[2]);
      else void host.openExternal?.(url.href);
    } catch { /* A malformed link never navigates the WebView. */ }
  },true);
  const bubble=document.createElement('div');bubble.className='note-bubble';bubble.hidden=true;
  bubble.setAttribute('role','toolbar');bubble.setAttribute('aria-label','Format');
  const linkPop=document.createElement('div');linkPop.className='note-linkpop';linkPop.hidden=true;
  linkPop.setAttribute('role','dialog');linkPop.setAttribute('aria-label','Link');
  root.append(notice,large,content,bubble,linkPop);
  if(options.statusBar)options.statusBar.replaceChildren(status,retryButton);else root.append(status,retryButton);
  const retrySave=()=>{if(!closed && !working){failed=false;setStatus();void flush();}};
  retryButton.addEventListener('click',retrySave);
  const savedCopy=/Android/i.test(globalThis.navigator?.userAgent??'') ? 'Saved on this device' : 'Saved on this Mac';
  const setStatus=()=>{
    retryButton.hidden=!failed;
    // The pause lifts by itself as saving catches up; say so while it lasts.
    if(pending.full)say(PAUSED);else if(notice.textContent===PAUSED)say('');
    const hasPending=pendingCount()>0;
    if(!hasPending || failed) {clearTimeout(savingTimer);savingTimer=null;savingSince=0;}
    else if(!savingSince) savingSince=Date.now();
    if(hasPending && !failed && !savingTimer && Date.now()-savingSince<1000) {
      savingTimer=setTimeout(()=>{savingTimer=null;if(!closed)setStatus();},1000-(Date.now()-savingSince));
    }
    const unsaved=failed;
    const saving=failed ? 'Not saved' : hasPending && Date.now()-savingSince>=1000 ? 'Saving…' : savedCopy;
    const text=held==='update' && !failed ? 'Saving before update…' : (options.readOnly || !editor)
      ? (pendingCount() ? 'Not saved · ' : '')+'Update BaseHero to edit this note.' : saving;
    if(status.textContent!==text)status.textContent=text;
    status.dataset.status=unsaved ? 'failed' : text===savedCopy ? 'saved' : !editor ? 'readonly' : 'busy';
    large.hidden=!(editor && tooLarge);
  };
  function flush() {
    if(flushing)return flushing;
    if(closed || failed || !pendingCount())return Promise.resolve();
    working=true;
    flushing=(async()=>{
      while(!closed && !failed && pendingCount()) {
        // IDs and bytes stay fixed across uncertain attempts and lease failure.
        const item=pending.submit(requestId());
        try {
          const ack=await host.commit(new Uint8Array(item.bytes),item.id);
          if(closed)return;
          if(!ack || ack.requestId!==item.id){failed=true;break;}
          pending.acknowledge();setStatus();changed();
        } catch {if(!closed)failed=true;}
      }
    })().finally(()=>{working=false;flushing=null;if(!closed)setStatus();changed();});
    return flushing;
  }
  function history(command,e) {
    if(!canAuthor())return false;
    if(pending.full) {say(PAUSED);return true;}
    if(e.state.doc.nodeSize>=editingPositions) {say(TOO_LARGE);return true;}
    say('');
    try {const ran=command(e.state);checkSize();return ran;} catch {
      // Yjs redoItem can throw after concurrent edits without emitting an
      // update. Keep the view usable; recheck any state it may have touched.
      rebuildMirror();return false;
    }
  }
  // Formatting on demand: a bubble over a selection, its shortcuts in its
  // tooltips. The link editor is a small field under the selection.
  const mac=/Mac|iP(hone|[oa]d)/.test(globalThis.navigator?.platform??'');
  const svg=(...paths)=>{
    const node=document.createElementNS('http://www.w3.org/2000/svg','svg');
    node.setAttribute('viewBox','0 0 16 16');node.setAttribute('aria-hidden','true');node.setAttribute('class','note-icon');
    for(const d of paths){const path=document.createElementNS('http://www.w3.org/2000/svg','path');path.setAttribute('d',d);node.append(path);}
    return node;
  };
  const glyph=(text,className)=>{const node=document.createElement('span');node.className='note-glyph '+className;node.textContent=text;node.setAttribute('aria-hidden','true');return node;};
  const formats=[
    ['Bold',()=>glyph('B','bold'),'⌘B','Ctrl+B',e=>e.chain().focus().toggleBold().run(),e=>e.isActive('bold')],
    ['Italic',()=>glyph('I','italic'),'⌘I','Ctrl+I',e=>e.chain().focus().toggleItalic().run(),e=>e.isActive('italic')],
    ['Code',()=>svg('M5.5 4L2 8l3.5 4M10.5 4L14 8l-3.5 4'),'⌘E','Ctrl+E',e=>e.chain().focus().toggleCode().run(),e=>e.isActive('code')],
    ['Link',()=>svg('M6.5 9.5l3-3','M7 4.5l1.5-1.5a2.5 2.5 0 013.5 3.5L10.5 8','M9 11.5L7.5 13A2.5 2.5 0 014 9.5L5.5 8'),'⌘K','Ctrl+K',()=>openLink(),e=>e.isActive('link')],
    null,
    ['Heading',()=>glyph('H','heading'),'⌥⌘2','Ctrl+Alt+2',e=>e.chain().focus().toggleHeading({level:2}).run(),e=>e.isActive('heading')],
    ['List',()=>svg('M6 4h8M6 8h8M6 12h8','M2 3.2h1.6v1.6H2zM2 7.2h1.6v1.6H2zM2 11.2h1.6v1.6H2z'),'⇧⌘8','Ctrl+Shift+8',e=>e.chain().focus().toggleBulletList().run(),e=>e.isActive('bulletList')],
    ['Checklist',()=>svg('M1.5 2.5h4v4h-4z','M2.6 4.5l.9.9 1.6-1.8','M1.5 9.5h4v4h-4z','M8 4.5h6.5M8 11.5h6.5'),'⇧⌘9','Ctrl+Shift+9',e=>e.chain().focus().toggleTaskList().run(),e=>e.isActive('taskList')],
  ];
  const pressed=[];
  for(const format of formats) {
    if(!format){const rule=document.createElement('span');rule.className='note-bubble-rule';bubble.append(rule);continue;}
    const [label,icon,macKeys,keys,run,active]=format;
    const button=document.createElement('button');button.type='button';button.setAttribute('aria-label',label);
    button.title=`${label} ${mac?macKeys:keys}`;button.append(icon());
    button.addEventListener('mousedown',event=>event.preventDefault());
    button.addEventListener('click',()=>{if(canAuthor()){run(editor);placeBubble();}});
    bubble.append(button);pressed.push([button,active]);
  }
  const linkInput=document.createElement('input');linkInput.type='url';linkInput.setAttribute('aria-label','Link URL');
  linkInput.placeholder='https://…';linkInput.spellcheck=false;
  const linkDone=document.createElement('button');linkDone.type='button';linkDone.textContent='Done';linkDone.className='note-go';
  const linkRemove=document.createElement('button');linkRemove.type='button';linkRemove.textContent='Remove';
  const pickNote=document.createElement('button');pickNote.type='button';pickNote.textContent='Link to a note';
  const noteSearch=document.createElement('input');noteSearch.type='search';noteSearch.setAttribute('aria-label','Search notes');noteSearch.hidden=true;
  const noteResults=document.createElement('div');noteResults.className='note-link-results';
  linkPop.append(linkInput,linkDone,linkRemove,pickNote,noteSearch,noteResults);
  let searchGeneration=0;
  pickNote.addEventListener('click',()=>{
    linkInput.hidden=true;linkDone.hidden=true;linkRemove.hidden=true;pickNote.hidden=true;
    noteSearch.hidden=false;noteSearch.focus();
  });
  noteSearch.addEventListener('input',async()=>{
    const generation=++searchGeneration;
    noteResults.replaceChildren();
    const results=await host.search?.(noteSearch.value)??[];
    if(generation!==searchGeneration || linkPop.hidden)return;
    for(const result of results){
      const button=document.createElement('button');button.type='button';button.textContent=result.title;
      button.addEventListener('click',()=>{
        if(!canAuthor())return;
        const href=`https://basehero.com/open/${encodeURIComponent(options.baseId)}/${encodeURIComponent(result.id)}`;
        editor.chain().focus().extendMarkRange('link').setLink({href}).run();closeLink(true);
      });
      noteResults.append(button);
    }
  });
  let pointerSelecting=false;
  // Fixed to the viewport beside the selection, kept inside the note's visible area.
  function place(node,above) {
    const {from,to}=editor.state.selection;
    const start=editor.view.coordsAtPos(from),end=editor.view.coordsAtPos(to);
    const area=scroller().getBoundingClientRect(),width=node.offsetWidth,height=node.offsetHeight;
    const centre=start.top===end.top?(start.left+end.right)/2:start.left+width/2;
    let top=above?start.top-height-8:end.bottom+8;
    if(above && top<Math.max(area.top,0)+4)top=end.bottom+8;
    const left=Math.max(8,Math.min(innerWidth-width-8,above?centre-width/2:start.left-12));
    node.style.left=`${Math.round(left)}px`;node.style.top=`${Math.round(top)}px`;
  }
  function placeBubble() {
    if(!editor || closed){bubble.hidden=true;return;}
    const show=!editor.state.selection.empty && canAuthor() && !pointerSelecting && linkPop.hidden &&
      (editor.view.hasFocus() || bubble.contains(document.activeElement));
    bubble.hidden=!show;
    if(!show)return;
    for(const [button,active] of pressed)button.setAttribute('aria-pressed',String(!!active(editor)));
    place(bubble,true);
  }
  function placeLink() {if(editor && !closed && !linkPop.hidden)place(linkPop,false);}
  function openLink() {
    if(!canAuthor())return false;
    const inLink=editor.isActive('link');
    if(editor.state.selection.empty && !inLink)return false;
    linkInput.value=inLink?editor.getAttributes('link').href??'':'';
    linkInput.hidden=false;linkDone.hidden=false;linkRemove.hidden=false;pickNote.hidden=false;
    noteSearch.hidden=true;noteSearch.value='';noteResults.replaceChildren();
    linkInput.removeAttribute('aria-invalid');
    linkPop.hidden=false;bubble.hidden=true;placeLink();
    linkInput.focus();linkInput.select();
    return true;
  }
  function closeLink(refocus) {
    if(linkPop.hidden)return;
    linkPop.hidden=true;searchGeneration++;noteResults.replaceChildren();
    if(refocus && editor)editor.view.focus();
    placeBubble();
  }
  function applyLink() {
    const input=linkInput.value.trim();
    try {
      const parsed=new URL(input);
      if (!canAuthor() || !inventory.marks.link.href.url.includes(parsed.protocol) || !parsed.hostname || /[\u0000-\u001f\u007f]/u.test(input)) throw Error('unsupported link');
    } catch { linkInput.setAttribute('aria-invalid','true');return; }
    editor.chain().focus().extendMarkRange('link').setLink({href:input}).run();
    closeLink(true);
  }
  linkDone.addEventListener('click',applyLink);
  linkRemove.addEventListener('click',()=>{
    if(canAuthor())editor.chain().focus().extendMarkRange('link').unsetLink().run();
    closeLink(true);
  });
  linkInput.addEventListener('keydown',event=>{
    if(event.key==='Enter'){event.preventDefault();applyLink();}
    else if(event.key==='Escape'){event.preventDefault();closeLink(true);}
  });
  const outside=event=>{if(!linkPop.hidden && !linkPop.contains(event.target))closeLink(false);};
  // Android: folding, rotating or the keyboard resizes the page, which can
  // rewrap a long note or cover the caret. Afterwards show what the person
  // was looking at: the caret if it was in view, otherwise the text at the
  // top of the pane, never the caret against their own scrolling.
  const android=/Android/i.test(navigator.userAgent);
  let layoutSize=`${innerWidth}x${innerHeight}`,caretSeen=false,reading=null;
  let pendingRestoration=null;
  const noteView=()=>{
    if (!android || !editor || closed) return;
    const bounds=scroller().getBoundingClientRect();
    const caret=editor.view.coordsAtPos(editor.state.selection.head);
    caretSeen=caret.bottom>bounds.top && caret.top<bounds.bottom;
    // The first block in view, and how far down it the pane's top falls.
    const blocks=editor.view.dom.children;
    let low=0,high=blocks.length-1;
    while (low<high) {const mid=(low+high)>>1;if(blocks[mid].getBoundingClientRect().bottom<=bounds.top)low=mid+1;else high=mid;}
    const block=blocks[low],rect=block?.getBoundingClientRect();
    reading=rect?.height?{block,at:(bounds.top-rect.top)/rect.height}:null;
  };
  const relayout=()=>{
    placeBubble();placeLink();
    if (!android || !editor || closed) return;
    const size=`${innerWidth}x${innerHeight}`;
    if (size===layoutSize) {noteView();return;}
    layoutSize=size;
    // Keep the pre-reflow anchor through all intermediate resize notifications.
    // Only the latest two-frame callback may apply it.
    const task=pendingRestoration??{keep:caretSeen?null:reading,caret:caretSeen,generation:0};
    if (!task.caret && !task.keep) return;
    pendingRestoration=task;
    const generation=++task.generation;
    requestAnimationFrame(()=>requestAnimationFrame(()=>{
      if (pendingRestoration!==task || task.generation!==generation || !editor || closed) return;
      pendingRestoration=null;
      const area=scroller(),bounds=area.getBoundingClientRect();
      if (task.keep) {
        if (!task.keep.block.isConnected) return;
        const rect=task.keep.block.getBoundingClientRect();
        area.scrollTop+=rect.top+task.keep.at*rect.height-bounds.top;
        return;
      }
      const caret=editor.view.coordsAtPos(editor.state.selection.head);
      // Keep a small margin around the cursor box rather than leaving
      // the selected line flush with the clipping edge.
      if (caret.top<bounds.top+8 || caret.bottom>bounds.bottom-8)
        area.scrollTop+=caret.top-bounds.top-bounds.height/2;
    }));
  };
  // Layout itself can emit scroll while WebView rewraps; only input or a
  // selection update establishes a newer intention than the saved anchor.
  const onUserIntent=()=>{if(android)pendingRestoration=null;};
  const onScroll=()=>relayout();
  const onSelectionIntent=()=>{if(android)pendingRestoration=null;queueMicrotask(noteView);};
  const pointerDown=event=>{if(content.contains(event.target)){pointerSelecting=true;bubble.hidden=true;}};
  const pointerUp=()=>{if(pointerSelecting){pointerSelecting=false;placeBubble();}};
  document.addEventListener('mousedown',outside,true);
  document.addEventListener('mousedown',pointerDown,true);
  window.addEventListener('mouseup',pointerUp,true);
  window.addEventListener('scroll',onScroll,true);
  window.addEventListener('resize',relayout);
  if(android)for(const type of ['wheel','touchstart','pointerdown','keydown'])
    window.addEventListener(type,onUserIntent,{capture:true,passive:true});
  // The native Edit menu's Undo and Redo arrive as history input events.
  content.addEventListener('beforeinput',event=>{
    if(event.inputType!=='historyUndo' && event.inputType!=='historyRedo')return;
    event.preventDefault();
    if(editor)history(event.inputType==='historyUndo'?undo:redo,editor);
  });
  let readonlyNodes=new Map();
  const make=item=>{
      const el=document.createElement(item.placeholder?'span':'div');
      if (item.placeholder) {el.textContent='Unsupported content';el.className='note-placeholder';}
      else if ('text' in item) el.textContent=item.text;
      else {el.className='note-'+item.label;for(const child of item.children)el.append(make(child));}
      return el;
  };
  function renderNode(node) {return safeViewNode(node).map(make);}
  function showReadonly(changes=null) {
    if (editor) {editor.destroy();editor=null;content.replaceChildren();readonlyNodes=new Map();}
    bubble.hidden=true;linkPop.hidden=true;
    if (!changes || changes.has(fragment)) {
      // Root insertions and nested edits can occur in the same transaction.
      // Reuse only blocks whose descendants were not also changed.
      const dirty=new Set();
      for (const type of changes??[]) {
        if (type===fragment) continue;
        let root=type;
        while (root.parent && root.parent!==fragment) root=root.parent;
        if (root.parent===fragment) dirty.add(root);
      }
      const children=fragment.toArray(),next=new Map();
      const desired=children.flatMap(node=>{
        if (!(node instanceof Y.XmlElement || node instanceof Y.XmlText)) return renderNode(node);
        const rendered=dirty.has(node)?renderNode(node):readonlyNodes.get(node)??renderNode(node);
        next.set(node,rendered);return rendered;
      });
      for (let i=0;i<desired.length;i++) if (content.childNodes[i]!==desired[i]) content.insertBefore(desired[i],content.childNodes[i]??null);
      while (content.childNodes.length>desired.length) content.lastChild.remove();
      readonlyNodes=next;
    } else {
      const roots=new Set();
      for (const type of changes) {
        let root=type;
        while (root.parent && root.parent!==fragment) root=root.parent;
        if (root.parent===fragment) roots.add(root);
      }
      for (const root of roots) {
        const previous=readonlyNodes.get(root);
        if (!previous) {showReadonly();return;}
        const next=renderNode(root),anchor=previous.at(-1)?.nextSibling??null;
        for (const element of previous) element.remove();
        for (const element of next) content.insertBefore(element,anchor);
        readonlyNodes.set(root,next);
      }
    }
    setStatus();
  }
  function showEditable() {
    if (editor) {setStatus();return;}
    content.replaceChildren();readonlyNodes=new Map();
    // Keep this view's last selection visible when a different window or a
    // toolbar input takes focus. This is local presentation only: never an
    // edit, a durable event, or a cross-device presence announcement.
    const selectionKey=new PluginKey('bhOwnSelection');
    const ownSelection=new Plugin({
      key:selectionKey,
      state:{init:()=>false,apply(tr,visible){return tr.getMeta(selectionKey) ?? visible;}},
      props:{
        handleDOMEvents:{
          blur(view){view.dispatch(view.state.tr.setMeta(selectionKey,true));return false;},
          focus(view){view.dispatch(view.state.tr.setMeta(selectionKey,false));return false;},
        },
        decorations(state){
          if (!selectionKey.getState(state)) return null;
          const {from,to}=state.selection;
          if (from!==to) return DecorationSet.create(state.doc,[
            Decoration.inline(from,to,{class:'bh-own-selection'}),
          ]);
          return DecorationSet.create(state.doc,[Decoration.widget(from,()=>{
            const marker=document.createElement('span');
            marker.className='bh-own-cursor';marker.setAttribute('aria-hidden','true');
            return marker;
          },{side:-1})]);
        },
      },
    });
    const otherSelections=new Plugin({
      key:peerKey,
      state:{
        init:()=>new Map(),
        apply(tr,previous){
          const message=tr.getMeta(peerKey);
          if (!message) return previous;
          const next=new Map(previous);
          if (message.type==='remove') next.delete(message.id);
          else if (message.type==='label') {
            const held=next.get(message.id);
            if (held) next.set(message.id,{...held,visible:!!message.visible});
          } else if (message.type==='set' && Number.isSafeInteger(message.anchor) && Number.isSafeInteger(message.head)) {
            // Another window on this device: the existing local integer path.
            next.set(message.id,{kind:'local',anchor:message.anchor,head:message.head});
          } else if (message.type==='remote' && positionBytes(message.anchor) && positionBytes(message.head)) {
            const held=next.get(message.id);
            next.set(message.id,{
              kind:'remote',
              anchor:message.anchor,head:message.head,
              label:labelText(message.label),
              colour:Number.isInteger(message.colour)?message.colour:0,
              visible:true,
              anchorPos:held?.anchorPos,
              headPos:held?.headPos,
            });
          }
          return next;
        },
      },
      props:{decorations(state){
        const decorations=[];
        const max=state.doc.content.size;
        for (const [id,peer] of peerKey.getState(state)) {
          if (peer.kind==='local') {
            const from=Math.max(0,Math.min(peer.anchor,peer.head,max));
            const to=Math.max(0,Math.min(Math.max(peer.anchor,peer.head),max));
            if (from!==to) decorations.push(Decoration.inline(from,to,{class:'bh-peer-selection','data-peer':id}));
            decorations.push(Decoration.widget(Math.max(0,Math.min(peer.head,max)),()=>{
              const marker=document.createElement('span');marker.className='bh-peer-cursor';
              marker.setAttribute('aria-hidden','true');marker.dataset.peer=id;return marker;
            },{side:-1,key:'bh-peer:'+id}));
            continue;
          }
          // Resolve on every decoration pass, after the binding has projected
          // the change: local typing and remote batches move the caret with
          // its words. A missing item keeps the last place it had.
          const anchorPos=resolvePeer(state,peer.anchor)??peer.anchorPos;
          const headPos=resolvePeer(state,peer.head)??peer.headPos;
          peer.anchorPos=anchorPos;peer.headPos=headPos;
          if (!Number.isInteger(headPos)) continue;
          const head=Math.max(0,Math.min(headPos,max));
          const anchor=Number.isInteger(anchorPos)?Math.max(0,Math.min(anchorPos,max)):head;
          const colour=remoteColour(peer.colour);
          if (anchor!==head) decorations.push(Decoration.inline(Math.min(anchor,head),Math.max(anchor,head),
            {class:'bh-remote-selection','data-peer':id,style:`--peer:${colour}`}));
        }
        return DecorationSet.create(state.doc,decorations);
      }},
      view:editorView=>{
        // Another device's caret and label are drawn over the note, outside
        // its editable text. An Android keyboard edits that text by offset;
        // a label inside it let Gboard's edit land in the label, which ended
        // editing and hid the keyboard.
        const layer=document.createElement('div');layer.className='bh-remote-carets';layer.setAttribute('aria-hidden','true');
        const markers=new Map();
        const draw=()=>{
          if (!markers.size && !hasRemote(editorView.state)) return;
          if (!layer.isConnected) {if(!editorView.dom.parentNode)return;editorView.dom.after(layer);}
          const {doc}=editorView.state,origin=layer.getBoundingClientRect(),shown=new Set();
          // Measure every peer before writing any marker: a write between two
          // measurements makes the next coordsAtPos flush the layout it caused.
          const places=[];
          for (const [id,peer] of peerKey.getState(editorView.state)) {
            if (peer.kind!=='remote' || !Number.isInteger(peer.headPos)) continue;
            const head=Math.max(0,Math.min(peer.headPos,doc.content.size));
            let at,text;
            try {
              at=editorView.coordsAtPos(head,-1);
              const {node}=editorView.domAtPos(head);text=node.nodeType===1?node:node.parentElement;
            } catch {continue;}
            // Sized from the text it stands in, its foot on that text's bottom.
            places.push({id,peer,left:at.left-origin.left,top:at.bottom-origin.top,fontSize:getComputedStyle(text).fontSize});
          }
          for (const {id,peer,left,top,fontSize} of places) {
            let marker=markers.get(id);
            if (!marker) {
              marker=document.createElement('span');marker.className='bh-remote-cursor';marker.dataset.peer=id;
              const label=document.createElement('span');label.className='bh-remote-label';
              marker.append(label);
              // A Fold tap on the collapsed tab shows the label again; the
              // note keeps focus and its keyboard.
              marker.addEventListener('mousedown',event=>event.preventDefault());
              marker.addEventListener('click',event=>{event.preventDefault();receivePeer({type:'label',id,visible:true});});
              markers.set(id,marker);layer.append(marker);
            }
            // Idle keeps the caret and collapses only the label to its tab.
            marker.toggleAttribute('data-collapsed',!peer.visible);
            marker.dataset.label=peer.label;
            // An unchanged name keeps its text node; a new one replaces it.
            if (marker.firstChild.textContent!==peer.label) marker.firstChild.textContent=peer.label;
            marker.style.setProperty('--peer',remoteColour(peer.colour));
            marker.style.fontSize=fontSize;
            marker.style.left=`${left}px`;marker.style.top=`${top}px`;
            shown.add(id);
          }
          for (const [id,marker] of markers) if (!shown.has(id)) {marker.remove();markers.delete(id);}
        };
        // Rewrapping (a fold, a resize) moves the text under a caret.
        const resized=new ResizeObserver(draw);resized.observe(editorView.dom);
        return {
          update(view,previous){
            if (!view.state.selection.eq(previous.selection) || view.state.doc!==previous.doc) sendSelection();
            // Incoming, Undo and Redo projections can change the size too.
            if (view.state.doc!==previous.doc) {queueMicrotask(checkSize);if(hasRemote(view.state))refreshPeers();}
            draw();
          },
          destroy(){resized.disconnect();layer.remove();},
        };
      },
    });
    const binding=Extension.create({
      name:'bhNoteBinding',priority:1100,
      addProseMirrorPlugins() {return [
        ownSelection,
        new Plugin({filterTransaction:tr=>{
          if(!tr.docChanged) return true;
          // Only the binding's own projections of Yjs changes (remote, Undo,
          // Redo) carry its meta; they write nothing further to Yjs.
          const projected=tr.getMeta(ySyncPluginKey);
          // A drain already read the last DOM input before holding.
          if((held || options.readOnly) && !projected)return false;
          // A pasted/programmatic transaction must not introduce a value the
          // binding could write but the shared inventory cannot render safely.
          if(!supportsProseMirror(tr.doc))return false;
          if(projected)return true;
          // At the unsaved limit only a composition already under way may
          // finish (its final DOM read included); new growth waits for saving.
          const composition=tr.getMeta('composition');
          if(composition!==undefined && underway.id!==composition)underway={id:composition,allowed:!pending.full};
          if(pending.full && !(composition!==undefined && underway.allowed)) {say(PAUSED);return false;}
          // Size is checked before the edit is accepted, from PM's cached size.
          if(tooLarge || !withinEditingLimit(tr.doc) && tr.doc.nodeSize>tr.before.nodeSize) {
            say(TOO_LARGE);return false;
          }
          say('');return true;
        }}),ySyncPlugin(fragment),otherSelections,yUndoPlugin(),
      ];},
      addKeyboardShortcuts(){return {'Mod-z':()=>history(undo,this.editor),'Mod-Shift-z':()=>history(redo,this.editor),'Mod-y':()=>history(redo,this.editor),'Mod-k':()=>openLink()};},
    });
    editable=!options.readOnly && !tooLarge && !held;
    editor=new Editor({element:content,extensions:[...extensions,binding],content:'',injectCSS:false,editable});
    for(const event of ['selectionUpdate','focus','blur','transaction'])editor.on(event,()=>queueMicrotask(placeBubble));
    editor.on('selectionUpdate',onSelectionIntent);
    editor.on('focus',()=>sendSelection());
    // No HTML from a note is ever passed to the editor or DOM.
    checkSize();setStatus();sendSelection();
  }
  function fallbackReadonly() {
    if (editor) {editor.destroy();editor=null;}
    bubble.hidden=true;linkPop.hidden=true;readonlyNodes=new Map();content.replaceChildren();
    const placeholder=document.createElement('span');placeholder.className='note-placeholder';
    placeholder.textContent='Unsupported content';content.append(placeholder);setStatus();
  }
  function refresh(supported,changes=null) {
    try {if (supported) showEditable();else showReadonly(changes);}
    catch {fallbackReadonly();}
  }
  doc.on('update',(bytes,origin)=>{
    const localUndo=editor && yUndoPluginKey.getState(editor.state)?.undoManager;
    if (closed || origin==='incoming') return;
    if (origin!==ySyncPluginKey && origin!==localUndo) {
      // An unaccounted write (including a delete-only update) may have changed
      // live without passing preflight. Suspend the binding and rebuild.
      rebuildMirror();return;
    }
    let verdict;
    try {verdict=mirror?.apply(bytes)??{uncertain:true};} catch {verdict={uncertain:true};}
    if (verdict.uncertain || !verdict.supported) rebuildMirror();
    pending.append(bytes);
    setStatus();void flush();
  });
  refresh(mirror?.supported??false);
  function applyIncoming(bytes) {Y.applyUpdate(doc,bytes,'incoming');}
  const composing=()=>composingNow || !!editor?.view.composing;
  // Finish composition (and a composition that starts within 25 ms of the
  // last one ending), read the last DOM change while still editable, THEN
  // hold: a read-only ProseMirror drops unread DOM input. Accepted writing,
  // in flight or queued, is saved; a failed save is retried once unchanged.
  // False at the deadline or on failure, still held: the caller decides.
  async function drain(deadline,reason='close') {
    if(closed)return false;
    for(;;) {
      while(composing()) if(!await wait(deadline))return false;
      if(!await wait(deadline,25))return false;
      if(!composing())break;
    }
    if(closed)return false;
    if(editor) {editor.view.domObserver.forceFlush();editor.view.domObserver.flush();}
    held=reason;syncEditable();setStatus();
    let retried=false;
    for(;;) {
      if(closed)return false;
      if(!working && !pendingCount())return true;
      if(!working && failed) {
        if(retried)return false;
        retried=true;failed=false;setStatus();
      }
      if(!working)void flush();
      if(!await wait(deadline))return false;
    }
  }
  // Hold without draining: an editor created after its page told native it
  // had nothing to save must not take input until native resumes it.
  function hold(reason='close') {if(!closed){held=reason;syncEditable();setStatus();}}
  function resume() {if(held){held=null;if(!closed){syncEditable();setStatus();}}}
  // The nearest scrolling ancestor actually holding this note's content.
  function scroller() {
    for(let el=content.parentElement;el && el!==document.body && el!==document.documentElement;el=el.parentElement) {
      if(/(auto|scroll)/.test(getComputedStyle(el).overflowY) && el.scrollHeight>el.clientHeight)return el;
    }
    return document.scrollingElement??document.documentElement;
  }
  // How far `pos` sits below the visible top of `area`, in CSS pixels. The
  // document scroller's visible top is the viewport's own.
  function offsetIn(area,pos) {
    const top=area===document.scrollingElement || area===document.documentElement ? 0 :
      area.getBoundingClientRect().top+area.clientTop;
    return editor.view.coordsAtPos(pos).top-top;
  }
  // An empty block has no text to anchor to, so y-tiptap names its end. Enter
  // in that block records in the note that its end moved on to the new block,
  // and resolving always follows the record: an empty line's caret showed at
  // the end of the note. Its start is the same place and Enter keeps it.
  const relative=(pos,binding)=>{
    const position=absolutePositionToRelativePosition(pos,fragment,binding.mapping);
    if(position.item===null && binding.prosemirrorView.state.doc.resolve(pos).parent.content.size===0)position.assoc=-1;
    return Array.from(Y.encodeRelativePosition(position));
  };
  function view() {
    const binding=editor && !closed && ySyncPluginKey.getState(editor.state)?.binding;
    if(!binding)return null;
    const {anchor,head}=editor.state.selection;
    return {version:1,anchor:relative(anchor,binding),head:relative(head,binding),cursorOffset:offsetIn(scroller(),head)};
  }
  const bytesHint=value=>Array.isArray(value) && value.length<=1024 &&
    value.every(byte=>Number.isInteger(byte) && byte>=0 && byte<256);
  const hint=options?.view;
  // The hint's position in the current document, or null if stale or malformed.
  function hinted(bytes) {
    const binding=editor && !closed && ySyncPluginKey.getState(editor.state)?.binding;
    if(!binding)return null;
    try {
      const pos=relativePositionToAbsolutePosition(doc,fragment,Y.decodeRelativePosition(Uint8Array.from(bytes)),binding.mapping);
      return Number.isInteger(pos) && pos>=0 && pos<=editor.state.doc.content.size ? pos : null;
    } catch {return null;}
  }
  // Applied once, and never over the person's own input or a newer load.
  let stopRestore=()=>{};
  if(hint?.version===1 && bytesHint(hint.anchor) && bytesHint(hint.head) &&
      Number.isFinite(hint.cursorOffset) && Math.abs(hint.cursorOffset)<=1e7) {
    let interrupted=false;
    const interrupt=()=>{interrupted=true;};
    const inputs=['keydown','pointerdown','wheel','touchstart'];
    for(const type of inputs)window.addEventListener(type,interrupt,{capture:true,passive:true});
    stopRestore=()=>{for(const type of inputs)window.removeEventListener(type,interrupt,{capture:true});};
    const live=()=>!closed && !interrupted && !!editor;
    // After the binding's first render, which y-tiptap defers by one task.
    setTimeout(()=>{
      if(!live()){stopRestore();return;}
      const anchor=hinted(hint.anchor),head=hinted(hint.head);
      if(anchor===null || head===null){stopRestore();return;}
      try {
        editor.view.dispatch(editor.state.tr.setSelection(TextSelection.create(editor.state.doc,anchor,head)).setMeta('addToHistory',false));
      } catch {stopRestore();return;}
      // Once fonts and layout settle, scroll the head back to its offset.
      void (document.fonts?.ready??Promise.resolve()).then(()=>requestAnimationFrame(()=>{
        stopRestore();
        if(!live())return;
        const at=hinted(hint.head);
        if(at===null)return;
        const area=scroller(),limit=area.scrollHeight-area.clientHeight;
        area.scrollTop=Math.max(0,Math.min(limit,area.scrollTop+offsetIn(area,at)-hint.cursorOffset));
      }));
    },0);
  }
  receive=bytes=>{
    if(closed) return;
    // Feed the persistent preflight copy before the live binding can observe
    // remote bytes. Unknown parts remain canonical, rendered inertly.
    let verdict;
    try {verdict=mirror?.apply(bytes)??{uncertain:true};} catch {verdict={uncertain:true};}
    if (verdict.uncertain) {
      // The disposable read failed. Suspend the binding, but still retain the
      // received update in the live copy before rebuilding a read-only view.
      if (editor) {editor.destroy();editor=null;}
      try {applyIncoming(bytes);} catch(error) {rebuildMirror();throw error;}
      rebuildMirror();return;
    }
    if (!verdict.supported && editor) {editor.destroy();editor=null;}
    const changes=new Set();
    const capture=events=>{for (const event of events) changes.add(event.target);};
    fragment.observeDeep(capture);
    try {applyIncoming(bytes);}
    catch(error) {rebuildMirror();throw error;}
    finally {fragment.unobserveDeep(capture);}
    refresh(verdict.supported,changes);checkSize();
  };
  for (const bytes of buffered) receive(bytes);
  return {
    retry:retrySave,
    drain,hold,resume,view,
    state() {return {mode:canAuthor()?'editable':'readonly',pending:pendingCount(),saved:!failed&&!pendingCount()&&!!editor};},
    close() {
      if(closed)return;
      closed=true;clearTimeout(savingTimer);changed();stopRestore();clearTimeout(peerTimer);for(const timer of peerHideTimers.values())clearTimeout(timer);peerHideTimers.clear();stopPeers();unsubscribe();editor?.destroy();editor=null;
      pending.close();mirror?.destroy();doc.destroy();doc=null;fragment=null;
      document.removeEventListener('mousedown',outside,true);document.removeEventListener('mousedown',pointerDown,true);
      window.removeEventListener('mouseup',pointerUp,true);window.removeEventListener('scroll',onScroll,true);window.removeEventListener('resize',relayout);
      if(android)for(const type of ['wheel','touchstart','pointerdown','keydown'])
        window.removeEventListener(type,onUserIntent,true);
      linkInput.value='';bubble.replaceChildren();linkPop.replaceChildren();content.replaceChildren();status.textContent='';
      status.remove();retryButton.remove();root.replaceChildren();
    },
  };
}
