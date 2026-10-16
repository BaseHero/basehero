import * as Y from 'yjs';
import { Editor, Extension } from '@tiptap/core';
import { Plugin, PluginKey, TextSelection } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { ySyncPlugin, yUndoPlugin, ySyncPluginKey, yUndoPluginKey, undo, redo,
  absolutePositionToRelativePosition, relativePositionToAbsolutePosition } from '@tiptap/y-tiptap';
import { extensions, createPreflightMirror, supportsProseMirror, safeViewNode, inventory, withinEditingLimit, editingPositions, isLeafNode } from './schema.mjs';
import { SaveQueue } from './save-queue.mjs';
import { WriterGuard, editBound, historyBound, historyGrowth } from './writer.mjs';

const TOO_LARGE='This note has reached its size limit, about one million characters. That change wasn’t added.';
const PAUSED='Editing is paused until your writing is saved. It picks up again by itself in a moment.';
const REPLAY_DROPPED='That change wasn’t added because the note changed meanwhile. Try it again.';
const UNDO_TOO_LARGE='Undo isn’t available this close to the note’s size limit, about one million characters. Delete something first.';

// A host supplies an already-authorized note, not a base/account/path selector.
// Contract: open(onUpdate,options)->{state,clientId,unsubscribe} is an atomic
// snapshot + subscription from the already-bound host; options {retire:true}
// asks it to retire this view's current writer for a fresh one after a drain.
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
  try { Y.applyUpdate(doc,opened.state,'initial'); }
  catch(error) {unsubscribe();doc.destroy();throw error;}
  let fragment=doc.getXmlFragment(inventory.fragment);
  let mirror;
  try {mirror=createPreflightMirror(doc);} catch {mirror=null;}
  let editor=null, closed=false, working=false, failed=false, flushing=null;
  // An operation refused for writer capacity waits here for a fresh writer.
  let rollover=null, replaying=false;
  // A note over the shared editing size stays readable; local authoring stops.
  // A lifecycle hold (drain) is separate from the writer's own unsafe holds:
  // resuming one never lifts the other.
  let tooLarge=false, editable=null, held=null;
  const canAuthor=()=>!!editor && !writer.blocked && !tooLarge && !held;
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
  let writer;
  try {writer=new WriterGuard(doc,opened.clientId,()=>syncEditable());}
  catch(error) {unsubscribe();doc.destroy();throw error;}
  const peerKey=new PluginKey('bhPeerSelections');
  let peerTimer=null;
  const receivePeer=event=>{
    if (!editor || closed || !event?.id) return;
    editor.view.dispatch(editor.state.tr.setMeta(peerKey,event));
  };
  const stopPeers=host.onPeers?.(receivePeer)??(()=>{});
  function sendSelection() {
    if (peerTimer || !host.selection || !editor || closed) return;
    peerTimer=setTimeout(()=>{
      peerTimer=null;
      if (!editor || closed) return;
      const {anchor,head}=editor.state.selection;
      void Promise.resolve(host.selection(anchor,head)).then(peers=>{
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
  // A bound native host must handle external links in the system browser later.
  // Until then, content itself cannot navigate the WebView.
  for (const type of ['click','auxclick']) content.addEventListener(type,event=>{
    if(event.target instanceof Element && event.target.closest('a')) event.preventDefault();
  },true);
  const bubble=document.createElement('div');bubble.className='note-bubble';bubble.hidden=true;
  bubble.setAttribute('role','toolbar');bubble.setAttribute('aria-label','Format');
  const linkPop=document.createElement('div');linkPop.className='note-linkpop';linkPop.hidden=true;
  linkPop.setAttribute('role','dialog');linkPop.setAttribute('aria-label','Link');
  root.append(notice,large,content,bubble,linkPop);
  if(options.statusBar)options.statusBar.replaceChildren(status,retryButton);else root.append(status,retryButton);
  const retrySave=()=>{if(!closed && !working){failed=false;setStatus();void (writer.paused?reacquire():flush());}};
  retryButton.addEventListener('click',retrySave);
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
    const unsaved=failed || writer.paused || !!rollover;
    const saving=failed || writer.paused ? 'Not saved' : rollover ? 'Not saved · Editing paused' : hasPending && Date.now()-savingSince>=1000 ? 'Saving…' : 'Saved on this Mac';
    const text=held==='update' && !failed ? 'Saving before update…' : !editor
      ? (pendingCount() ? 'Not saved · ' : '')+'Read-only · Update BaseHero to edit' : saving;
    if(status.textContent!==text)status.textContent=text;
    status.dataset.status=unsaved ? 'failed' : text==='Saved on this Mac' ? 'saved' : !editor ? 'readonly' : 'busy';
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
  async function holdAndDrain() {
    writer.hold();await flush();
    return !closed && !failed && !pendingCount();
  }
  // A refused operation starts at most one rollover; its replay never starts
  // another, so an operation that a fresh writer cannot take is just dropped.
  function admit(bound,replay) {
    const verdict=writer.admit(bound);
    if(verdict==='fit')return true;
    if(verdict==='rollover' && !rollover && !replaying) {
      rollover={replay};setStatus();queueMicrotask(()=>{if(!closed)void reacquire();});
    }
    return false;
  }
  async function reacquire() {
    const resumed=await writer.reacquire(holdAndDrain,async()=>{
      // A writer whose terminal save already ended its lease reopens normally.
      const retire=!!rollover && !writer.spent;
      const next=await host.open(bytes=>receive(bytes),retire?{retire:true}:undefined);
      if(closed){next.unsubscribe();throw Error('closed view');}
      const previous=unsubscribe;unsubscribe=next.unsubscribe;previous();
      return {clientId:next.clientId,hydrate(){receive(next.state);}};
    });
    if(!closed){
      if(!resumed)failed=true;syncEditable();setStatus();
      if(resumed && rollover) {
        const {replay}=rollover;rollover=null;replaying=true;
        try {replay();} finally {replaying=false;}
      }
    }
    return resumed;
  }
  function history(command,e) {
    if(!canAuthor())return false;
    const manager=yUndoPluginKey.getState(e.state)?.undoManager;
    const stack=manager && (command===undo?manager.undoStack:manager.redoStack);
    // Yjs applies an item as a whole: refuse before it could pass the limit.
    if(stack && pending.full) {say(PAUSED);return true;}
    if(stack && e.state.doc.nodeSize+historyGrowth(doc.store,stack,isLeafNode)>editingPositions &&
        historyGrowth(doc.store,stack,isLeafNode)>0) {say(UNDO_TOO_LARGE);return true;}
    // Handled either way: the action waits for a fresh writer or is refused.
    if(stack && !admit(historyBound(stack),()=>{if(editor)history(command,editor);}))return true;
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
  linkPop.append(linkInput,linkDone,linkRemove);
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
    linkInput.removeAttribute('aria-invalid');
    linkPop.hidden=false;bubble.hidden=true;placeLink();
    linkInput.focus();linkInput.select();
    return true;
  }
  function closeLink(refocus) {
    if(linkPop.hidden)return;
    linkPop.hidden=true;
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
  const relayout=()=>{placeBubble();placeLink();};
  const pointerDown=event=>{if(content.contains(event.target)){pointerSelecting=true;bubble.hidden=true;}};
  const pointerUp=()=>{if(pointerSelecting){pointerSelecting=false;placeBubble();}};
  document.addEventListener('mousedown',outside,true);
  document.addEventListener('mousedown',pointerDown,true);
  window.addEventListener('mouseup',pointerUp,true);
  window.addEventListener('scroll',relayout,true);
  window.addEventListener('resize',relayout);
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
          else if (message.type==='set' && Number.isSafeInteger(message.anchor) && Number.isSafeInteger(message.head))
            next.set(message.id,{anchor:message.anchor,head:message.head});
          return next;
        },
      },
      props:{decorations(state){
        const decorations=[];
        for (const [id,{anchor,head}] of peerKey.getState(state)) {
          const max=state.doc.content.size;
          const from=Math.max(0,Math.min(anchor,head,max));
          const to=Math.max(0,Math.min(Math.max(anchor,head),max));
          if (from!==to) decorations.push(Decoration.inline(from,to,{class:'bh-peer-selection','data-peer':id}));
          decorations.push(Decoration.widget(Math.max(0,Math.min(head,max)),()=>{
            const marker=document.createElement('span');marker.className='bh-peer-cursor';
            marker.setAttribute('aria-hidden','true');marker.dataset.peer=id;return marker;
          },{side:-1,key:'bh-peer:'+id}));
        }
        return DecorationSet.create(state.doc,decorations);
      }},
      view:()=>({update(view,previous){
        if (!view.state.selection.eq(previous.selection) || view.state.doc!==previous.doc) sendSelection();
        // Incoming, Undo and Redo projections can change the size too.
        if (view.state.doc!==previous.doc) queueMicrotask(checkSize);
      }}),
    });
    const binding=Extension.create({
      name:'bhNoteBinding',priority:1100,
      addProseMirrorPlugins() {return [
        ownSelection,otherSelections,
        new Plugin({filterTransaction:tr=>{
          if(!tr.docChanged) return true;
          // Only the binding's own projections of Yjs changes (remote, Undo,
          // Redo) carry its meta; they write nothing further to Yjs.
          const projected=tr.getMeta(ySyncPluginKey);
          // A drain already read the last DOM input before holding.
          if((writer.blocked || held) && !projected)return false;
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
          if(!admit(editBound(tr.doc.nodeSize),()=>{
            if(editor && editor.state.doc===tr.before)editor.view.dispatch(tr);
            else say(REPLAY_DROPPED);
          }))return false;
          say('');return true;
        }}),ySyncPlugin(fragment),yUndoPlugin(),
      ];},
      addKeyboardShortcuts(){return {'Mod-z':()=>history(undo,this.editor),'Mod-Shift-z':()=>history(redo,this.editor),'Mod-y':()=>history(redo,this.editor),'Mod-k':()=>openLink()};},
    });
    editable=!writer.blocked && !tooLarge && !held;
    editor=new Editor({element:content,extensions:[...extensions,binding],content:'',injectCSS:false,editable});
    for(const event of ['selectionUpdate','focus','blur','transaction'])editor.on(event,()=>queueMicrotask(placeBubble));
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
    // Authoring already stops synchronously (blocked); hold outside this
    // binding transaction, drain the terminal work, then reacquire.
    if(writer.spent)queueMicrotask(()=>{if(!closed)void reacquire();});
    setStatus();void flush();
  });
  refresh(mirror?.supported??false);
  function applyIncoming(bytes) {
    const wasPaused=writer.paused;
    try {writer.apply(()=>Y.applyUpdate(doc,bytes,'incoming'));}
    finally {
      if(!wasPaused && writer.paused)queueMicrotask(()=>{if(!closed)void reacquire();});
    }
  }
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
  const relative=(pos,binding)=>Array.from(Y.encodeRelativePosition(absolutePositionToRelativePosition(pos,fragment,binding.mapping)));
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
    holdAndDrain,
    reacquire,
    state() {return {mode:canAuthor()?'editable':'readonly',pending:pendingCount(),saved:!failed&&!writer.paused&&!pendingCount()&&!!editor};},
    close() {
      if(closed)return;
      closed=true;clearTimeout(savingTimer);changed();stopRestore();clearTimeout(peerTimer);stopPeers();unsubscribe();editor?.destroy();editor=null;
      pending.close();mirror?.destroy();doc.destroy();doc=null;fragment=null;
      document.removeEventListener('mousedown',outside,true);document.removeEventListener('mousedown',pointerDown,true);
      window.removeEventListener('mouseup',pointerUp,true);window.removeEventListener('scroll',relayout,true);window.removeEventListener('resize',relayout);
      linkInput.value='';bubble.replaceChildren();linkPop.replaceChildren();content.replaceChildren();status.textContent='';
      status.remove();retryButton.remove();root.replaceChildren();
    },
  };
}
