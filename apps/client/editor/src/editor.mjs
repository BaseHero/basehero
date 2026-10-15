import * as Y from 'yjs';
import { Editor, Extension } from '@tiptap/core';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { ySyncPlugin, yUndoPlugin, ySyncPluginKey, yUndoPluginKey, undo, redo } from '@tiptap/y-tiptap';
import { extensions, createPreflightMirror, supportsProseMirror, safeViewNode, inventory } from './schema.mjs';
import { SaveQueue } from './save-queue.mjs';

// A host supplies an already-authorized note, not a base/account/path selector.
// Contract: open(onUpdate)->{state,unsubscribe} is an atomic snapshot +
// subscription from the already-bound host; commit(update,requestId)->
// {requestId} only after durable core commit. No Tauri commands here.
// Known limit: one giant paragraph can still lag during browser layout; the
// incremental preflight mirror does not reduce that rendering cost.
export async function createNoteEditor(root, host) {
  if (!host || typeof host.open!=='function' || typeof host.commit!=='function') throw new TypeError('bound note host required');
  const buffered=[];
  let receive=bytes=>buffered.push(bytes);
  const opened=await host.open(bytes=>receive(bytes));
  if (!opened || typeof opened.unsubscribe!=='function') throw new TypeError('atomic bound note open required');
  const {unsubscribe}=opened;
  let doc=new Y.Doc();
  try { Y.applyUpdate(doc,opened.state,'initial'); }
  catch(error) {unsubscribe();doc.destroy();throw error;}
  let fragment=doc.getXmlFragment(inventory.fragment);
  let mirror;
  try {mirror=createPreflightMirror(doc);} catch {mirror=null;}
  let editor=null, closed=false, working=false, failed=false;
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
  const pendingCount=()=>pending.count;
  root.replaceChildren();
  const controls=document.createElement('div');controls.className='note-controls';
  const status=document.createElement('p');status.dataset.status='';status.setAttribute('role','status');
  const retryButton=document.createElement('button');retryButton.type='button';retryButton.textContent='Retry save';retryButton.hidden=true;
  const content=document.createElement('div');content.className='note-content';
  // A bound native host must handle external links in the system browser later.
  // Until then, content itself cannot navigate the WebView.
  for (const type of ['click','auxclick']) content.addEventListener(type,event=>{
    if(event.target instanceof Element && event.target.closest('a')) event.preventDefault();
  },true);
  root.append(controls,content,status,retryButton);
  const retrySave=()=>{if(!closed && !working){failed=false;setStatus();void flush();}};
  retryButton.addEventListener('click',retrySave);
  const setStatus=()=>{
    retryButton.hidden=!failed;
    status.textContent=editor
      ? (failed ? 'Not saved · Retry' : pendingCount() ? 'Saving on this device…' : 'Saved on this device')
      : (pendingCount() ? 'Not saved · ' : '')+'Read-only · Update BaseHero to edit';
  };
  async function flush() {
    if (closed || working || failed || !pendingCount()) return;
    working=true;
    // An attempt's ID and bytes are fixed even when its result is uncertain.
    try {
      const item=pending.submit(requestId());
      // The host owns its submitted copy: disposing this editing view must
      // not zero bytes an in-flight durable commit still needs.
      const ack=await host.commit(new Uint8Array(item.bytes),item.id);
      if (closed) return;
      if (!ack || ack.requestId!==item.id) { failed=true; return; }
      pending.acknowledge();
    } catch { if (!closed) failed=true; }
    finally { working=false; if (!closed) {setStatus();if (!failed) void flush();} }
  }
  function action(label,run) {
    const button=document.createElement('button');button.type='button';button.textContent=label;
    button.addEventListener('mousedown',event=>event.preventDefault());
    button.addEventListener('click',()=>{if(editor) run(editor);});controls.append(button);
  }
  function history(command,e) {
    try {return command(e.state);} catch {
      // Yjs redoItem can throw after concurrent edits without emitting an
      // update. Keep the view usable; recheck any state it may have touched.
      rebuildMirror();return false;
    }
  }
  action('Undo',e=>history(undo,e));action('Redo',e=>history(redo,e));
  action('Bold',e=>e.chain().focus().toggleBold().run());
  action('Heading',e=>e.chain().focus().toggleHeading({level:2}).run());
  action('List',e=>e.chain().focus().toggleBulletList().run());
  action('Checklist',e=>e.chain().focus().toggleTaskList().run());
  const linkInput=document.createElement('input');linkInput.type='url';linkInput.setAttribute('aria-label','Link URL');
  linkInput.placeholder='https://…';controls.append(linkInput);
  action('Set link',e=>{
    const input=linkInput.value;
    try {
      const parsed=new URL(input);
      if (!inventory.marks.link.href.url.includes(parsed.protocol) || !parsed.hostname || /[\u0000-\u001f\u007f]/u.test(input)) return;
      e.chain().focus().setLink({href:input}).run();
    } catch { /* invalid input cannot create a link */ }
  });
  action('Remove link',e=>e.chain().focus().unsetLink().run());
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
    controls.hidden=true;
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
    controls.hidden=false;content.replaceChildren();readonlyNodes=new Map();
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
      }}),
    });
    const binding=Extension.create({
      name:'bhNoteBinding',priority:1100,
      addProseMirrorPlugins() {return [
        ownSelection,otherSelections,
        new Plugin({filterTransaction:tr=>{
          if(!tr.docChanged) return true;
          // A pasted/programmatic transaction must not introduce a value the
          // binding could write but the shared inventory cannot render safely.
          return supportsProseMirror(tr.doc);
        }}),ySyncPlugin(fragment),yUndoPlugin(),
      ];},
      addKeyboardShortcuts(){return {'Mod-z':()=>history(undo,this.editor),'Mod-Shift-z':()=>history(redo,this.editor),'Mod-y':()=>history(redo,this.editor)};},
    });
    editor=new Editor({element:content,extensions:[...extensions,binding],content:'',injectCSS:false});
    // No HTML from a note is ever passed to the editor or DOM.
    setStatus();sendSelection();
  }
  function fallbackReadonly() {
    if (editor) {editor.destroy();editor=null;}
    controls.hidden=true;readonlyNodes=new Map();content.replaceChildren();
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
      try {Y.applyUpdate(doc,bytes,'incoming');} catch(error) {rebuildMirror();throw error;}
      rebuildMirror();return;
    }
    if (!verdict.supported && editor) {editor.destroy();editor=null;}
    const changes=new Set();
    const capture=events=>{for (const event of events) changes.add(event.target);};
    fragment.observeDeep(capture);
    try {Y.applyUpdate(doc,bytes,'incoming');}
    catch(error) {rebuildMirror();throw error;}
    finally {fragment.unobserveDeep(capture);}
    refresh(verdict.supported,changes);
  };
  for (const bytes of buffered) receive(bytes);
  return {
    retry:retrySave,
    state() {return {mode:editor?'editable':'readonly',pending:pendingCount(),saved:!failed&&!pendingCount()&&!!editor};},
    close() {
      if(closed)return;
      closed=true;clearTimeout(peerTimer);stopPeers();unsubscribe();editor?.destroy();editor=null;
      pending.close();mirror?.destroy();doc.destroy();doc=null;fragment=null;
      linkInput.value='';controls.replaceChildren();content.replaceChildren();status.textContent='';root.replaceChildren();
    },
  };
}
