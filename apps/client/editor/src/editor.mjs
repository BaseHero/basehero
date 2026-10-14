import * as Y from 'yjs';
import { Editor, Extension } from '@tiptap/core';
import { Plugin } from '@tiptap/pm/state';
import { ySyncPlugin, yUndoPlugin, ySyncPluginKey, yUndoPluginKey, undo, redo, prosemirrorToYXmlFragment } from '@tiptap/y-tiptap';
import { extensions, classify, canBind, safeView, inventory } from './schema.mjs';

// A host supplies an already-authorized note, not a base/account/path selector.
// Contract: open(onUpdate)->{state,unsubscribe} is an atomic snapshot +
// subscription from the already-bound host; commit(update,requestId)->
// {requestId} only after durable core commit. No Tauri commands here.
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
  let editor=null, closed=false, working=false, failed=false;
  const requestId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('');
  const pending=[];
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
      ? (failed ? 'Not saved · Retry' : pending.length ? 'Saving on this device…' : 'Saved on this device')
      : (pending.length ? 'Not saved · ' : '')+'Read-only · Update BaseHero to edit';
  };
  async function flush() {
    if (closed || working || failed || !pending.length) return;
    working=true;
    const item=pending[0];
    try {
      // The host owns its submitted copy: disposing this editing view must
      // not zero bytes an in-flight durable commit still needs.
      const ack=await host.commit(new Uint8Array(item.bytes),item.id);
      if (closed) return;
      if (!ack || ack.requestId!==item.id) { failed=true; return; }
      pending.shift().bytes.fill(0);
    } catch { if (!closed) failed=true; }
    finally { working=false; if (!closed) {setStatus();if (!failed) void flush();} }
  }
  function action(label,run) {
    const button=document.createElement('button');button.type='button';button.textContent=label;
    button.addEventListener('mousedown',event=>event.preventDefault());
    button.addEventListener('click',()=>{if(editor) run(editor);});controls.append(button);
  }
  action('Undo',e=>undo(e.state));action('Redo',e=>redo(e.state));
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
  function showReadonly() {
    if (editor) { editor.destroy();editor=null; }
    controls.hidden=true;content.replaceChildren();
    const make=item=>{
      const el=document.createElement(item.placeholder?'span':'div');
      if (item.placeholder) {el.textContent='Unsupported content';el.className='note-placeholder';}
      else if ('text' in item) el.textContent=item.text;
      else {el.className='note-'+item.label;for(const child of item.children)el.append(make(child));}
      return el;
    };
    for (const item of safeView(fragment)) content.append(make(item));
    setStatus();
  }
  function showEditable() {
    if (editor) {setStatus();return;}
    controls.hidden=false;content.replaceChildren();
    const binding=Extension.create({
      name:'bhNoteBinding',priority:1100,
      addProseMirrorPlugins() {return [
        new Plugin({filterTransaction:tr=>{
          if(!tr.docChanged) return true;
          // A pasted/programmatic transaction must not introduce a value the
          // binding could write but the shared inventory cannot render safely.
          const copy=new Y.Doc();
          try {prosemirrorToYXmlFragment(tr.doc,copy.getXmlFragment(inventory.fragment));
            return classify(copy.getXmlFragment(inventory.fragment)).supported;
          } catch {return false;} finally {copy.destroy();}
        }}),ySyncPlugin(fragment),yUndoPlugin(),
      ];},
      addKeyboardShortcuts(){return {'Mod-z':()=>undo(this.editor.state),'Mod-Shift-z':()=>redo(this.editor.state),'Mod-y':()=>redo(this.editor.state)};},
    });
    editor=new Editor({element:content,extensions:[...extensions,binding],content:'',injectCSS:false});
    // No HTML from a note is ever passed to the editor or DOM.
    setStatus();
  }
  function refresh() {if (canBind(fragment)) showEditable();else showReadonly();}
  doc.on('update',(bytes,origin)=>{
    const localUndo=editor && yUndoPluginKey.getState(editor.state)?.undoManager;
    if (closed || (origin!==ySyncPluginKey && origin!==localUndo)) return;
    pending.push({bytes:new Uint8Array(bytes),id:requestId()});
    setStatus();void flush();
  });
  refresh();
  receive=bytes=>{
    if(closed) return;
    // Preflight on a disposable copy before the live binding sees incoming data.
    // Unknown parts stay canonical in the editing copy, without running an editor.
    const candidate=new Y.Doc();
    Y.applyUpdate(candidate,Y.encodeStateAsUpdate(doc),'copy');
    try { Y.applyUpdate(candidate,bytes,'incoming'); }
    catch { candidate.destroy();return; }
    const supported=canBind(candidate.getXmlFragment(inventory.fragment));
    if (!supported && editor) { editor.destroy();editor=null; }
    Y.applyUpdate(doc,bytes,'incoming');
    candidate.destroy();
    refresh();
  };
  for (const bytes of buffered) receive(bytes);
  return {
    retry:retrySave,
    state() {return {mode:editor?'editable':'readonly',pending:pending.length,saved:!failed&&!pending.length&&!!editor};},
    close() {
      if(closed)return;
      closed=true;unsubscribe();editor?.destroy();editor=null;
      for (const item of pending) item.bytes.fill(0);
      pending.length=0;doc.destroy();doc=null;fragment=null;
      linkInput.value='';controls.replaceChildren();content.replaceChildren();status.textContent='';root.replaceChildren();
    },
  };
}
