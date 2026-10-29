// @ts-nocheck
import { Node } from '@tiptap/core';

export const validObjectId = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);

export const imageNode = Node.create({
  name: 'image', group: 'block', atom: true, selectable: true,
  addOptions() { return { backend: null, r: null, fileR: null, objectUrl: null, releaseObjectUrl: null }; },
  addAttributes() { return { file: { default: null } }; },
  parseHTML() { return [{ tag: 'img[data-bh-file]', getAttrs: element => {
    const file=element.getAttribute('data-bh-file');
    return validObjectId(file) ? { file } : false;
  } }]; },
  renderHTML({node}) { return ['img', {'data-bh-file':node.attrs.file}]; },
  addNodeView() {
    const {backend,r,fileR,objectUrl,releaseObjectUrl}=this.options;
    return ({node}) => {
      const dom=document.createElement('div');dom.className='note-image';
      let alive=true, generation=0, using=null;
      const file=node.attrs.file;
      async function refresh() {
        const current=++generation;
        if (using) {releaseObjectUrl(using,file);using=null;}
        dom.replaceChildren();
        if (!backend || !r || !validObjectId(file)) {dom.textContent="Can't show this image";return;}
        try {
          // The mount-point document lives in the outer base; new files live in
          // its mounted base, while images added before grants may still be here.
          let ref=r, info=null;
          if (fileR) {
            try {info=await backend.fileInfo(fileR,file);if(info)ref=fileR;}
            catch { /* The mounted base may not be on this device yet. */ }
          }
          if (!info) info=await backend.fileInfo(r,file);
          if (!alive || current!==generation) return;
          if (!info || info.status.kind==='broken') {dom.textContent="Can't show this image";return;}
          if (info.status.kind!=='here') {dom.textContent='Image not on this device yet';return;}
          try {
            const url=await objectUrl(ref,file);
            if (!alive || current!==generation) {releaseObjectUrl(ref,file);return;}
            using=ref;
            const img=document.createElement('img');
            img.setAttribute('src',url);
            img.setAttribute('alt',info.name);
            img.setAttribute('class','note-image-content');
            dom.replaceChildren(img);
          } catch (error) {
            if (!alive || current!==generation) return;
            if (error?.kind!=='Invalid') {dom.textContent="Can't show this image";return;}
            const name=document.createElement('span');name.textContent=info.name;
            const open=document.createElement('button');open.type='button';open.textContent='Open';
            open.addEventListener('click',()=>{void backend.fileOpen(ref,file);});
            dom.replaceChildren(name,open);
          }
        } catch {if(alive && current===generation)dom.textContent="Can't show this image";}
      }
      let stop=()=>{};
      if (backend) void backend.onEvent(event=>{
        if (event.kind==='base' && event.account===r.account && (event.base===r.base || event.base===fileR?.base) &&
          event.event?.filesChanged?.includes(file)) void refresh();
      }).then(unsubscribe=>{if(alive)stop=unsubscribe;else unsubscribe();});
      void refresh();
      return {dom, destroy(){alive=false;generation++;stop();if(using)releaseObjectUrl(using,file);}};
    };
  },
});
