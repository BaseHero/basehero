import * as Y from 'yjs';
import {createNoteEditor} from '/note-editor.js';
let view,doc,listener,jobs=[];
function element(name,text,attrs={}) {
  const el=new Y.XmlElement(name);for(const [key,value] of Object.entries(attrs))el.setAttribute(key,value);
  if(text!==null) {const inner=new Y.XmlText();inner.insert(0,text);el.insert(0,[inner]);}
  return el;
}
function initial(kind) {
  doc=new Y.Doc(); const fragment=doc.getXmlFragment('default');
  if(kind==='rich') fragment.insert(0,[element('paragraph','intro'),element('heading','headline',{level:2})]);
  if(kind==='spaces'||kind==='spacesUnknown') fragment.insert(0,[element('paragraph','a  b')]);
  if(kind==='spacesUnknown') fragment.insert(1,[element('futureWidget','private',{payload:'keep'})]);
  if(kind==='racing') fragment.insert(0,[element('paragraph','before')]);
  if(kind==='node') fragment.insert(0,[element('futureWidget','private',{payload:'keep'})]);
  if(kind==='attr') fragment.insert(0,[element('paragraph','private',{futureAttr:'keep'})]);
  if(kind==='value') fragment.insert(0,[element('heading','private',{level:4})]);
  if(kind==='invalidStructure') {const list=element('bulletList',null);list.insert(0,[element('listItem',null)]);fragment.insert(0,[list]);}
  if(kind==='mark'||kind==='textAttr') {const p=element('paragraph',null);const t=new Y.XmlText();t.insert(0,'private',kind==='mark'?{futureMark:{secret:'keep'}}:{});if(kind==='textAttr')t.setAttribute('futureTextAttr','keep');p.insert(0,[t]);fragment.insert(0,[p]);}
}
window.harness={
  async open(kind) {
    view?.close();jobs=[];listener=null;if(kind!=='existing')initial(kind);
    view=await createNoteEditor(document.querySelector('#root'),{
      open:async callback=>{
        listener=callback;
        const state=Y.encodeStateAsUpdate(doc);
        if(kind==='racing') {
          const before=Y.encodeStateVector(doc);
          doc.getXmlFragment('default').insert(1,[element('paragraph','while opening')]);
          callback(Y.encodeStateAsUpdate(doc,before));
        }
        return {state,unsubscribe:()=>{listener=null;}};
      },
      commit:(bytes,id)=>new Promise((resolve,reject)=>jobs.push({bytes,id,resolve,reject})),
    });
    return {...view.state(),writes:jobs.length};
  },
  pending:()=>jobs.length,
  inFlight:()=>jobs[0]?{id:jobs[0].id,bytes:Array.from(jobs[0].bytes)}:null,
  close(){view.close();},
  ack(id) {const job=jobs.shift();if(!job)throw Error('no pending commit');if(id===undefined)Y.applyUpdate(doc,job.bytes);job.resolve({requestId:id??job.id});},
  reject(){const job=jobs.shift();if(!job)throw Error('no pending commit');job.reject(Error('disk full'));},
  retry(){view.retry();},
  incoming(kind){
    const beforeJobs=jobs.length;
    const before=Y.encodeStateVector(doc);
    const frag=doc.getXmlFragment('default');
    if(kind==='remote') frag.insert(frag.length,[element('paragraph','remote')]);
    if(kind==='unknown') frag.insert(frag.length,[element('futureWidget','future',{payload:'keep'})]);
    if(kind==='removeUnknown') {const index=frag.toArray().findIndex(el=>el.nodeName==='futureWidget');frag.delete(index,1);}
    listener(Y.encodeStateAsUpdate(doc,before));
    return {...view.state(),writes:jobs.length-beforeJobs};
  },
};
