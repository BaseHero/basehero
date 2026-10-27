import test from 'node:test';
import assert from 'node:assert/strict';
import {getSchema} from '@tiptap/core';
import {Node as PMNode} from '@tiptap/pm/model';
import {extensions,supportsProseMirror} from '../../src/lib/editor/schema.mjs';
const s=getSchema(extensions),p=text=>s.nodes.paragraph.create(null,s.text(text));
test('unchanged immutable PM subtrees are not revalidated per transaction',()=>{
  const old=p('stable');let checks=0;
  const original=old.type.validContent;
  old.type.validContent=function(...args){checks++;return original.apply(this,args);};
  try {
    assert.equal(supportsProseMirror(s.nodes.doc.create(null,[old,p('one')])),true);
    const first=checks;
    assert.equal(supportsProseMirror(s.nodes.doc.create(null,[old,p('two')])),true);
    assert.equal(checks-first,1,'only new paragraph validated');
  } finally {old.type.validContent=original;}
});
test('cached subtree still checks parent on every occurrence and validates newly invalid descendants',()=>{
  const nested=s.nodes.paragraph.create(null,s.text('old'));
  assert.equal(supportsProseMirror(s.nodes.doc.create(null,[nested])),true);
  const quoted=s.nodes.blockquote.create(null,nested);
  assert.equal(supportsProseMirror(s.nodes.doc.create(null,[quoted])),true,'legal reparent');
  const invalid=s.nodes.bulletList.create(null,[nested]);
  assert.equal(supportsProseMirror(s.nodes.doc.create(null,[invalid])),false,'cached paragraph disallowed in list');
  const bad=s.nodes.heading.create({level:4},s.text('future'));
  const newQuote=s.nodes.blockquote.create(null,[nested,bad]);
  assert.equal(supportsProseMirror(s.nodes.doc.create(null,[newQuote])),false,'new invalid descendant');
});

test('blockquote chain accepts depth 128 but refuses a text node beyond it',()=>{
  const quote=level=>{
    let node=p('deep');
    for(let i=0;i<level;i++) node=s.nodes.blockquote.create(null,node);
    return s.nodes.doc.create(null,node);
  };
  assert.equal(supportsProseMirror(quote(126)),true,'text in 126 quotes is at depth 128');
  assert.equal(supportsProseMirror(quote(127)),false,'text in 127 quotes exceeds depth 128');
});
test('task-list chain accepts 63 nested levels but refuses 64',()=>{
  const task=level=>{
    let node=s.nodes.taskList.create(null,s.nodes.taskItem.create(null,p('deep')));
    for(let i=1;i<level;i++) node=s.nodes.taskList.create(null,
      s.nodes.taskItem.create(null,[p('item'),node]));
    return s.nodes.doc.create(null,node);
  };
  assert.equal(supportsProseMirror(task(63)),true,'63 nested task lists fit');
  assert.equal(supportsProseMirror(task(64)),false,'64 nested task lists exceed the bound');
});
test('local paste refuses an outline deeper than level 63, including cached subtrees',()=>{
  const outline=level=>{
    let node=s.nodes.bulletList.create(null,s.nodes.listItem.create(null,p('deep')));
    for(let i=1;i<level;i++) node=s.nodes.bulletList.create(null,
      s.nodes.listItem.create(null,[p('item'),node]));
    return s.nodes.doc.create(null,node);
  };
  const allowed=outline(63);
  assert.equal(supportsProseMirror(allowed),true);
  assert.equal(supportsProseMirror(outline(64)),false);
  // A formerly valid cached subtree is not legal when reparented deeper.
  const wrapper=s.nodes.bulletList.create(null,s.nodes.listItem.create(null,[p('item'),allowed.firstChild]));
  assert.equal(supportsProseMirror(s.nodes.doc.create(null,wrapper)),false);
});

test('incremental validator matches recursive PM check for local attributes and mark sets',()=>{
  const bold=s.marks.bold.create(),italic=s.marks.italic.create();
  const text=s.text('ordinary');
  const cases=[
    s.nodes.doc.create(null,[p('ordinary')]),
    s.nodes.doc.create(null,[s.nodes.paragraph.create(null,s.text('ordinary',[bold,italic]))]),
    s.nodes.doc.create(null,[s.nodes.heading.create({level:2},s.text('heading'))]),
    s.nodes.doc.create(null,[new PMNode(s.nodes.paragraph,{},p('x').content,[bold])]),
    s.nodes.doc.create(null,[s.nodes.paragraph.create(null,new PMNode(s.nodes.text,text.attrs,text.content,[bold,bold]))]),
    s.nodes.doc.create(null,[s.nodes.paragraph.create(null,new PMNode(s.nodes.text,text.attrs,text.content,[italic,bold]))]),
    new PMNode(s.nodes.doc,{future:true},s.nodes.doc.create(null,[p('ordinary')]).content),
  ];
  for(const doc of cases) {
    let valid=true;try{doc.check();}catch{valid=false;}
    assert.equal(supportsProseMirror(doc),valid,doc.toString());
  }
});
