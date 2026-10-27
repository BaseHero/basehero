import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,copyFileSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import * as Y from 'yjs';
import {createPreflightMirror} from '../../src/lib/editor/schema.mjs';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

const editor=new URL('../../',import.meta.url).pathname;
const names=['src/types/YText.js','dist/yjs.mjs','dist/yjs.cjs'];
const script=new URL('../../scripts/patch-yjs.mjs',import.meta.url).pathname;
function scratch(){
  const dir=mkdtempSync(join(tmpdir(),'bh-editor-yjs-'));
  for(const name of names){mkdirSync(join(dir,...name.split('/').slice(0,-1)),{recursive:true});copyFileSync(join(editor,'node_modules/yjs',name),join(dir,name));}
  // The preparer accepts a package root, never searches for another Yjs copy.
  copyFileSync(join(editor,'node_modules/yjs/package.json'),join(dir,'package.json'));
  return dir;
}
const run=dir=>spawnSync(process.execPath,[script,dir],{encoding:'utf8'});

test('pinned output check accepts patched files and rejects each pristine dist file',async t=>{
  const {assertPatchedYjs}=await import(pathToFileURL(script));
  assert.equal(typeof assertPatchedYjs,'function');
  const dir=scratch();t.after(()=>rmSync(dir,{recursive:true,force:true}));
  assert.doesNotThrow(()=>assertPatchedYjs(dir));
  const packed=spawnSync('npm',['pack','--offline','--ignore-scripts','--pack-destination',dir,'https://registry.npmjs.org/yjs/-/yjs-13.6.33.tgz'],{encoding:'utf8',cwd:dir});
  assert.equal(packed.status,0,packed.stderr);
  const extracted=spawnSync('tar',['-xzf',join(dir,packed.stdout.trim()),'-C',dir],{encoding:'utf8'});
  assert.equal(extracted.status,0,extracted.stderr);
  for(const name of names.filter(name=>name.startsWith('dist/'))){
    copyFileSync(join(dir,'package',name),join(dir,name));
    assert.throws(()=>assertPatchedYjs(dir),new RegExp(`patched Yjs.*${name}`));
    copyFileSync(join(editor,'node_modules/yjs',name),join(dir,name));
  }
  assert.doesNotThrow(()=>assertPatchedYjs(dir));
});

test('schema and Tiptap resolve the same Yjs instance as the editor',()=>{
  const schema=createRequire(new URL('../../src/lib/editor/schema.mjs',import.meta.url));
  const binding=createRequire(new URL('../../node_modules/@tiptap/y-tiptap/dist/index.js',import.meta.url));
  assert.equal(schema.resolve('yjs'),binding.resolve('yjs'));
  assert.equal(schema.resolve('yjs'),createRequire(import.meta.url).resolve('yjs'));
  const doc=new Y.Doc(),mirror=createPreflightMirror(doc);
  assert.ok(mirror.doc instanceof Y.Doc);
  mirror.destroy();doc.destroy();
});

test('preparation is idempotent and refuses a changed file without partial modification',t=>{
  const dir=scratch();t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const first=run(dir);assert.equal(first.status,0,first.stderr);
  const before=names.map(name=>readFileSync(join(dir,name)));
  const second=run(dir);assert.equal(second.status,0,second.stderr);
  assert.deepEqual(names.map(name=>readFileSync(join(dir,name))),before);
  writeFileSync(join(dir,names[1]),Buffer.concat([before[1],Buffer.from('\n// tampered\n')]));
  const failed=run(dir);assert.notEqual(failed.status,0);
  assert.match(failed.stderr,/hash|content|refus/i);
  assert.deepEqual(readFileSync(join(dir,names[0])),before[0]);
  assert.deepEqual(readFileSync(join(dir,names[2])),before[2]);
});

test('preparation refuses wrong Yjs version before touching an otherwise valid install',t=>{
  const dir=scratch();t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const before=names.map(name=>readFileSync(join(dir,name)));
  const badVersion=JSON.parse(readFileSync(join(dir,'package.json')));
  badVersion.version='13.6.34';writeFileSync(join(dir,'package.json'),JSON.stringify(badVersion));
  const refused=run(dir);
  assert.notEqual(refused.status,0);assert.match(refused.stderr,/non-pinned Yjs/);
  assert.deepEqual(names.map(name=>readFileSync(join(dir,name))),before);
});
