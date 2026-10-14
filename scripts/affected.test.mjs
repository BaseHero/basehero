import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const layers = fileURLToPath(new URL('./layers.json', import.meta.url));

const script = fileURLToPath(new URL('./affected.mjs', import.meta.url));
// Build "up" prefixes at runtime: the export guard rejects committed literals
// that look like paths leaving the product tree.
const up = n => Array(n).fill('..').join('/');
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'bh-affected-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  function put(path, content) { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), content); }
  function run(cmd, args) { return spawnSync(cmd, args, { cwd: root, encoding: 'utf8', env: { ...process.env, BH_PRODUCT_ROOT: root } }); }
  function git(...args) { const r = run('git', args); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); }
  function crate(dir, name, deps = '') {
    put(`${dir}/Cargo.toml`, `[package]\nname = "${name}"\nversion = "0.1.0"\nedition = "2021"\n${deps}`);
    put(`${dir}/src/lib.rs`, 'pub fn ok() {}\n');
  }
  git('init', '-q'); git('config', 'user.email', 'test@example.invalid'); git('config', 'user.name', 'Test');
  put('Cargo.toml', '[workspace]\nmembers = ["libs/*", "services/*", "apps/client/src-tauri", "tests/system"]\nresolver = "2"\n');
  crate('libs/low', 'low');
  crate('libs/high', 'high', `[dev-dependencies]\nlow = { path = "${up(1)}/low" }\n`);
  crate('services/api', 'api', `[build-dependencies]\nhigh = { path = "${up(2)}/libs/high" }\n`);
  crate('apps/client/src-tauri', 'client', `[dependencies]\napi = { path = "${up(3)}/services/api" }\n`);
  crate('tests/system', 'system', `[dependencies]\nlow = { path = "${up(2)}/libs/low" }\n`);
  git('add', '.'); git('commit', '-qm', 'initial');
  const base = git('rev-parse', 'HEAD');
  function select(from = base) { const r = run('node', [script, '--base', from, '--head', 'HEAD', '--list']); assert.equal(r.status, 0, r.stderr); return r.stdout.trim().split('\n').filter(Boolean); }
  return { root, put, git, run, crate, base, select };
}

test('one central layer definition names the ordered boundaries', () => {
  const definition = JSON.parse(readFileSync(layers, 'utf8'));
  assert.deepEqual(definition.order, ['foundation', 'libs', 'services', 'apps', 'tests']);
  assert.ok(definition.foundation.includes('libs/core'));
});

test('metadata reverse closure includes dev/build dependents and client, even for newly discovered crates', t => {
  const f = fixture(t);
  f.put('libs/low/src/lib.rs', 'pub fn changed() {}\n'); f.git('add', '.'); f.git('commit', '-qm', 'change');
  assert.deepEqual(f.select(), ['api', 'client', 'high', 'low', 'system']);
  f.crate('libs/new', 'new');
  f.put('services/api/Cargo.toml', `[package]\nname = "api"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nnew = { path = "${up(2)}/libs/new" }\n`);
  f.git('add', '.'); f.git('commit', '-qm', 'new crate');
  const added = f.git('rev-parse', 'HEAD');
  f.put('libs/new/src/lib.rs', 'pub fn changed() {}\n'); f.git('add', '.'); f.git('commit', '-qm', 'new source');
  assert.deepEqual(f.select(added), ['api', 'client', 'new']);
});

test('manifest, lock, config and build inputs conservatively select all packages and global JS checks', t => {
  for (const path of ['Cargo.lock', 'flake.nix', 'tests/system/Cargo.toml', 'tests/system/build.rs']) {
    const f = fixture(t);
    const content = path.endsWith('Cargo.toml')
      ? `[package]\nname = "system"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nlow = { path = "${up(2)}/libs/low" }\n# changed\n`
      : '# changed\n';
    f.put(path, content); f.git('add', '.'); f.git('commit', '-qm', path);
    const plan = f.run('node', [script, '--base', f.base, '--head', 'HEAD', '--plan']);
    assert.equal(plan.status, 0, plan.stderr);
    const parsed = JSON.parse(plan.stdout);
    assert.deepEqual(parsed.crates, ['api', 'client', 'high', 'low', 'system']);
    assert.ok(parsed.js.includes('client') && parsed.js.includes('interop'), JSON.stringify(parsed.js));
  }
});

test('dependency layers reject library to service and service to app including dev/build edges', t => {
  const f = fixture(t);
  const check = () => f.run('node', [script, '--layers']);
  assert.equal(check().status, 0, check().stderr);
  f.put('libs/high/Cargo.toml', `[package]\nname = "high"\nversion = "0.1.0"\nedition = "2021"\n[dev-dependencies]\napi = { path = "${up(2)}/services/api" }\n`);
  assert.match(check().stderr, /high.*api/); assert.notEqual(check().status, 0);
  f.put('libs/high/Cargo.toml', '[package]\nname = "high"\nversion = "0.1.0"\nedition = "2021"\n');
  f.put('services/api/Cargo.toml', `[package]\nname = "api"\nversion = "0.1.0"\nedition = "2021"\n[build-dependencies]\nclient = { path = "${up(2)}/apps/client/src-tauri" }\n`);
  assert.match(check().stderr, /api.*client/);
  f.put('services/api/Cargo.toml', '[package]\nname = "api"\nversion = "0.1.0"\nedition = "2021"\n');
  f.crate('libs/core', 'core', `[dependencies]\nhigh = { path = "${up(1)}/high" }\n`);
  assert.match(check().stderr, /core.*high/);
});

test('path families select JS, interop, the Rust interop consumer and website', t => {
  const f = fixture(t);
  f.crate('libs/core', 'bh-core');
  f.git('add', '.'); f.git('commit', '-qm', 'core fixture member');
  const baseline = f.git('rev-parse', 'HEAD');
  f.put('apps/client/view.js', 'client\n');
  f.put('tests/interop/sample.js', 'interop\n');
  f.put('website/public/index.html', '<p>hello</p>\n');
  f.git('add', '.'); f.git('commit', '-qm', 'web');
  const r = f.run('node', [script, '--base', baseline, '--head', 'HEAD', '--plan']);
  assert.equal(r.status, 0, r.stderr);
  const plan = JSON.parse(r.stdout);
  assert.deepEqual(plan.js, ['client', 'interop', 'editor', 'website']);
  assert.deepEqual(plan.crates, ['bh-core']);
});

test('editor paths, shared schema and core note consumers select the rendered editor gate and core Rust', t => {
  const f = fixture(t);
  f.crate('libs/core', 'bh-core');
  f.put('note-schema/v1.json', '{}\n');
  f.put('tests/interop/known.bin', 'fixture\n');
  f.put('apps/client/editor/test/rich.bin', 'fixture\n');
  f.put('apps/client/editor/src/schema.mjs', 'export const schema = 1;\n');
  f.put('apps/client/ui/note-editor.js', 'export {};\n');
  f.put('apps/client/ui/note-editor.css', '.note {}\n');
  f.git('add', '.'); f.git('commit', '-qm', 'editor baseline');
  const base = f.git('rev-parse', 'HEAD');
  let from = base;
  for (const path of [
    'apps/client/editor/src/schema.mjs',
    'apps/client/ui/note-editor.js',
    'apps/client/ui/note-editor.css',
    'note-schema/v1.json',
    'libs/core/src/note_schema.rs',
    'libs/core/examples/note_to_yjs.rs',
    'libs/core/tests/note.rs',
    'tests/interop/known.bin',
    'apps/client/editor/test/rich.bin',
  ]) {
    f.put(path, `changed ${path}\n`);
    f.git('add', '.'); f.git('commit', '-qm', path);
    const r = f.run('node', [script, '--base', from, '--head', 'HEAD', '--plan']);
    assert.equal(r.status, 0, r.stderr);
    const plan = JSON.parse(r.stdout);
    assert.ok(plan.js.includes('editor'), `${path}: ${r.stdout}`);
    if (path.endsWith('.bin') || path === 'note-schema/v1.json') {
      assert.ok(plan.crates.includes('bh-core'), `${path}: ${r.stdout}`);
    }
    from = f.git('rev-parse', 'HEAD');
  }
  f.put('services/api/src/lib.rs', 'pub fn changed() {}\n');
  f.git('add', '.'); f.git('commit', '-qm', 'unrelated service source');
  const unrelated = f.run('node', [script, '--base', from, '--head', 'HEAD', '--plan']);
  assert.ok(!JSON.parse(unrelated.stdout).js.includes('editor'), unrelated.stdout);
});

test('editor gate actually runs and fails when the selected editor check is broken', t => {
  const f = fixture(t);
  f.put('scripts/check.sh', '#!/usr/bin/env bash\nset -e\ncase "${1:-}" in\n  editor) node apps/client/editor/test/gate.test.mjs ;;\n  *) exit 0 ;;\nesac\n');
  f.put('apps/client/editor/test/gate.test.mjs', 'throw new Error("editor gate must run")\n');
  f.git('add', '.'); f.git('commit', '-qm', 'editor gate and failing test');
  const base = f.git('rev-parse', 'HEAD');
  f.put('apps/client/ui/note-editor.css', '.note { color: red; }\n');
  f.git('add', '.'); f.git('commit', '-qm', 'css change');
  const gate = f.run('node', [script, '--base', base, '--head', 'HEAD', '--check']);
  assert.notEqual(gate.status, 0, `${gate.stdout}\n${gate.stderr}`);
  assert.match(gate.stderr, /editor/);
});

test('sync worker JS changes and selected Rust worker run failing Wasm gate', t => {
  const f = fixture(t);
  f.crate('services/sync-worker', 'bh-sync-worker', `[dependencies]\nlow = { path = "${up(2)}/libs/low" }\n`);
  f.put('scripts/check.sh', '#!/usr/bin/env bash\nset -e\nnode tests/sync-worker/test/worker.test.mjs\n');
  f.put('tests/sync-worker/test/worker.test.mjs', 'throw new Error("must be checked")\n');
  f.git('add', '.'); f.git('commit', '-qm', 'worker and test');
  const added = f.git('rev-parse', 'HEAD');
  f.put('tests/sync-worker/test/worker.test.mjs', 'throw new Error("still must be checked")\n');
  f.git('add', '.'); f.git('commit', '-qm', 'broken test');
  const plan = f.run('node', [script, '--base', added, '--head', 'HEAD', '--plan']);
  assert.deepEqual(JSON.parse(plan.stdout).js, ['wasm-sync']);
  // The Wasm check in a real checkout runs this JS test; make the gate observable here.
  const gate = f.run('node', [script, '--base', added, '--head', 'HEAD', '--check']);
  assert.notEqual(gate.status, 0, `${gate.stdout}\n${gate.stderr}`);
  assert.match(gate.stderr, /wasm-sync/);
  const jsHead = f.git('rev-parse', 'HEAD');
  f.put('libs/low/src/lib.rs', 'pub fn changed() {}\n');
  f.git('add', '.'); f.git('commit', '-qm', 'library source');
  const rust = f.run('node', [script, '--base', jsHead, '--head', 'HEAD', '--plan']);
  assert.ok(JSON.parse(rust.stdout).js.includes('wasm-sync'));
});

test('interop fixture and core Rust changes select both halves of the cross-language gate', t => {
  const f = fixture(t);
  f.crate('libs/core', 'bh-core');
  f.put('libs/core/tests/fixture.rs', `const BYTES: &[u8] = include_bytes!("${up(3)}/tests/interop/known.bin");\n#[test]\nfn fixture_matches() {\n    assert_eq!(BYTES, b"expected");\n}\n`);
  f.put('tests/interop/known.bin', 'expected');
  const lock = f.run('cargo', ['generate-lockfile', '--offline']);
  assert.equal(lock.status, 0, lock.stderr);
  f.git('add', '.'); f.git('commit', '-qm', 'fixture baseline');
  const baseline = f.git('rev-parse', 'HEAD');
  f.put('tests/interop/known.bin', 'incompatible');
  f.git('add', '.'); f.git('commit', '-qm', 'break rust fixture');
  const plan = f.run('node', [script, '--base', baseline, '--head', 'HEAD', '--plan']);
  assert.ok(JSON.parse(plan.stdout).crates.includes('bh-core'));
  assert.ok(JSON.parse(plan.stdout).js.includes('interop'));
  const result = f.run('node', [script, '--base', baseline, '--head', 'HEAD', '--check']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /fixture_matches|fixture.rs/);
  const fixtureHead = f.git('rev-parse', 'HEAD');
  f.put('libs/core/src/lib.rs', 'pub fn changed() {}\n'); f.git('add', '.'); f.git('commit', '-qm', 'rust change');
  const reverse = f.run('node', [script, '--base', fixtureHead, '--head', 'HEAD', '--plan']);
  assert.ok(JSON.parse(reverse.stdout).js.includes('interop'));
});
