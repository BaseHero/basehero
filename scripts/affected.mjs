#!/usr/bin/env node
// Cargo metadata is the source of workspace membership and of every dependency edge,
// including dev and build edges. Paths only choose roots; closure chooses checks.
import { spawnSync } from 'node:child_process';
import { dirname, relative, resolve, sep } from 'node:path';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = resolve(process.env.BH_PRODUCT_ROOT || resolve(dirname(fileURLToPath(import.meta.url)), '..'));
const args = process.argv.slice(2);
const value = flag => { const i = args.indexOf(flag); return i < 0 ? null : args[i + 1]; };
function run(cmd, argv, cwd = root) {
  const result = spawnSync(cmd, argv, { cwd, stdio: ['inherit', 'pipe', 'inherit'], encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`${cmd} ${argv.join(' ')} failed (${result.status})`);
  return result.stdout;
}
const metadata = JSON.parse(run(process.env.BH_CARGO || 'cargo', ['metadata', '--locked', '--offline', '--no-deps', '--format-version', '1']));
const members = metadata.packages.filter(p => metadata.workspace_members.includes(p.id));
const byName = new Map(members.map(p => [p.name, p]));
const location = p => relative(root, dirname(p.manifest_path)).split(sep).join('/');
const dir = new Map(members.map(p => [p.name, location(p)]));
// One small definition sets the direction; adding an ordinary crate changes no list.
const definition = JSON.parse(readFileSync(new URL('./layers.json', import.meta.url), 'utf8'));
const foundation = new Set(definition.foundation);
const layer = path => {
  if (foundation.has(path)) return 0;
  const entry = Object.entries(definition.prefixes).find(([prefix]) => path.startsWith(prefix));
  return entry ? definition.order.indexOf(entry[1]) : -1;
};
function dependencies(p) { return p.dependencies.filter(d => d.path && byName.has(d.name)).map(d => d.name); }
function layers() {
  for (const p of members) {
    const path = dir.get(p.name);
    if (layer(path) < 0) throw new Error(`Unclassified workspace crate: ${path}`);
    for (const dep of dependencies(p)) {
      if (layer(path) < layer(dir.get(dep))) throw new Error(`Dependency layer violation: ${p.name} (${path}) -> ${dep} (${dir.get(dep)})`);
    }
  }
}
try {
  layers();
  if (args.includes('--layers')) process.exit(0);
  const base = value('--base'), head = value('--head');
  if (!base || !head) throw new Error('usage: affected.mjs --base <commit> --head <commit> [--list|--check|--layers]');
  const repo = run('git', ['rev-parse', '--show-toplevel']).trim();
  const prefix = relative(repo, root).split(sep).join('/');
  const paths = run('git', ['diff', '--name-only', '--no-renames', '-z', base, head, '--', prefix || '.'], repo).split('\0').filter(Boolean).map(p => prefix ? p.slice(prefix.length + 1) : p);
  // Unknown product paths are not assumed safe: run the portable suite.
  const global = paths.some(p => p === 'Cargo.toml' || p === 'Cargo.lock' || p === 'rust-toolchain.toml' || p === 'flake.nix' || p === 'flake.lock' || p.startsWith('scripts/') || p.endsWith('/Cargo.toml') || p.endsWith('/build.rs') || p.endsWith('.gitignore'));
  const selected = new Set(global ? byName.keys() : []);
  // Cross-crate file consumers Cargo metadata cannot see: core's tests include_bytes!
  // the interop and editor fixtures, and core's note_schema include_str!s the shared
  // schema, so each must pull bh-core into closure.
  if (paths.some(p => p.startsWith('tests/interop/') || p === 'note-schema/v1.json'
      || (p.startsWith('apps/client/editor/test/') && p.endsWith('.bin'))) && byName.has('bh-core')) selected.add('bh-core');
  for (const p of paths) {
    const owner = members.filter(m => p.startsWith(`${dir.get(m.name)}/`)).sort((a, b) => dir.get(b.name).length - dir.get(a.name).length)[0];
    if (owner && (p.endsWith('.rs') || p.startsWith(`${dir.get(owner.name)}/`))) selected.add(owner.name);
    else if (!p.startsWith('apps/client/') && !p.startsWith('website/') && !p.startsWith('tests/interop/') && !p.startsWith('tests/sync-worker/') && !p.startsWith('tests/crypto-worker/')) for (const name of byName.keys()) selected.add(name);
  }
  let changed;
  do {
    changed = false;
    for (const p of members) if (!selected.has(p.name) && dependencies(p).some(d => selected.has(d))) { selected.add(p.name); changed = true; }
  } while (changed);
  const names = [...selected].sort();
  // note_to_yjs bridges core's note into the bundled editor, so core changes (bh-core),
  // the shared schema and interop fixtures all reach the editor's Rust-to-Yjs tests.
  const editor = global
    || selected.has('bh-core')
    || paths.some(p => p.startsWith('apps/client/editor/')
      || p === 'apps/client/ui/note-editor.js' || p === 'apps/client/ui/note-editor.css'
      || p === 'note-schema/v1.json' || p.startsWith('tests/interop/'));
  const js = [
    ...(global || paths.some(p => p.startsWith('apps/client/')) ? ['client'] : []),
    ...(global || selected.has('bh-core') || paths.some(p => p.startsWith('tests/interop/') || p.startsWith('apps/client/')) ? ['interop'] : []),
    ...(editor ? ['editor'] : []),
    ...(global && byName.has('bh-sync-worker') || selected.has('bh-sync-worker') || paths.some(p => p.startsWith('tests/sync-worker/') || p.startsWith('services/sync-worker/')) ? ['wasm-sync'] : []),
    ...(paths.some(p => p.startsWith('website/')) ? ['website'] : []),
  ];
  if (args.includes('--plan')) { console.log(JSON.stringify({ crates: names, js })); process.exit(0); }
  if (args.includes('--list')) { console.log(names.join('\n')); process.exit(0); }
  if (!args.includes('--check')) throw new Error('specify --list or --check');
  const shell = (cmd, argv) => { console.error(`Affected: ${cmd} ${argv.join(' ')}`); const r = spawnSync(cmd, argv, { cwd: root, stdio: 'inherit' }); if (r.status !== 0) process.exit(r.status || 1); };
  if (paths.length) {
    shell('cargo', ['fmt', '--all', '--check']);
    if (names.length) {
      const portable = names.filter(n => !dir.get(n).startsWith('apps/') && n !== 'bh-crypto-worker-test');
      if (portable.length) {
        const pkgs = portable.flatMap(n => ['-p', n]);
        shell('cargo', ['clippy', '--locked', '--all-targets', ...pkgs, '--', '-D', 'warnings']);
        shell('cargo', ['test', '--locked', ...pkgs]);
        if (portable.includes('bh-public-web') && process.platform === 'linux') shell('bash', ['libs/public-web/netns.sh', 'cargo', 'test', '--locked', '--offline', '-p', 'bh-public-web', '--lib', '--', '--ignored', '--test-threads=1']);
      }
      if (names.some(n => dir.get(n).startsWith('apps/'))) shell('bash', ['scripts/check.sh', 'desktop']);
      if (names.includes('bh-crypto-worker-test')) shell('bash', ['scripts/check.sh', 'wasm-crypto']);
    }
    if (js.includes('wasm-sync')) shell('bash', ['scripts/check.sh', 'wasm-sync']);
    if (js.includes('editor')) shell('bash', ['scripts/check.sh', 'editor']);
    if (js.includes('client')) shell('node', ['--test', ...readdirSync(resolve(root, 'apps/client/tests')).filter(p => p.endsWith('.test.mjs')).map(p => `apps/client/tests/${p}`)]);
    if (js.includes('interop')) { shell('npm', ['ci', '--prefix', 'tests/interop', '--ignore-scripts', '--no-audit', '--no-fund']); shell('npm', ['test', '--prefix', 'tests/interop']); }
    if (js.includes('website')) { shell('npm', ['ci', '--prefix', 'website', '--ignore-scripts', '--no-audit', '--no-fund']); shell('npm', ['run', 'check', '--prefix', 'website']); }
  }
} catch (error) { console.error(error.message); process.exit(1); }
