// Optional Nix integration test: compiler reuse must not share Cargo build dirs.
// Run with: node --test scripts/cache-shell.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const product = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function port() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const value = server.address().port;
      server.close(() => resolvePort(value));
    });
  });
}

test('separate fresh native worktrees reuse Rust dependency outputs without sharing target dirs', async t => {
  const root = mkdtempSync(join(tmpdir(), 'bh-cache-test-'));
  const env = { ...process.env, SCCACHE_DIR: join(root, 'cache'), SCCACHE_SERVER_PORT: String(await port()) };
  delete env.CARGO_TARGET_DIR;
  delete env.BH_CARGO_DEFAULT_TARGET;
  delete env.RUSTC_WRAPPER;
  t.after(() => {
    spawnSync('nix', ['develop', product, '--command', 'sh', '-c', '"$RUSTC_WRAPPER" --stop-server'], { cwd: root, env, stdio: 'ignore' });
    rmSync(root, { recursive: true, force: true });
  });
  function run(cwd, cmd, argv) {
    const result = spawnSync(cmd, argv, { cwd, env, encoding: 'utf8' });
    assert.equal(result.status, 0, `${cmd} ${argv.join(' ')}: ${result.stdout}\n${result.stderr}`);
    return result.stdout;
  }
  for (const name of ['first', 'second']) {
    const cwd = join(root, name);
    mkdirSync(join(cwd, 'src'), { recursive: true });
    writeFileSync(join(cwd, 'Cargo.toml'), '[workspace]\n[package]\nname = "cache-probe"\nversion = "0.1.0"\nedition = "2024"\n[dependencies]\nitoa = "=1.0.18"\n');
    writeFileSync(join(cwd, 'src/main.rs'), 'fn main() { let mut b = itoa::Buffer::new(); assert_eq!(b.format(42), "42"); }\n');
    // Minimal locked registry dependency, identical across both workspaces.
    run(cwd, 'nix', ['develop', product, '--command', 'cargo', 'generate-lockfile', '--offline']);
    run(cwd, 'nix', ['develop', product, '--command', 'cargo', 'build', '--locked', '--offline']);
    const stats = JSON.parse(run(cwd, 'nix', ['develop', product, '--command', 'sh', '-c', '"$RUSTC_WRAPPER" --show-stats --stats-format json']));
    if (name === 'first') assert.equal(stats.stats.cache_hits.counts.Rust || 0, 0);
    else assert.ok(stats.stats.cache_hits.counts.Rust >= 1, JSON.stringify(stats.stats));
  }
  for (const name of ['first', 'second']) run(join(root, name), join(root, name, 'target/debug/cache-probe'), []);
});
