import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { Miniflare } from 'miniflare';

const root = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
test('unchanged Rust bh-crypto hash and verifier execute in workerd', async () => {
  const previous = process.cwd();
  const scratch = mkdtempSync(join(tmpdir(), 'bh-worker-'));
  process.chdir(scratch);
  let mf;
  try {
    mf = new Miniflare({
      rootPath: root,
      modulesRoot: root,
      scriptPath: resolve(root, 'tests/crypto-worker/src/worker.mjs'),
      modules: true,
      modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
      compatibilityDate: '2026-07-01',
    });
    const response = await mf.dispatchFetch('http://fixture.invalid/');
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.code, 0, `hash/signature failure code ${result.code}`);
    assert.ok(result.entropyCalls > 0, 'sodium_init must use Worker secure entropy');
  } finally {
    try {
      if (mf) await mf.dispose();
    } finally {
      process.chdir(previous);
      rmSync(scratch, { recursive: true, force: true });
    }
  }
});
