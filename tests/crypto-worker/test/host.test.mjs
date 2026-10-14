import test from 'node:test';
import assert from 'node:assert/strict';
import { createHost, assertImports } from '../../../libs/crypto/worker-host.mjs';

const names = ['__assert_fail', 'abort', 'emscripten_asm_const_int', 'explicit_bzero'];
const imports = names.map(name => ({ module: 'env', name, kind: 'function' }));

// WAT for a module with exactly the four permitted imports is not needed:
// validate the same descriptor list returned by WebAssembly.Module.imports.
test('rejects added, missing and nonfunction imports', () => {
  assert.doesNotThrow(() => assertImports(imports));
  assert.throws(() => assertImports([...imports, { module: 'env', name: 'malloc', kind: 'function' }]));
  assert.throws(() => assertImports(imports.slice(1)));
  assert.throws(() => assertImports(imports.map(i => i.name === 'abort' ? { ...i, kind: 'memory' } : i)));
});

test('rejects unknown glue and its wrong vararg ABI', () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const bytes = new Uint8Array(memory.buffer);
  const code = new TextEncoder().encode('{ return Module.getRandomValue(); }\0');
  bytes.set(code, 100);
  bytes.set(new TextEncoder().encode('i\0'), 200);
  const host = createHost();
  host.bindMemory(memory);
  assert.throws(() => host.imports.env.emscripten_asm_const_int(100, 200, 0), /argument signature/);
  assert.throws(() => host.imports.env.emscripten_asm_const_int(100, 0, 1), /varargs/);
  bytes[100] = 'x'.charCodeAt(0);
  assert.throws(() => host.imports.env.emscripten_asm_const_int(100, 0, 0), /unknown Emscripten/);
});

test('fails closed without secure entropy', () => {
  const host = createHost(null);
  const memory = new WebAssembly.Memory({ initial: 1 });
  new Uint8Array(memory.buffer).set(new TextEncoder().encode('{ return Module.getRandomValue(); }\0'), 100);
  host.bindMemory(memory);
  assert.throws(() => host.imports.env.emscripten_asm_const_int(100, 0, 0), /secure entropy/);
});

test('wipes only the exact in-bounds region', () => {
  const host = createHost();
  const memory = new WebAssembly.Memory({ initial: 1 });
  const bytes = new Uint8Array(memory.buffer);
  bytes.fill(17, 100, 104);
  host.bindMemory(memory);
  host.imports.env.explicit_bzero(101, 2);
  assert.deepEqual([...bytes.slice(100, 104)], [17, 0, 0, 17]);
  for (const [ptr, size] of [[-1, 1], [bytes.length, 1], [1, bytes.length], [0, -1]]) {
    assert.throws(() => host.imports.env.explicit_bzero(ptr, size), /memory bounds/);
  }
});
