// Host imports for the pinned Emscripten libsodium archive's hash/verify path.
// Trust only a module built from our pinned C source and Rust crate: the Worker
// instantiates a compiled module shipped with its own code, never user input.
const IMPORTS = ['__assert_fail', 'abort', 'emscripten_asm_const_int', 'explicit_bzero'];
// RANDOM and STIR below are excerpts from the pinned libsodium
// src/libsodium/randombytes/randombytes.c, not original BaseHero code.
/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
const RANDOM = '{ return Module.getRandomValue(); }';
// Exact stringized EM_ASM from the root-pinned libsodium randombytes.c, as
// compiled by the root-pinned Emscripten toolchain. Changes require review.
const STIR = `{ if (Module.getRandomValue === undefined) { try { var window_ = 'object' === typeof window ? window : self; var crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto; crypto_ = (crypto_ === undefined) ? crypto : crypto_; var randomValuesStandard = function() { var buf = new Uint32Array(1); crypto_.getRandomValues(buf); return buf[0] >>> 0; }; randomValuesStandard(); Module.getRandomValue = randomValuesStandard; } catch (e) { try { var crypto = require('crypto'); var randomValueNodeJS = function() { var buf = crypto['randomBytes'](4); return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0; }; randomValueNodeJS(); Module.getRandomValue = randomValueNodeJS; } catch (e) { throw 'No secure random number generator found'; } } } }`;

export function assertImports(imports) {
  const actual = imports.map(({ module, name, kind }) => `${module}.${name}:${kind}`).sort();
  const expected = IMPORTS.map(name => `env.${name}:function`).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`unsupported Worker Wasm imports: ${JSON.stringify(actual)}`);
  }
}

export function createHost(entropy = globalThis.crypto) {
  let memory;
  let entropyCalls = 0;
  function bytes() {
    if (!(memory instanceof WebAssembly.Memory)) throw new Error('Worker Wasm memory not bound');
    return new Uint8Array(memory.buffer);
  }
  function checkedSpan(ptr, length) {
    const view = bytes();
    if (!Number.isSafeInteger(ptr) || !Number.isSafeInteger(length) || ptr < 0 || length < 0 || ptr > view.length || length > view.length - ptr) {
      throw new Error('Worker Wasm memory bounds');
    }
    return view;
  }
  function readCString(ptr) {
    const view = checkedSpan(ptr, 1);
    const end = view.indexOf(0, ptr);
    if (end < 0 || end - ptr > 1024) throw new Error('unsupported Emscripten string');
    return new TextDecoder().decode(view.subarray(ptr, end));
  }
  function random() {
    if (typeof entropy?.getRandomValues !== 'function') throw new Error('Worker secure entropy unavailable');
    const value = new Uint32Array(1);
    entropy.getRandomValues(value);
    entropyCalls++;
    return value[0] | 0;
  }
  return {
    bindMemory(value) {
      if (memory) throw new Error('Worker Wasm memory already bound');
      memory = value;
      bytes();
    },
    get entropyCalls() { return entropyCalls; },
    imports: { env: {
      abort() { throw new Error('libsodium aborted'); },
      __assert_fail() { throw new Error('libsodium assertion failed'); },
      explicit_bzero(ptr, length) { checkedSpan(ptr, length).fill(0, ptr, ptr + length); },
      // Emscripten em_asm.h: (code pointer, NUL-terminated argument-signature
      // pointer, C varargs pointer). This pinned source calls with no varargs.
      emscripten_asm_const_int(code, signatures, varargs) {
        if (readCString(signatures) !== '') throw new Error('unexpected Emscripten argument signature');
        if (varargs !== 0) throw new Error('unexpected Emscripten varargs');
        switch (readCString(code)) {
          case STIR: random(); return 0;
          case RANDOM: return random();
          default: throw new Error('unknown Emscripten glue');
        }
      },
    } },
  };
}
