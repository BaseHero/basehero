#!/usr/bin/env node
// Inspect only the test executables emitted by this cargo invocation, never
// historical files in a guessed target directory.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const expected = new Map([
  ['bh-crypto:lib:bh_crypto', null],
  ['bh-release:lib:bh_release', null],
  ['bh-release:test:verification', null],
]);
const events = readFileSync(process.argv[2], 'utf8').trim().split('\n');
for (const line of events) {
  const artifact = JSON.parse(line);
  if (artifact.reason !== 'compiler-artifact' || !artifact.executable || !artifact.profile?.test) continue;
  const pkg = ['bh-crypto', 'bh-release'].find(name => artifact.package_id?.includes(`#${name}@`));
  const kind = artifact.target?.kind;
  if (!pkg || kind?.length !== 1) continue;
  const key = `${pkg}:${kind[0]}:${artifact.target.name}`;
  if (!expected.has(key)) continue;
  if (expected.get(key)) throw new Error(`duplicate Android test artifact: ${key}`);
  expected.set(key, artifact.executable);
}

const tools = join(process.env.NDK_HOME, 'toolchains/llvm/prebuilt/linux-x86_64/bin');
for (const [key, binary] of expected) {
  if (!binary) throw new Error(`missing Android test artifact: ${key}`);
  const readelf = (...args) => execFileSync(join(tools, 'llvm-readelf'), [...args, binary], { encoding: 'utf8' });
  if (!/Machine:\s+AArch64\b/.test(readelf('-h'))) throw new Error(`not AArch64: ${key}: ${binary}`);
  if (/NEEDED[^\n]*libsodium/.test(readelf('-d'))) throw new Error(`dynamic libsodium: ${key}: ${binary}`);
  if (key === 'bh-crypto:lib:bh_crypto') {
    const symbols = execFileSync(join(tools, 'llvm-nm'), [binary], { encoding: 'utf8' });
    if (!/^\S+ T crypto_kem_xwing_enc$/m.test(symbols)) throw new Error(`missing static X-Wing symbol: ${binary}`);
  }
  console.log(`checked Android ${key}: ${binary}`);
}
