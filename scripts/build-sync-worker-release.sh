#!/usr/bin/env bash
# Internal committed-export build step; no deploy or Wrangler network calls.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${1:?new Worker output directory required}"
: "${CARGO_TARGET_DIR:?private Cargo target directory required}"
test ! -e "$1"
test -n "${PKG_CONFIG_LIBDIR:-}"
test "$(pkg-config --variable=libdir libsodium)" = "${PKG_CONFIG_LIBDIR%/pkgconfig}"
RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
  cargo build --locked --release --target wasm32-unknown-unknown -p bh-sync-worker --lib
mkdir -p "$1/services/sync-worker/src" "$1/libs/crypto"
# Preserve the exact relative import layout, without fixtures or local config.
cp services/sync-worker/src/{budget,edge,log,relay,wasm}.mjs "$1/services/sync-worker/src/"
cp libs/crypto/worker-host.mjs "$1/libs/crypto/"
cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/bh_sync_worker.wasm" "$1/services/sync-worker/sync_worker.wasm"
node --input-type=module - "$1" <<'JS'
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const root = resolve(process.argv[2]);
const { assertImports } = await import(pathToFileURL(`${root}/libs/crypto/worker-host.mjs`));
const module = await WebAssembly.compile(await readFile(`${root}/services/sync-worker/sync_worker.wasm`));
assertImports(WebAssembly.Module.imports(module));
console.log('release Wasm imports permitted');
JS
