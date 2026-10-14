#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Invoked in .#cryptoWorker: its pkg-config lookup is target-only, never the
# native libsodium.so. Only these four unresolved C/Emscripten functions may
# become host imports; the test independently audits the final Wasm imports.
test -n "${PKG_CONFIG_LIBDIR:-}"
test "$(pkg-config --variable=libdir libsodium)" = "${PKG_CONFIG_LIBDIR%/pkgconfig}"

npm ci --prefix tests/crypto-worker --ignore-scripts --no-audit --no-fund
RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
  cargo build --locked --target wasm32-unknown-unknown -p bh-crypto-worker-test --lib
cp "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/debug/bh_crypto_worker_test.wasm" tests/crypto-worker/probe.wasm
node --test tests/crypto-worker/test/*.test.mjs
