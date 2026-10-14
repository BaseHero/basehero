#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Same root-pinned libsodium and audited host glue as wasm-crypto. Only the
# hash/verify imports are permitted, including in the final linked module.
test -n "${PKG_CONFIG_LIBDIR:-}"
test "$(pkg-config --variable=libdir libsodium)" = "${PKG_CONFIG_LIBDIR%/pkgconfig}"
npm ci --prefix tests/crypto-worker --ignore-scripts --no-audit --no-fund
RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
  cargo build --locked --target wasm32-unknown-unknown -p bh-sync-worker --lib
cp "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/debug/bh_sync_worker.wasm" services/sync-worker/sync_worker.wasm
node --test tests/sync-worker/test/*.test.mjs
