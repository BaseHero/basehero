#!/usr/bin/env bash
# AccountOwner -> attested authz -> real workerd private storage, with cold restart.
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export LOCAL_STACK_DIR="$(mktemp -d /tmp/bh-home-stack-XXXXXX)"
export LOCAL_STACK_BIND=127.0.0.1
stack=scripts/local-stack.sh
trap 'bash "$stack" down' EXIT
# The local runner's cached-Wasm behavior is not this test's build contract.
nix develop --offline .#cryptoWorker --command bash -c '
  RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
  cargo build --locked --offline --target wasm32-unknown-unknown -p bh-sync-worker --lib
  cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/bh_sync_worker.wasm" services/sync-worker/sync_worker.wasm
'
bash "$stack" up
"$CARGO_TARGET_DIR/debug/examples/local_probe" home-first "$LOCAL_STACK_DIR"
bash "$stack" down
# Open exactly the same DO SQLite with a test-only internal readback fixture in
# a NEW workerd. No public route is added to the production edge.
node tests/sync-worker/home-readback.mjs "$LOCAL_STACK_DIR"
"$CARGO_TARGET_DIR/debug/examples/local_probe" home-verify "$LOCAL_STACK_DIR"
# A cold authz DB, not just a process restart: all authority is replayed from
# the account home. Keep the old DB as test evidence rather than deleting it.
mv "$LOCAL_STACK_DIR/authz.db" "$LOCAL_STACK_DIR/authz-before-restart.db"
bash "$stack" up
"$CARGO_TARGET_DIR/debug/examples/local_probe" home-again "$LOCAL_STACK_DIR"
bash "$stack" down
node tests/sync-worker/home-readback.mjs "$LOCAL_STACK_DIR"
"$CARGO_TARGET_DIR/debug/examples/local_probe" home-verify "$LOCAL_STACK_DIR"
printf 'Home stack durable restart and exact retry passed: %s\n' "$LOCAL_STACK_DIR"
