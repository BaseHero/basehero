#!/usr/bin/env bash
# Two devices of one account against real local stacks: each test starts its
# own stack (local workerd Worker with log objects, R2 bodies and relay, and
# the authorization service with labelled synthetic attestation) and its own
# device processes, so the tests run concurrently. Opt-in; nothing leaves
# this machine. Extra arguments go to the test binary, e.g. a test name.
#
# Each test keeps its stack, device files and logs under
# $BH_LOCAL_SYNC_RUNS (default: a new directory under /tmp).
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export BH_LOCAL_SYNC_RUNS="${BH_LOCAL_SYNC_RUNS:-$(mktemp -d /tmp/bh-local-sync-XXXXXX)}"
[[ -f tests/crypto-worker/node_modules/miniflare/dist/src/index.js ]] || {
  echo 'local Miniflare missing; provision pinned test dependencies offline' >&2; exit 1;
}
# Build once, before any stack starts: the stacks then start prebuilt.
cargo build --locked --offline -p bh-authz --features synthetic-attestation --bin bh-authz --examples
nix develop --offline .#cryptoWorker --command bash -euc '
  RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
  cargo build --locked --offline --target wasm32-unknown-unknown -p bh-sync-worker --lib
  cp "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/debug/bh_sync_worker.wasm" services/sync-worker/sync_worker.wasm
'
cargo build --locked --offline -p bh-local-sync-tests --features synthetic-attestation --tests --examples
printf 'Local sync runs: %s\n' "$BH_LOCAL_SYNC_RUNS"
for test in checkpoint typed; do
  cargo test --locked --offline -p bh-local-sync-tests --features synthetic-attestation \
    --test "$test" -- --ignored "$@"
done
printf 'Local sync tests passed: %s\n' "$BH_LOCAL_SYNC_RUNS"
