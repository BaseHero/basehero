#!/usr/bin/env bash
# The native sync Client against the real local stack: a new account
# publishes and completes its setup at its account home, then the home's
# storage survives a full stack stop, a new workerd's readback and a cold
# authorization service before setup completes.
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export LOCAL_STACK_DIR="$(mktemp -d /tmp/bh-client-home-stack-XXXXXX)"
export LOCAL_STACK_BIND=127.0.0.1
stack=scripts/local-stack.sh
trap 'bash "$stack" down' EXIT
cargo build --locked --offline -p bh-sync-client-tests --features synthetic-attestation --tests
bash "$stack" up
cargo test --locked --offline -p bh-sync-client-tests --features synthetic-attestation \
  --test local_stack -- --ignored --test-threads 1 --nocapture
printf 'Client home setup through the local stack and its restart passed: %s\n' "$LOCAL_STACK_DIR"
