#!/usr/bin/env bash
# The app host's own signer, sync and pairing (bh-host) against the real
# local stack (Worker, log objects, relay and authorization service, with
# labelled synthetic attestation): a first device shows a code, a second
# joins, bootstraps and both keep writing one note. Opt-in; nothing leaves
# this machine. The stack's endpoint is written as an endpoint file and read
# as an app build reads its own.
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export LOCAL_STACK_DIR="$(mktemp -d /tmp/bh-client-local-stack-XXXXXX)"
export LOCAL_STACK_BIND=127.0.0.1
stack=scripts/local-stack.sh
trap 'bash "$stack" down' EXIT
bash "$stack" up
# The stack's endpoint as the build-time endpoint file.
node -e '
  const fs = require("node:fs");
  const [dir] = process.argv.slice(1);
  const env = Object.fromEntries(fs.readFileSync(`${dir}/env`, "utf8").trim().split("\n")
    .map(line => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
  fs.writeFileSync(`${dir}/endpoint.json`, JSON.stringify({
    edge_url: env.LOCAL_STACK_HOST_EDGE_URL,
    hosting_root: env.LOCAL_STACK_HOSTING_ROOT,
    app_root: env.LOCAL_STACK_APP_ROOT,
    policy: fs.readFileSync(env.LOCAL_STACK_POLICY).toString("hex"),
    policy_signature: fs.readFileSync(`${dir}/keys/policy.sig`, "utf8").trim(),
    max_lifetime_secs: 86400,
    max_uncertainty_secs: 0,
    build_floor: 1,
    appraisal: "synthetic",
  }), { mode: 0o600 });
' "$LOCAL_STACK_DIR"
cargo test --locked --offline -p bh-host-tests --features synthetic-attestation \
  --test pairing -- --ignored --nocapture local_stack
printf 'Host pairing and sync through the local stack passed: %s\n' "$LOCAL_STACK_DIR"
