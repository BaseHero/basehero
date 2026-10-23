#!/usr/bin/env bash
# Real local stack: an attested device, permitted writes/reads and two restarts.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
requested_target="${CARGO_TARGET_DIR-}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/basehero-local-stack-target}"
if [[ -n "$requested_target" && "$CARGO_TARGET_DIR" != "$requested_target" ]]; then
  echo 'test runner ignored the caller Cargo target' >&2; exit 1
fi
printf 'Local stack Cargo target: %s\n' "$CARGO_TARGET_DIR"
export LOCAL_STACK_DIR="${LOCAL_STACK_DIR:-$(mktemp -d)}"
stack=scripts/local-stack.sh
bash scripts/local-stack-owner.test.sh
# Reject directories beneath the publishable source tree before creating keys.
refused_dir="$PWD/.local-stack-refused-$$"
if LOCAL_STACK_DIR="$refused_dir" bash "$stack" up >/dev/null 2>&1; then
  LOCAL_STACK_DIR="$refused_dir" bash "$stack" down
  rm -r "$refused_dir"
  echo 'stack accepted a source-tree key directory' >&2; exit 1
fi
[[ ! -e "$refused_dir" ]] || { LOCAL_STACK_DIR="$refused_dir" bash "$stack" down; rm -r "$refused_dir"; exit 1; }
cleanup() { bash "$stack" down || :; }
trap cleanup EXIT

# A nonempty stale generated artifact must never bypass the incremental build.
printf 'stale worker regression fixture\n' > services/sync-worker/sync_worker.wasm
bash "$stack" up
cmp services/sync-worker/sync_worker.wasm "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/bh_sync_worker.wasm"
bash "$stack" status
for private in "$LOCAL_STACK_DIR"/keys/* "$LOCAL_STACK_DIR"/bindings.json "$LOCAL_STACK_DIR"/env "$LOCAL_STACK_DIR"/pids; do
  [[ "$(stat -c %a "$private")" == 600 ]] || { echo "unsafe mode on $private" >&2; exit 1; }
done
# The native example performs the actual WebSocket upgrade and synthetic
# channel handshake; it also publishes and reads an account log via permits.
# Devices get the home's certified recovery key; its seed stays with the
# service, and the service holds it.
grep -qx "LOCAL_STACK_RECOVERY_KEY=$(<"$LOCAL_STACK_DIR/keys/recovery.cert")" "$LOCAL_STACK_DIR/env" ||
  { echo 'env lacks the recovery key certificate' >&2; exit 1; }
! grep -qF "$(<"$LOCAL_STACK_DIR/keys/recovery.seed")" "$LOCAL_STACK_DIR/env" ||
  { echo 'the recovery seed reached the endpoint' >&2; exit 1; }
! grep -q 'recovery claims are refused' "$LOCAL_STACK_DIR/authz.log" ||
  { echo 'service started without the recovery key' >&2; exit 1; }
"$CARGO_TARGET_DIR/debug/examples/local_probe" first "$LOCAL_STACK_DIR"
bash "$stack" down
# Make a correctly signed, already-expired policy from this app root and
# retain it as the device's previous policy snapshot. A fresh handshake after
# up must accept the next generation, not conflict with the saved one.
"$CARGO_TARGET_DIR/debug/examples/local_probe" expire-policy "$LOCAL_STACK_DIR"
app_root_before=$(<"$LOCAL_STACK_DIR/keys/app-root.pub")
old_generation=$(node -p 'require(process.argv[1]).generation' "$LOCAL_STACK_DIR/keys/policy.json")
# For the emulator, the exported URL must be its actual host alias, not a
# loopback URL that resolves inside Android. The host probe uses HOST_EDGE_URL.
export LOCAL_STACK_BIND=0.0.0.0
bash "$stack" up
bash "$stack" status
[[ "$(<"$LOCAL_STACK_DIR/keys/app-root.pub")" == "$app_root_before" ]]
new_generation=$(node -p 'require(process.argv[1]).generation' "$LOCAL_STACK_DIR/keys/policy.json")
source "$LOCAL_STACK_DIR/env"
[[ "$LOCAL_STACK_EDGE_URL" == http://10.0.2.2:* ]]
[[ "$LOCAL_STACK_HOST_EDGE_URL" == http://127.0.0.1:* ]]
"$CARGO_TARGET_DIR/debug/examples/local_probe" again "$LOCAL_STACK_DIR"
(( new_generation > old_generation ))
bash "$stack" down
! bash "$stack" status
# A forged entry with a *correct* PID, process birth time and command is
# still not a process launched by the stack.
sleep 60 &
unrelated=$!
born=$(python3 -c 'import sys; print(open("/proc/"+sys.argv[1]+"/stat").read().rsplit(") ",1)[1].split()[19])' "$unrelated")
printf '%s %s %s\n' "$unrelated" "$born" sleep > "$LOCAL_STACK_DIR/pids"
bash "$stack" down
if ! kill -0 "$unrelated" 2>/dev/null; then
  wait "$unrelated" || :
  echo 'down killed an unrelated process' >&2; exit 1
fi
kill -TERM "$unrelated"
wait "$unrelated" || :
printf 'Local stack: attested channel, permitted log and restart passed\n'
