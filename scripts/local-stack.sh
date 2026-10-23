#!/usr/bin/env bash
# Disposable synthetic stack. No Cloudflare account, deployment or external host.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/basehero-local-stack-target}"
LOCAL_STACK_DIR="${LOCAL_STACK_DIR:-/tmp/basehero-local-stack-${UID}}"
# Refuse keys anywhere inside the checkout, even through an existing symlink.
[[ "$LOCAL_STACK_DIR" == /* ]] || { echo 'LOCAL_STACK_DIR must be absolute' >&2; exit 2; }
checkout=$(git rev-parse --show-toplevel)
case "$(realpath -m "$LOCAL_STACK_DIR")" in
  "$checkout"|"$checkout"/*) echo 'LOCAL_STACK_DIR must be outside the checkout' >&2; exit 2 ;;
esac
LOCAL_STACK_BIND="${LOCAL_STACK_BIND:-127.0.0.1}"
case "$LOCAL_STACK_BIND" in
  127.0.0.1|0.0.0.0) ;;
  *) echo 'LOCAL_STACK_BIND must be 127.0.0.1 or explicitly 0.0.0.0' >&2; exit 2 ;;
esac
case "${1:-}" in
  up|down|status) ;;
  stop-part|start-part)
    case "${2:-}" in authz|edge) ;; *) echo "usage: local-stack.sh $1 authz|edge" >&2; exit 2 ;; esac ;;
  *) echo 'usage: local-stack.sh up|down|status|stop-part PART|start-part PART' >&2; exit 2 ;;
esac
# LOCAL_STACK_PREBUILT=1: the caller already built the service, its examples and
# the current Worker (as `up` does), so several stacks can start at once
# without racing over one target or the generated Worker file.
LOCAL_STACK_PREBUILT="${LOCAL_STACK_PREBUILT:-}"
# Captured /proc birth time and a fresh per-launch environment marker bind
# the recorded PID to a process launched by this invocation.
start_time() {
  local line rest
  IFS= read -r line < "/proc/$1/stat" || return 1
  rest="${line##*) }"
  local -a fields
  read -ra fields <<< "$rest"
  [[ ${fields[0]} != Z ]] || return 1
  printf '%s' "${fields[19]}"
}
# On a refusal, `unverified` says which check failed and what it saw: the
# birth time, the command's first word and the launch marker's first
# characters, never the rest of the process's environment.
verified() {
  local pid=$1 born=$2 executable=$3 line now marker
  local marker_prefix=LOCAL_STACK_LAUNCH_ID=
  unverified='malformed record'
  [[ $pid =~ ^[0-9]+$ && $born =~ ^[0-9]+$ ]] || return 1
  now=$(start_time "$pid" 2>/dev/null) || now=gone
  unverified="birth time $now"
  [[ $now == "$born" ]] || return 1
  unverified='command unreadable'
  [[ -r /proc/$pid/cmdline ]] || return 1
  line=$(tr '\0' '\n' < "/proc/$pid/cmdline")
  unverified="command ${line%%$'\n'*}"
  [[ $line == *"$executable"* ]] || return 1
  unverified='launch-id or environment unreadable'
  [[ -f "$LOCAL_STACK_DIR/launch-id" && -r /proc/$pid/environ ]] || return 1
  marker="${marker_prefix}$(<"$LOCAL_STACK_DIR/launch-id")"
  # One exact NUL-separated entry, read straight from the file: a pipe
  # whose reader stops at the match would end its writer with SIGPIPE and,
  # under pipefail, refuse the stack's own process.
  if ! grep -zFqx -e "$marker" "/proc/$pid/environ" 2>/dev/null; then
    unverified="launch marker: expected ${marker:0:${#marker_prefix}+12}, present $(present_marker "$pid")"
    unverified+=", environment $({ wc -c < "/proc/$pid/environ"; } 2>/dev/null || echo ?) bytes"
    return 1
  fi
  unverified=''
}
# The first characters of process $1's launch marker entry, or `absent`.
present_marker() {
  local marker_prefix=LOCAL_STACK_LAUNCH_ID= found
  found=$(grep -zaoE "^${marker_prefix}[0-9a-f]{0,12}" "/proc/$1/environ" 2>/dev/null | head -c "$((${#marker_prefix} + 12))" | tr -d '\0') || :
  printf '%s' "${found:-absent}"
}
live() {
  [[ -f "$LOCAL_STACK_DIR/pids" ]] || return 1
  local pid born executable
  while read -r pid born executable; do
    verified "$pid" "$born" "$executable" ||
      { down_reason="$pid $born $executable: $unverified"; return 1; }
  done < "$LOCAL_STACK_DIR/pids"
  [[ -s "$LOCAL_STACK_DIR/pids" ]]
}
authz_bin() { printf '%s' "$CARGO_TARGET_DIR/debug/bh-authz"; }
part_executable() {
  case "$1" in authz) authz_bin ;; edge) printf 'scripts/local-edge.mjs' ;; *) printf '' ;; esac
}
# Stop the recorded processes whose executable is $1 (all when empty) with
# signal $2, then KILL any still running after five seconds.
stop_matching() {
  [[ -f "$LOCAL_STACK_DIR/pids" ]] || return 0
  local only=$1 signal=$2 pid born executable kids=() own kid
  while read -r pid born executable; do
    [[ -z $only || $executable == "$only" ]] || continue
    if verified "$pid" "$born" "$executable"; then
      # The Worker's local workerd is the edge process's child: it must not
      # outlive it, still holding the edge port and stored logs.
      own=()
      while read -r kid; do own+=("$kid"); done < <(children_of "$pid")
      kids+=("${own[@]}")
      note_stop "$signal $pid $executable children: ${own[*]:-none}"
      kill "-$signal" "$pid"
    else
      note_stop "not verified, left alone: $pid $born $executable: $unverified"
    fi
  done < "$LOCAL_STACK_DIR/pids"
  for _ in {1..50}; do
    local running=0
    while read -r pid born executable; do
      [[ -z $only || $executable == "$only" ]] || continue
      verified "$pid" "$born" "$executable" && running=1
    done < "$LOCAL_STACK_DIR/pids"
    (( running == 0 )) && break
    sleep 0.1
  done
  while read -r pid born executable; do
    [[ -z $only || $executable == "$only" ]] || continue
    if verified "$pid" "$born" "$executable"; then
      note_stop "KILL $pid $executable: still running after 5 s"
      kill -KILL "$pid"
    fi
  done < "$LOCAL_STACK_DIR/pids"
  for kid in "${kids[@]}"; do
    read -r pid born <<< "$kid"
    [[ $(start_time "$pid" 2>/dev/null) == "$born" ]] || continue
    note_stop "child $pid outlived its parent: TERM"
    kill -TERM "$pid" 2>/dev/null || continue
    for _ in {1..50}; do
      [[ $(start_time "$pid" 2>/dev/null) == "$born" ]] || break
      sleep 0.1
    done
    if [[ $(start_time "$pid" 2>/dev/null) == "$born" ]]; then
      note_stop "child $pid: KILL"
      kill -KILL "$pid" 2>/dev/null || :
    fi
  done
}
# The direct children of process $1, as "pid start-time" lines.
children_of() {
  local stat line rest
  local -a fields
  for stat in /proc/[0-9]*/stat; do
    # A process may end between the glob and the read.
    { IFS= read -r line < "$stat"; } 2>/dev/null || continue
    rest="${line##*) }"
    read -ra fields <<< "$rest"
    [[ ${fields[1]} == "$1" ]] && printf '%s %s\n' "${stat//[!0-9]/}" "${fields[19]}"
  done
}
note_stop() {
  printf '%s %s\n' "$(date +%T.%N)" "$1" >> "$LOCAL_STACK_DIR/stop.log"
}
# Just launched: give it a few seconds to answer; each miss says why.
wait_up() {
  for _ in {1..20}; do
    bash scripts/local-stack.sh status && return 0
    sleep 0.5
  done
  echo 'stack unavailable after launch; see edge.log and authz.log' >&2
  return 1
}
# Which part of `status` failed, for the log.
why_down() {
  [[ -s "$LOCAL_STACK_DIR/pids" ]] || { echo 'status: no recorded processes'; return; }
  local pid born executable code
  [[ -z ${down_reason:-} ]] || echo "status: not verified: $down_reason"
  # Checked again, so a passing second look shows the first was transient.
  while read -r pid born executable; do
    if verified "$pid" "$born" "$executable"; then
      echo "status: recheck verified: $pid"
    else
      echo "status: recheck not verified: $pid $born $executable: $unverified"
    fi
  done < "$LOCAL_STACK_DIR/pids"
  if [[ -f "$LOCAL_STACK_DIR/edge-url" ]]; then
    code=$(curl --noproxy '*' --silent --max-time 2 --output /dev/null --write-out '%{http_code}' \
      "$(<"$LOCAL_STACK_DIR/edge-url")/v1/data" || echo "curl exit $?")
    echo "status: edge answered $code"
  else
    echo 'status: no edge-url'
  fi
}
stop() {
  stop_matching '' TERM
  rm -f "$LOCAL_STACK_DIR/pids" "$LOCAL_STACK_DIR/edge-url" "$LOCAL_STACK_DIR/env" "$LOCAL_STACK_DIR/launch-id"
}
# The authorization service on $1, on the stack's protected database, keys
# and the edge's recorded port; records its PID and observed address.
launch_authz() {
  local before
  before=$(grep -c 'bh-authz: listening on' "$LOCAL_STACK_DIR/authz.log" 2>/dev/null || :)
  "$(authz_bin)" \
    --listen "$1" --db "$LOCAL_STACK_DIR/authz.db" \
    --edge "ws://127.0.0.1:$edge_port/v1/data" \
    --hosting-root "$(<"$LOCAL_STACK_DIR/keys/hosting-root.pub")" \
    --permit-key "$LOCAL_STACK_DIR/keys/permit.seed" --permit-cert "$LOCAL_STACK_DIR/keys/permit.cert" \
    --app-root "$(<"$LOCAL_STACK_DIR/keys/app-root.pub")" \
    --policy "$LOCAL_STACK_DIR/keys/policy.json" --policy-signature "$LOCAL_STACK_DIR/keys/policy.sig" \
    --recovery-key "$LOCAL_STACK_DIR/keys/recovery.seed" --recovery-cert "$LOCAL_STACK_DIR/keys/recovery.cert" \
    --synthetic-attestation >>"$LOCAL_STACK_DIR/authz.log" 2>&1 &
  local authz_pid=$! address='' born
  born=$(start_time "$authz_pid")
  printf '%s %s %s\n' "$authz_pid" "$born" "$(authz_bin)" >> "$LOCAL_STACK_DIR/pids"
  for _ in {1..600}; do
    address=$(grep -oE 'bh-authz: listening on 127\.0\.0\.1:[0-9]+' "$LOCAL_STACK_DIR/authz.log" |
      tail -n +"$((${before:-0} + 1))" | tail -n 1 | cut -d' ' -f4 || :)
    [[ -n $address ]] && break
    # Only that it is still running: just after the fork it may not have
    # exec'd yet, so its command and environment are still the shell's.
    [[ $(start_time "$authz_pid" 2>/dev/null) == "$born" ]] || { echo 'authz exited' >&2; return 1; }
    sleep 0.1
  done
  [[ -n $address ]] || { echo 'authz did not listen' >&2; return 1; }
  printf '%s\n' "$address" > "$LOCAL_STACK_DIR/authz-address"
}
# The local Worker on the recorded edge port and persisted storage.
launch_edge() {
  node -e 'const fs=require("fs"); fs.writeFileSync(process.argv[1], JSON.stringify({
   HOSTING_ROOT:fs.readFileSync(process.argv[2]+"/hosting-root.pub","utf8"),
   RECEIPT_KEY:fs.readFileSync(process.argv[2]+"/receipt.seed","utf8"),
   RECEIPT_CERT:fs.readFileSync(process.argv[2]+"/receipt.cert","utf8"),
   AUTHZ_BACKENDS:JSON.stringify([{url:"http://"+process.argv[3]+"/v1/channel",ready:true}])
  }),{mode:0o600})' "$LOCAL_STACK_DIR/bindings.json" "$LOCAL_STACK_DIR/keys" "$(<"$LOCAL_STACK_DIR/authz-address")"
  rm -f "$LOCAL_STACK_DIR/edge-url"
  node scripts/local-edge.mjs "$LOCAL_STACK_DIR" "$LOCAL_STACK_BIND" "$edge_port" >>"$LOCAL_STACK_DIR/edge.log" 2>&1 &
  local edge_pid=$! born
  born=$(start_time "$edge_pid")
  printf '%s %s %s\n' "$edge_pid" "$born" "scripts/local-edge.mjs" >> "$LOCAL_STACK_DIR/pids"
  for _ in {1..600}; do
    [[ -f "$LOCAL_STACK_DIR/edge-url" ]] && break
    [[ $(start_time "$edge_pid" 2>/dev/null) == "$born" ]] || { echo 'edge exited' >&2; return 1; }
    sleep 0.1
  done
  [[ -f "$LOCAL_STACK_DIR/edge-url" ]] || { echo 'edge did not listen' >&2; return 1; }
}
case "$1" in
  down) stop; exit 0 ;;
  stop-part)
    # One part only: the edge stops gracefully (its local workerd child goes
    # with it); the authorization service is killed as a crash would.
    signal=TERM; [[ $2 == authz ]] && signal=KILL
    stop_matching "$(part_executable "$2")" "$signal"
    [[ -f "$LOCAL_STACK_DIR/pids" ]] && { grep -vF " $(part_executable "$2")" "$LOCAL_STACK_DIR/pids" > "$LOCAL_STACK_DIR/pids.next" || :; mv "$LOCAL_STACK_DIR/pids.next" "$LOCAL_STACK_DIR/pids"; }
    [[ $2 == edge ]] && rm -f "$LOCAL_STACK_DIR/edge-url"
    exit 0
    ;;
  start-part)
    # The same part again on its recorded address, keys and storage.
    umask 077
    [[ -f "$LOCAL_STACK_DIR/launch-id" && -f "$LOCAL_STACK_DIR/edge-port" && -f "$LOCAL_STACK_DIR/authz-address" ]] ||
      { echo 'no running stack to start a part of' >&2; exit 1; }
    ! grep -qF " $(part_executable "$2")" "$LOCAL_STACK_DIR/pids" 2>/dev/null || { echo "$2 already recorded; stop-part first" >&2; exit 1; }
    export LOCAL_STACK_LAUNCH_ID="$(<"$LOCAL_STACK_DIR/launch-id")"
    edge_port=$(<"$LOCAL_STACK_DIR/edge-port")
    case "$2" in
      authz) launch_authz "$(<"$LOCAL_STACK_DIR/authz-address")" ;;
      edge) launch_edge ;;
    esac
    wait_up
    exit
    ;;
  status)
    if live && [[ -f "$LOCAL_STACK_DIR/edge-url" ]] &&
       curl --noproxy '*' --silent --max-time 2 --output /dev/null \
         --write-out '%{http_code}' "$(<"$LOCAL_STACK_DIR/edge-url")/v1/data" | grep -qx 426; then
      printf 'up: %s\n' "$(<"$LOCAL_STACK_DIR/edge-url")"
      exit 0
    fi
    why_down >&2
    echo 'down or unreachable'
    exit 1
    ;;
esac
umask 077
if live; then echo 'stack already running; use status or down' >&2; exit 1; fi
# Refuse to overwrite a PID file we cannot verify: it may belong to a live
# process from an earlier run. A crashed stack can be recovered with down.
[[ ! -s "$LOCAL_STACK_DIR/pids" ]] || { echo 'stale pids file; run down first' >&2; exit 1; }
mkdir -p "$LOCAL_STACK_DIR/keys" "$LOCAL_STACK_DIR/workerd"
chmod 700 "$LOCAL_STACK_DIR" "$LOCAL_STACK_DIR/keys" "$LOCAL_STACK_DIR/workerd"
if [[ -z $LOCAL_STACK_PREBUILT ]]; then
  cargo build --quiet --locked --offline -p bh-authz --features synthetic-attestation --bin bh-authz --examples
fi
if [[ ! -f "$LOCAL_STACK_DIR/keys/hosting-root.seed" ]]; then
  "$CARGO_TARGET_DIR/debug/examples/local_keys" "$LOCAL_STACK_DIR/keys"
else
  # Keep every key and the stored logs. A fresh signature at the old
  # generation would conflict with a device's previously saved policy.
  "$CARGO_TARGET_DIR/debug/examples/local_keys" "$LOCAL_STACK_DIR/keys" renew
fi
# Renewing keeps the home's recovery key; keys made before it had one can't.
[[ -s "$LOCAL_STACK_DIR/keys/recovery.seed" && -s "$LOCAL_STACK_DIR/keys/recovery.cert" ]] || {
  echo 'stack keys have no recovery key; use a fresh LOCAL_STACK_DIR' >&2; exit 1;
}
# Always ask Cargo for the current sources, even with a nonempty generated
# artifact. The incremental build is cheap; an existing file is not freshness.
if [[ -z $LOCAL_STACK_PREBUILT ]]; then
  nix develop --offline .#cryptoWorker --command bash -euc '
    RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
    cargo build --locked --offline --target wasm32-unknown-unknown -p bh-sync-worker --lib
    cp "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/debug/bh_sync_worker.wasm" services/sync-worker/sync_worker.wasm
  '
fi
[[ -s services/sync-worker/sync_worker.wasm ]] || { echo 'local Worker not built' >&2; exit 1; }
[[ -f tests/crypto-worker/node_modules/miniflare/dist/src/index.js ]] || {
  echo 'local Miniflare missing; provision pinned test dependencies offline' >&2; exit 1;
}
node -p 'require("node:crypto").randomBytes(32).toString("hex")' > "$LOCAL_STACK_DIR/launch-id"
export LOCAL_STACK_LAUNCH_ID="$(<"$LOCAL_STACK_DIR/launch-id")"
# Both peers require the other's URL at launch. Reserve a candidate port
# using a loopback socket, then close it immediately before its server binds.
# A restarted stack keeps its recorded ports, so devices reconnect to the
# same endpoint and the Worker reaches the same service address. They are
# chosen below the kernel's ephemeral range, so no outgoing connection is
# given one while its server is restarting.
free_port() {
  python3 -c '
import random, socket
low = int(open("/proc/sys/net/ipv4/ip_local_port_range").read().split()[0])
for _ in range(500):
    port = random.randrange(10000, low) if low > 11000 else 0
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        print(s.getsockname()[1])
        break
    except OSError:
        pass
    finally:
        s.close()
'
}
if [[ -s "$LOCAL_STACK_DIR/edge-port" ]]; then
  edge_port=$(<"$LOCAL_STACK_DIR/edge-port")
else
  edge_port=$(free_port)
  printf '%s\n' "$edge_port" > "$LOCAL_STACK_DIR/edge-port"
fi
# Only the backend's observed bound address enters the local Worker
# configuration.
trap 'stop' EXIT
: > "$LOCAL_STACK_DIR/pids"
listen="127.0.0.1:$(free_port)"
[[ -s "$LOCAL_STACK_DIR/authz-address" ]] && listen=$(<"$LOCAL_STACK_DIR/authz-address")
launch_authz "$listen" || exit 1
launch_edge || exit 1
# Host-side URL stays loopback even when workerd listens on all interfaces.
local_url="http://127.0.0.1:$edge_port"
public_url="$local_url"
[[ "$LOCAL_STACK_BIND" == 0.0.0.0 ]] && public_url="http://10.0.2.2:$edge_port"
cat > "$LOCAL_STACK_DIR/env" <<EOF
LOCAL_STACK_EDGE_URL=$public_url
LOCAL_STACK_HOST_EDGE_URL=$local_url
LOCAL_STACK_HOSTING_ROOT=$(<"$LOCAL_STACK_DIR/keys/hosting-root.pub")
LOCAL_STACK_APP_ROOT=$(<"$LOCAL_STACK_DIR/keys/app-root.pub")
LOCAL_STACK_POLICY=$LOCAL_STACK_DIR/keys/policy.json
LOCAL_STACK_RECOVERY_KEY=$(<"$LOCAL_STACK_DIR/keys/recovery.cert")
EOF
chmod 600 "$LOCAL_STACK_DIR/env"
wait_up || exit 1
printf 'SYNTHETIC ATTESTATION — local only\n'
cat "$LOCAL_STACK_DIR/env"
trap - EXIT
