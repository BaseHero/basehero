#!/usr/bin/env bash
# Disposable, flagged synthetic stack and its two build-time endpoint files.
set -euo pipefail

write_endpoints() {
  local env_file=$1 host=$2
  umask 077
  python3 - "$env_file" "$host" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

env_file = Path(sys.argv[1])
host = sys.argv[2]
if not host or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.' for c in host):
    raise SystemExit('invalid Tailscale host name')
values = dict(line.split('=', 1) for line in env_file.read_text().splitlines())
local = urlsplit(values['LOCAL_STACK_HOST_EDGE_URL'])
if local.scheme != 'http' or local.hostname != '127.0.0.1' or not local.port or local.path:
    raise SystemExit('unexpected local stack host URL')
if urlsplit(values['LOCAL_STACK_EDGE_URL']).hostname != '10.0.2.2':
    raise SystemExit('local stack must be bound for emulator access')
policy = Path(values['LOCAL_STACK_POLICY'])
endpoint = {
    'edge_url': values['LOCAL_STACK_EDGE_URL'],
    'hosting_root': values['LOCAL_STACK_HOSTING_ROOT'],
    'app_root': values['LOCAL_STACK_APP_ROOT'],
    'policy': policy.read_bytes().hex(),
    'policy_signature': (policy.parent / 'policy.sig').read_text().strip(),
    'recovery_key': values['LOCAL_STACK_RECOVERY_KEY'],
    'max_lifetime_secs': 86400,
    'max_uncertainty_secs': 0,
    'build_floor': 1,
    'appraisal': 'synthetic',
}
for name, url in [('endpoint-emulator.json', endpoint['edge_url']),
                  ('endpoint-mac.json', f'http://{host}:{local.port}')]:
    path = env_file.parent / name
    path.write_text(json.dumps({**endpoint, 'edge_url': url}, sort_keys=True) + '\n')
    path.chmod(0o600)
    print(f'{name}: {url}')
PY
}

# Installed only after our own local-stack.sh up succeeds. A failed build or
# a refused up (including an already-running stack) is not ours to stop.
cleanup_started() {
  LOCAL_STACK_DIR="$LOCAL_STACK_DIR" bash scripts/local-stack.sh down || :
  rm -f "$LOCAL_STACK_DIR/endpoint-emulator.json" "$LOCAL_STACK_DIR/endpoint-mac.json"
}

# Sourcing defines the pure endpoint writer for tests without starting the stack.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/basehero-local-stack-target}"
LOCAL_STACK_DIR="${LOCAL_STACK_DIR:-/tmp/basehero-local-stack-${UID}}"
case "${1:-}" in
  up)
    nix develop --offline --command env BH_FLAG_REMOVAL_WAIT=5m cargo build --locked --offline -p bh-authz --features synthetic-attestation --bin bh-authz --examples
    nix develop --offline .#cryptoWorker --command bash -euc '
      BH_FLAG_REMOVAL_WAIT=5m RUSTFLAGS="-C link-arg=--allow-undefined-file=$(pwd)/tests/crypto-worker/allowed-imports.txt" \
      cargo build --locked --offline --target wasm32-unknown-unknown -p bh-sync-worker --lib
      cp "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/debug/bh_sync_worker.wasm" services/sync-worker/sync_worker.wasm
    '
    LOCAL_STACK_PREBUILT=1 LOCAL_STACK_BIND=0.0.0.0 LOCAL_STACK_DIR="$LOCAL_STACK_DIR" bash scripts/local-stack.sh up
    trap cleanup_started EXIT
    write_endpoints "$LOCAL_STACK_DIR/env" "$(hostname -s)"
    trap - EXIT
    ;;
  down)
    LOCAL_STACK_DIR="$LOCAL_STACK_DIR" bash scripts/local-stack.sh down
    rm -f "$LOCAL_STACK_DIR/endpoint-emulator.json" "$LOCAL_STACK_DIR/endpoint-mac.json"
    ;;
  status)
    LOCAL_STACK_DIR="$LOCAL_STACK_DIR" bash scripts/local-stack.sh status
    ;;
  *) echo 'usage: recovery-local-stack.sh up|down|status' >&2; exit 2 ;;
esac
