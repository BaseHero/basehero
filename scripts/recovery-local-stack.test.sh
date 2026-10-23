#!/usr/bin/env bash
# Endpoint generation can be tested without building or launching a stack.
set -euo pipefail
cd "$(dirname "$0")/.."
real_bash=$(command -v bash)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/keys" "$root/home" "$root/gh" "$root/xdg"
printf 'signed policy fixture' > "$root/keys/policy.json"
printf 'cafe\n' > "$root/keys/policy.sig"
cat > "$root/env" <<EOF
LOCAL_STACK_EDGE_URL=http://10.0.2.2:12345
LOCAL_STACK_HOST_EDGE_URL=http://127.0.0.1:12345
LOCAL_STACK_HOSTING_ROOT=$(printf '11%.0s' {1..32})
LOCAL_STACK_APP_ROOT=$(printf '22%.0s' {1..32})
LOCAL_STACK_POLICY=$root/keys/policy.json
LOCAL_STACK_RECOVERY_KEY=0001$(printf '11%.0s' {1..32})$(printf 'ab%.0s' {1..1216})$(printf 'cd%.0s' {1..64})
EOF
# A separate shell and network namespace: rendering must not start or access the stack.
env -u GH_TOKEN -u GITHUB_TOKEN HOME="$root/home" GH_CONFIG_DIR="$root/gh" XDG_CONFIG_HOME="$root/xdg" \
  unshare -rn bash --noprofile --norc -c 'source scripts/recovery-local-stack.sh; write_endpoints "$1" "$2"' _ "$root/env" neptune
python3 - "$root" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name, url in [('endpoint-emulator.json', 'http://10.0.2.2:12345'),
                  ('endpoint-mac.json', 'http://neptune:12345')]:
    file = root / name
    data = json.loads(file.read_text())
    assert data == {
        'edge_url': url, 'hosting_root': '11' * 32, 'app_root': '22' * 32,
        'policy': b'signed policy fixture'.hex(), 'policy_signature': 'cafe',
        'recovery_key': '0001' + '11' * 32 + 'ab' * 1216 + 'cd' * 64,
        'max_lifetime_secs': 86400, 'max_uncertainty_secs': 0, 'build_floor': 1,
        'appraisal': 'synthetic',
    }, (name, data)
    assert file.stat().st_mode & 0o777 == 0o600
print('2 endpoint files, URLs, fields, recovery certificates and permissions passed')
PY
# Refuse an env from a stack that was not bound for the emulator.
cp "$root/env" "$root/bad-env"
python3 - "$root/bad-env" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace('http://10.0.2.2:12345', 'http://127.0.0.1:12345'))
PY
if env -u GH_TOKEN -u GITHUB_TOKEN HOME="$root/home" GH_CONFIG_DIR="$root/gh" XDG_CONFIG_HOME="$root/xdg" \
  unshare -rn bash --noprofile --norc -c 'source scripts/recovery-local-stack.sh; write_endpoints "$1" "$2"' _ "$root/bad-env" neptune >/dev/null 2>&1; then
  echo 'loopback-only stack unexpectedly produced emulator endpoint' >&2; exit 1
fi
printf 'loopback-only stack refused\n'

# The build and stack are isolated stubs; no real stack, process or network.
mkdir -p "$root/stubs" "$root/stack"
printf '#!%s\n' "$real_bash" > "$root/stubs/nix"
cat >> "$root/stubs/nix" <<'SH'
[[ ${1:-} == develop && ${2:-} == --offline ]] || exit 90
SH
printf '#!%s\n' "$real_bash" > "$root/stubs/bash"
cat >> "$root/stubs/bash" <<'SH'
[[ ${1:-} == scripts/local-stack.sh ]] || exit 91
case "${2:-}" in
  up)
    printf 'up\n' >> "$STUB_CALLS"
    if [[ $STUB_MODE == pre-existing ]]; then exit 1; fi
    cp "$STUB_BAD_ENV" "$LOCAL_STACK_DIR/env"
    ;;
  down)
    printf 'down\n' >> "$STUB_CALLS"
    rm -f "$LOCAL_STACK_DIR/env"
    ;;
  *) exit 92 ;;
esac
SH
chmod +x "$root/stubs/nix" "$root/stubs/bash"
# A successful up followed by invalid env must down exactly once. An up
# refusal, including a pre-existing stack, must never acquire cleanup rights.
for mode in fresh pre-existing; do
  calls="$root/$mode.calls"
  : > "$calls"
  isolated=(env -u GH_TOKEN -u GITHUB_TOKEN HOME="$root/home" GH_CONFIG_DIR="$root/gh"
    XDG_CONFIG_HOME="$root/xdg" PATH="$root/stubs:$PATH" LOCAL_STACK_DIR="$root/stack"
    STUB_BAD_ENV="$root/bad-env" STUB_CALLS="$calls" STUB_MODE="$mode" unshare -rn)
  "${isolated[@]}" "$real_bash" --noprofile --norc -c '
    [[ $(command -v nix) == "$1/nix" && $(command -v bash) == "$1/bash" ]]
  ' _ "$root/stubs"
  if "${isolated[@]}" "$real_bash" --noprofile --norc scripts/recovery-local-stack.sh up > "$root/$mode.out" 2>&1; then
    echo "unexpected successful $mode stack start" >&2; exit 1
  fi
  expected=up
  [[ $mode == fresh ]] && expected=$'up\ndown'
  [[ $(< "$calls") == "$expected" ]] || {
    printf '%s: expected %q calls, got %q\n' "$mode" "$expected" "$(< "$calls")" >&2; exit 1;
  }
done
printf 'fresh failed endpoint cleaned up; pre-existing stack left alone\n'
