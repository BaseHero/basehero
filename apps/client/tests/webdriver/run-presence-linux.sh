#!/usr/bin/env bash
# Real desktop app presence run on the local sync stack.
#
#   LOCAL_STACK_DIR=/tmp/... bash apps/client/tests/android/run-sync.sh prepare
#   LOCAL_STACK_DIR=/tmp/... CARGO_TARGET_DIR=/tmp/... \
#     bash apps/client/tests/webdriver/run-presence-linux.sh
#
# The peer is the local-sync test device process. The app is built with the
# non-default webdriver, desktop-fixture and synthetic-attestation features
# against the stack's endpoint, runs under a private HOME and Xvfb, and the
# shared WebDriver spec joins the peer's account, then drives the peer's
# selection and checks the remote caret in the real DOM.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
cd "$basehero_dir"

: "${LOCAL_STACK_DIR:?private local stack}" "${CARGO_TARGET_DIR:?private target}"
CLIENT_BIN=${CLIENT_BIN:-$CARGO_TARGET_DIR/debug/bh-client}
SYNC_PEER_BIN=${SYNC_PEER_BIN:-$CARGO_TARGET_DIR/debug/examples/local_sync_device}
SYNC_HOST_ENDPOINT=${SYNC_HOST_ENDPOINT:-$LOCAL_STACK_DIR/host-endpoint.json}
DISPLAY_NUM=${DISPLAY_NUM:-96}
bash scripts/local-stack.sh status >/dev/null
[ -f "$SYNC_HOST_ENDPOINT" ] || { echo "missing $SYNC_HOST_ENDPOINT" >&2; exit 2; }
[ -x "$SYNC_PEER_BIN" ] || { echo "missing peer $SYNC_PEER_BIN" >&2; exit 2; }

if [ "${BUILD:-1}" = 1 ]; then
  ( cd "$basehero_dir" && BH_SYNC_ENDPOINT=$(realpath "$SYNC_HOST_ENDPOINT") \
    cargo build --locked --offline -p bh-client \
    --features webdriver,desktop-fixture,synthetic-attestation )
fi
[ -x "$CLIENT_BIN" ] || { echo "missing $CLIENT_BIN" >&2; exit 2; }
refuse_occupied_port

SYNC_RUN=${SYNC_RUN:-$(mktemp -d /tmp/bh-presence-desktop.XXXXXX)}
PRESENCE_SHOTS=${PRESENCE_SHOTS:-$SYNC_RUN/shots}
HOME_DIR=${HOME_DIR:-$SYNC_RUN/home}
mkdir -p "$SYNC_RUN" "$PRESENCE_SHOTS" "$HOME_DIR"
chmod 700 "$SYNC_RUN" "$HOME_DIR"

XVFB_PID=""
APP_PID=""
cleanup() {
  if [ -n "$APP_PID" ]; then kill "$APP_PID" 2>/dev/null && echo "killed app $APP_PID"; fi
  if [ -n "$XVFB_PID" ]; then kill "$XVFB_PID" 2>/dev/null && echo "killed Xvfb $XVFB_PID"; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

Xvfb ":$DISPLAY_NUM" -screen 0 1280x800x24 -nolisten tcp &
XVFB_PID=$!
export DISPLAY=":$DISPLAY_NUM"
sleep 1

echo "starting $CLIENT_BIN on $DISPLAY with HOME=$HOME_DIR"
HOME="$HOME_DIR" WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 \
  "$CLIENT_BIN" &
APP_PID=$!
echo "app pid $APP_PID"
wait_for_status "$APP_PID"

require_loopback
ensure_webdriverio
( cd "$webdriver_dir" && SYNC_RUN="$SYNC_RUN" SYNC_PEER_BIN="$SYNC_PEER_BIN" \
    SYNC_HOST_ENDPOINT="$SYNC_HOST_ENDPOINT" PRESENCE_SHOTS="$PRESENCE_SHOTS" \
    WEBDRIVER_PRESENCE=1 node spec.mjs "$webdriver_screenshot" )
echo "webdriver presence PASS; screenshots $PRESENCE_SHOTS"
