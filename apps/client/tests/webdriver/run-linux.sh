#!/usr/bin/env bash
# Real-app WebDriver test on Linux.
#
#   bash apps/client/tests/webdriver/run-linux.sh
#
# Builds the client with the non-default `webdriver` feature (BUILD=0 to use an
# existing CLIENT_BIN), runs it under a private Xvfb display, refuses to connect
# unless the listener is loopback-only, runs the shared spec and kills only the
# PIDs it started.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

CLIENT_BIN=${CLIENT_BIN:-$basehero_dir/target/debug/bh-client}
DISPLAY_NUM=${DISPLAY_NUM:-98}
if [ "${BUILD:-1}" = 1 ]; then
  ( cd "$basehero_dir" && cargo build --locked -p bh-client --features webdriver )
fi
[ -x "$CLIENT_BIN" ] || { echo "missing $CLIENT_BIN" >&2; exit 2; }

refuse_occupied_port

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

echo "starting $CLIENT_BIN on $DISPLAY"
WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1 "$CLIENT_BIN" &
APP_PID=$!
echo "app pid $APP_PID"
wait_for_status "$APP_PID"

require_loopback
ensure_webdriverio
run_spec
echo "webdriver-linux PASS"
