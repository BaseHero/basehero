#!/usr/bin/env bash
# Real-app WebDriver test on macOS (run on the host itself, including over SSH).
#
#   bash apps/client/tests/webdriver/run-macos.sh
#
# Builds the client with the non-default `webdriver` feature (BUILD=0 to use an
# existing CLIENT_BIN), launches it directly, refuses to connect unless the
# listener is loopback-only, runs the shared spec and kills only its own PID.
# A console GUI session is not required: the direct launch joins its own session
# and WebKit still renders and snapshots the window.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

CLIENT_BIN=${CLIENT_BIN:-$basehero_dir/target/debug/bh-client}
if [ "${BUILD:-1}" = 1 ]; then
  ( cd "$basehero_dir" && cargo build --locked -p bh-client --features webdriver )
fi
[ -x "$CLIENT_BIN" ] || { echo "missing $CLIENT_BIN" >&2; exit 2; }

refuse_occupied_port

APP_PID=""
cleanup() {
  if [ -n "$APP_PID" ]; then kill "$APP_PID" 2>/dev/null && echo "killed app $APP_PID"; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "starting $CLIENT_BIN"
"$CLIENT_BIN" &
APP_PID=$!
echo "app pid $APP_PID"
wait_for_status "$APP_PID"

require_loopback
ensure_webdriverio
run_spec
echo "webdriver-macos PASS"
