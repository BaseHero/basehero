#!/usr/bin/env bash
# Shared helpers for the real-app WebDriver runners (Linux, macOS, Android).
# Sourced, not executed.
set -euo pipefail

webdriver_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
basehero_dir=$(cd "$webdriver_dir/../../../.." && pwd)
webdriver_port=4445
webdriver_screenshot=${WEBDRIVER_SCREENSHOT:-$webdriver_dir/session-screenshot.png}
webdriver_activity=app.basehero.client/.MainActivity

ensure_webdriverio() {
  if [ ! -d "$webdriver_dir/node_modules" ]; then
    npm ci --prefix "$webdriver_dir" --ignore-scripts --no-audit --no-fund
  fi
}

# Refuse any existing listener before launching the app or creating an adb forward.
# Otherwise a failed bind can silently test a different worktree's app.
refuse_occupied_port() {
  local listing
  if command -v ss >/dev/null 2>&1; then
    listing=$(ss -ltn "( sport = :$webdriver_port )" | tail -n +2)
  else
    listing=$(lsof -nP -iTCP:"$webdriver_port" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)
  fi
  if [ -n "$listing" ]; then
    echo "refusing: already listening on $webdriver_port:" >&2
    printf '%s\n' "$listing" >&2
    return 1
  fi
}

# Do not ever commandeer another task's emulator, including offline devices.
refuse_attached_android() {
  local devices listeners
  devices=$(adb devices | awk 'NR > 1 && NF > 1 { print }')
  if [ -n "$devices" ]; then
    echo "refusing: Android device already attached:" >&2
    printf '%s\n' "$devices" >&2
    return 1
  fi
  if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -ltn '( sport = :5554 or sport = :5555 )' | tail -n +2)
  else
    listeners=$(lsof -nP -iTCP:5554 -iTCP:5555 -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)
  fi
  if [ -n "$listeners" ]; then
    echo "refusing: emulator ports 5554/5555 already listening:" >&2
    printf '%s\n' "$listeners" >&2
    return 1
  fi
}

# Wait for /status, failing if the app exits first.
wait_for_status() {
  local pid=$1
  for _ in $(seq 1 600); do
    if curl -fsS "http://127.0.0.1:$webdriver_port/status" >/dev/null 2>&1; then
      return 0
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      echo "app exited before /status became ready" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "no /status after 60 s" >&2
  return 1
}

# Refuse to connect unless the listener is loopback-only.
require_loopback() {
  local listing
  if command -v ss >/dev/null 2>&1; then
    listing=$(ss -ltn | grep -F ":$webdriver_port " || true)
  else
    listing=$(lsof -nP -iTCP:"$webdriver_port" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)
  fi
  if [ -z "$listing" ]; then
    echo "nothing is listening on $webdriver_port" >&2
    return 1
  fi
  if printf '%s\n' "$listing" | grep -qv '127\.0\.0\.1[:.]'; then
    echo "refusing: the listener is not loopback-only:" >&2
    printf '%s\n' "$listing" >&2
    return 1
  fi
  echo "listener is 127.0.0.1:$webdriver_port only"
}

run_spec() {
  ( cd "$webdriver_dir" && node spec.mjs "$webdriver_screenshot" )
}
