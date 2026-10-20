#!/usr/bin/env bash
# Shared helpers for disposable Android emulator runners. Sourced, not executed.
#
# Callers set `serial`, `avd_name`, `work` and `pid` and define their own `adb`
# guard. Every helper addresses only "$serial": other emulators may run on the
# same host and are never touched, nor is any non-emulator device.
set -euo pipefail

# The emulator's console and adb ports for `-port <even port>`.
emulator_port_free() {
  local port=$1 listeners
  if command adb devices | awk 'NR > 1 { print $1 }' | grep -qx "emulator-$port"; then
    return 1
  fi
  if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -ltn "( sport = :$port or sport = :$((port + 1)) )" | tail -n +2)
  else
    listeners=$(lsof -nP -iTCP:"$port" -iTCP:"$((port + 1))" -sTCP:LISTEN 2>/dev/null | tail -n +2 || true)
  fi
  [ -z "$listeners" ]
}

# First free even console port from $1 (default 5554) up to 5584.
free_emulator_port() {
  local port
  for port in $(seq "${1:-5554}" 2 5584); do
    if emulator_port_free "$port"; then
      echo "$port"
      return 0
    fi
  done
  echo 'no free emulator port in 5554-5585' >&2
  return 1
}

# 0: our AVD owns the serial; 1: nothing answers yet; 2: a different emulator.
avd_on_serial() {
  local name
  name=$(timeout 5 adb -s "$serial" emu avd name 2>/dev/null | tr -d '\r' | { IFS= read -r line || :; printf '%s' "$line"; }) || return 1
  [ "$name" = "$avd_name" ] && return 0
  [ -z "$name" ] && return 1
  return 2
}

# Wait for our own AVD to finish booting on its serial.
wait_for_boot() {
  local ready=0
  for _ in $(seq 1 240); do
    kill -0 "$pid" 2>/dev/null || { echo 'emulator died before boot' >&2; return 1; }
    if avd_on_serial; then
      if [ "$(timeout 5 adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
        ready=1
        break
      fi
    else
      [ "$?" != 2 ] || { echo 'foreign emulator occupies serial' >&2; return 1; }
    fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo 'emulator boot timed out or serial belongs to another AVD' >&2; return 1; }
}

# A screen lock is required before Android accepts a fingerprint.
set_pin() {
  adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
  adb -s "$serial" shell wm dismiss-keyguard
  adb -s "$serial" shell input keyevent 82
  adb -s "$serial" shell locksettings set-pin 1234
  adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
  adb -s "$serial" shell wm dismiss-keyguard
  adb -s "$serial" shell input text 1234
  adb -s "$serial" shell input keyevent 66
  adb -s "$serial" shell input keyevent 82
}

# These UI steps touch only the disposable AVD. Refuse to advance if its
# Settings screen is different; never guess coordinates on another device.
screen() {
  local ok=0
  for _ in $(seq 1 10); do
    if adb -s "$serial" shell uiautomator dump /sdcard/devicekeys-window.xml >/dev/null 2>&1 &&
       adb -s "$serial" pull /sdcard/devicekeys-window.xml "$work/window.xml" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  [ "$ok" = 1 ] || { echo 'no Settings UI hierarchy' >&2; return 1; }
  python3 - "$work/window.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
print(' | '.join(n.get('text') for n in ET.parse(sys.argv[1]).iter('node') if n.get('text')))
PY
}
tap_text() {
  local coords
  coords=$(python3 - "$work/window.xml" "$1" <<'PY'
import re, sys, xml.etree.ElementTree as ET
for n in ET.parse(sys.argv[1]).iter('node'):
    if n.get('text') == sys.argv[2]:
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', n.get('bounds')))
        print((x1+x2)//2, (y1+y2)//2)
        break
else:
    raise SystemExit('UI button not found: ' + sys.argv[2])
PY
  )
  adb -s "$serial" shell input tap $coords
}
# Enroll emulator finger $1 through Settings on the pixel_6 AVD (after set_pin).
enroll() {
  local id=$1 text
  for _ in 1 2 3; do
    adb -s "$serial" shell wm dismiss-keyguard >/dev/null
    adb -s "$serial" shell am start -a android.settings.FINGERPRINT_ENROLL >/dev/null
    sleep 2
    text=$(screen)
    if [[ "$text" == *'This app was built for an older version'* ]]; then
      tap_text OK
      sleep 1
      text=$(screen)
    fi
    if [[ "$text" == *'Re-enter your PIN'* ]]; then
      adb -s "$serial" shell input tap 540 1074
      sleep 1
      adb -s "$serial" shell input text 1234
      adb -s "$serial" shell input keyevent 66
      sleep 2
      text=$(screen)
    fi
    [[ "$text" == *'Set up Pixel Imprint'* || "$text" == *'Touch the sensor'* ]] && break
  done
  if [[ "$text" == *'Set up Pixel Imprint'* ]]; then
    for _ in 1 2 3 4; do
      if [[ "$text" == *'I AGREE'* ]]; then break; fi
      if [[ "$text" == *'MORE'* ]]; then tap_text MORE; else adb -s "$serial" shell input tap 910 2230; fi
      sleep 1
      text=$(screen)
    done
    [[ "$text" == *'I AGREE'* ]] || { echo "unexpected agreement screen: $text" >&2; exit 1; }
    tap_text 'I AGREE'
    sleep 1
    text=$(screen)
  fi
  [[ "$text" == *'Touch the sensor'* ]] || { echo "unexpected enrollment screen: $text" >&2; exit 1; }
  for _ in $(seq 1 14); do
    adb -s "$serial" emu finger touch "$id" >/dev/null
    sleep 0.5
  done
  text=$(screen)
  [[ "$text" == *'Fingerprint added'* ]] || { echo "fingerprint was not enrolled: $text" >&2; exit 1; }
  if [[ "$text" == *'Done'* ]]; then tap_text Done; else adb -s "$serial" shell input tap 900 2230; fi
}
