#!/usr/bin/env bash
# Boot only BaseHero's API 36 Pixel 9 Pro Fold on port 5580 (headless).
# Use `scripts/android-emulator.sh stop` to stop only the recorded, verified PID.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?run inside nix develop .#androidEmulator}"
export ANDROID_AVD_HOME="${ANDROID_AVD_HOME:-$PWD/.android-avd}"
export ANDROID_USER_HOME="${ANDROID_USER_HOME:-$PWD/.android-user}"
mkdir -p "$ANDROID_AVD_HOME" "$ANDROID_USER_HOME"
serial=emulator-5580
avd=bh-fold-36
pid_file="$ANDROID_USER_HOME/$avd.pid"
case "${1:-start}" in
  stop)
    [ -f "$pid_file" ] || { echo "no recorded $avd emulator PID" >&2; exit 1; }
    read -r pid < "$pid_file"
    [[ "$pid" =~ ^[0-9]+$ ]] && [ -r "/proc/$pid/cmdline" ] || {
      echo "recorded $avd emulator PID is no longer running" >&2; exit 1;
    }
    mapfile -d '' -t command < "/proc/$pid/cmdline"
    [[ "${command[0]:-}" == */qemu-system-x86_64-headless ]] || {
      echo "recorded PID $pid is not the emulator process" >&2; exit 1;
    }
    found_avd=false found_port=false
    for ((i = 1; i < ${#command[@]} - 1; i++)); do
      [ "${command[i]}" = -avd ] && [ "${command[i+1]}" = "$avd" ] && found_avd=true
      [ "${command[i]}" = -port ] && [ "${command[i+1]}" = 5580 ] && found_port=true
    done
    [ "$found_avd" = true ] && [ "$found_port" = true ] || {
      echo "recorded PID $pid is not $avd on port 5580" >&2; exit 1;
    }
    [ "$(adb -s "$serial" emu avd name | tr -d '\r' | head -n 1)" = "$avd" ] || {
      echo "port 5580 is not $avd; refusing to stop PID $pid" >&2; exit 1;
    }
    kill "$pid"
    for ((i = 0; i < 30; i++)); do
      if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$pid_file"
        echo "stopped $avd emulator PID $pid"
        exit 0
      fi
      sleep 1
    done
    echo "emulator PID $pid did not stop after SIGTERM" >&2
    exit 1
    ;;
  start) ;;
  *) echo 'Usage: android-emulator.sh [start|stop]' >&2; exit 2 ;;
esac
if [ ! -f "$ANDROID_AVD_HOME/$avd.ini" ]; then
  # Use the SDK device profile rather than inventing fold-screen dimensions.
  printf 'no\n' | avdmanager create avd -n "$avd" \
    -k 'system-images;android-36;google_apis;x86_64' -d pixel_9_pro_fold --force
fi
if adb -s "$serial" get-state >/dev/null 2>&1; then
  active=$(adb -s "$serial" emu avd name | tr -d '\r' | head -n 1)
  [ "$active" = "$avd" ] || { echo "port 5580 belongs to $active, not $avd" >&2; exit 1; }
else
  # Never take a port belonging to someone else, even if adb has not seen it.
  if (exec 3<>/dev/tcp/127.0.0.1/5580) 2>/dev/null ||
     (exec 3<>/dev/tcp/127.0.0.1/5581) 2>/dev/null; then
    echo 'emulator port 5580 or 5581 is occupied' >&2
    exit 1
  fi
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'KVM unavailable' >&2; exit 1; }
  emulator -avd "$avd" -port 5580 -no-window -no-audio -no-boot-anim \
    -no-metrics -gpu swiftshader_indirect -memory 2048 -cores 4 -no-snapshot \
    >"$ANDROID_USER_HOME/bh-fold-36.log" 2>&1 < /dev/null &
  pid=$!
  printf '%s\n' "$pid" >"$pid_file"
  echo "started $avd emulator PID $pid"
fi
adb -s "$serial" wait-for-device
until [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
[ "$(adb -s "$serial" emu avd name | tr -d '\r' | head -n 1)" = "$avd" ] || {
  echo 'unexpected emulator on port 5580' >&2; exit 1;
}
[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || {
  echo 'not an emulator' >&2; exit 1;
}
echo "$serial ($avd) booted"
