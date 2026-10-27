#!/usr/bin/env bash
# Debug x86_64 build for BaseHero Sample's disposable emulator.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?run inside nix develop .#androidEmulator}"
case "${1:-}" in
  build)
    (cd apps/sample && cargo tauri android build --debug --apk --target x86_64 --ci)
    ;;
  install)
    "$0" build
    apk=apps/sample/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
    [ -f "$apk" ] || { printf 'missing debug APK: %s\n' "$apk" >&2; exit 1; }
    [ "$(adb -s emulator-5580 shell getprop ro.boot.qemu.avd_name | tr -d '\r')" = bh-fold-36 ] &&
    [ "$(adb -s emulator-5580 shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || {
      echo 'port 5580 is not the disposable BaseHero emulator' >&2; exit 1;
    }
    if ! out=$(adb -s emulator-5580 install -r "$apk" 2>&1); then
      case "$out" in
        *INSTALL_FAILED_UPDATE_INCOMPATIBLE*)
          adb -s emulator-5580 uninstall app.basehero.sample
          adb -s emulator-5580 install "$apk"
          ;;
        *) printf '%s\n' "$out" >&2; exit 1 ;;
      esac
    fi
    ;;
  *) echo 'Usage: sample-android.sh build|install' >&2; exit 2 ;;
esac
