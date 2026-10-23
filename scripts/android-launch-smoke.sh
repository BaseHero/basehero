#!/bin/sh
# Launch a signed APK on a disposable emulator and catch startup crashes.
# /bin/sh does not source a caller's BASH_ENV before we can unset it.
unset BASH_ENV
set -eu
if [ "$#" -ne 2 ]; then
  echo "usage: $0 emulator-serial signed.apk" >&2
  exit 2
fi
serial=$1
apk=$2
case "$serial" in
  emulator-*) ;;
  *)
    echo "refusing to run outside an Android emulator" >&2
    exit 2
    ;;
esac
# adb can create its own files under HOME; never use the caller's ~/.android.
isolation=$(mktemp -d)
trap 'rm -rf "$isolation"' EXIT
trap 'exit 1' HUP INT TERM
export HOME="$isolation/home"
export XDG_CONFIG_HOME="$isolation/config"
export XDG_CACHE_HOME="$isolation/cache"
export XDG_DATA_HOME="$isolation/data"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
if [ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" != 1 ]; then
  echo "refusing to run outside an Android emulator" >&2
  exit 2
fi
adb -s "$serial" uninstall app.basehero.client >/dev/null 2>&1 || true
adb -s "$serial" install "$apk" >/dev/null
adb -s "$serial" logcat -c
adb -s "$serial" shell am start -n app.basehero.client/.MainActivity >/dev/null
# WebView boots asynchronously. A failed launch disappears within two seconds.
sleep 7
if ! adb -s "$serial" shell pidof app.basehero.client | grep -q '[0-9]'; then
  echo "client exited during startup; Android crash buffer follows:" >&2
  adb -s "$serial" logcat -b crash -d >&2
  exit 1
fi
if adb -s "$serial" logcat -b crash -d | grep -q '>>> app.basehero.client <<<'; then
  echo "client crashed during startup" >&2
  exit 1
fi
echo 'client stayed alive after startup'
