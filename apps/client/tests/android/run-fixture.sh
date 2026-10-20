#!/usr/bin/env bash
# Emulator fixture account check on a disposable x86_64 AVD.
#
#   nix develop .#androidEmulator --command bash apps/client/tests/android/run-fixture.sh
#
# Builds an APK with the non-default `webdriver` and `emulator-fixture` features
# (APK=... to reuse one) and signs it with a key generated for this run only.
# Proves the APK carries the labelled fixture (the release check's positive
# control), boots its own AVD on a free port (AVD_NAME=... to name it), enrolls
# an emulator fingerprint and runs fixture-account.spec.mjs. Other emulators
# and non-emulator devices are never addressed; cleanup stops only the emulator
# PID this run started and deletes its AVD.
set -euo pipefail
source "$(dirname "$0")/../webdriver/lib.sh"
source "$(dirname "$0")/emulator.sh"
android_dir=$(cd "$(dirname "$0")" && pwd)

: "${ANDROID_HOME:?run in nix develop .#androidEmulator}"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'KVM unavailable' >&2; exit 2; }
command adb start-server >/dev/null
work=$(mktemp -d "${TMPDIR:-/tmp}/bh-android-fixture.XXXXXX")
export ANDROID_AVD_HOME=$work/avd
mkdir -p "$ANDROID_AVD_HOME"
avd_name=${AVD_NAME:-bh_fixture_${work##*.}}
port=$(free_emulator_port)
serial=emulator-$port
pid=''
cleanup() {
  if [ -n "$pid" ]; then
    if kill -0 "$pid" 2>/dev/null && avd_on_serial; then
      timeout 5 adb -s "$serial" forward --remove "tcp:$webdriver_port" >/dev/null 2>&1 || true
      timeout 5 adb -s "$serial" emu kill >/dev/null 2>&1 || true
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    echo "stopped emulator $pid"
  fi
  rm -rf "$work"
  echo "removed $work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

apk=${APK:-}
if [ -z "$apk" ]; then
  echo '--- building the APK with the webdriver and emulator-fixture features'
  ( cd "$basehero_dir/apps/client" && cargo tauri android build --target x86_64 --apk --ci --features webdriver,emulator-fixture )
  unsigned="$basehero_dir/apps/client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
  keytool -genkeypair -keystore "$work/run.keystore" -storepass android -keypass android \
    -alias bhfixture -keyalg RSA -keysize 2048 -validity 1 -dname "CN=BaseHero emulator fixture test"
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$work/aligned.apk"
  apk=$work/fixture.apk
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/run.keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$apk" "$work/aligned.apk"
fi
[ -f "$apk" ] || { echo "missing APK $apk" >&2; exit 2; }
bash "$basehero_dir/scripts/android-release-check.sh" "$apk" --expect-fixture
python3 "$basehero_dir/scripts/webdriver_android_manifest.py" "$apk" "$ANDROID_HOME/build-tools/35.0.0/aapt"

echo "--- creating disposable AVD $avd_name on $serial"
avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
[ -x "$avdmanager" ] || { echo "avdmanager not found under $ANDROID_HOME" >&2; exit 2; }
echo no | "$avdmanager" create avd -n "$avd_name" -k 'system-images;android-36;google_apis;x86_64' -d pixel_6 --force >/dev/null
emulator_port_free "$port" || { echo "emulator port $port was taken" >&2; exit 1; }
refuse_occupied_port
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics \
  -gpu swiftshader_indirect -memory 2048 -cores 4 -port "$port" -no-snapshot >"$work/emulator.log" 2>&1 &
pid=$!
echo "emulator pid $pid"
wait_for_boot
adb() {
  kill -0 "$pid" 2>/dev/null && avd_on_serial || { echo 'lost disposable emulator' >&2; return 1; }
  command adb "$@"
}
[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || { echo 'not an emulator' >&2; exit 4; }
# Keep the disposable screen awake so the WebView stays visible across relaunch.
adb -s "$serial" shell svc power stayon true
set_pin
enroll 1

adb -s "$serial" install -r "$apk" >/dev/null
adb -s "$serial" forward "tcp:$webdriver_port" "tcp:$webdriver_port" >/dev/null
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP >/dev/null
adb -s "$serial" shell wm dismiss-keyguard >/dev/null
adb -s "$serial" logcat -c
adb -s "$serial" shell am start -n "$webdriver_activity" >/dev/null
wait_for_status ""
require_loopback
node "$webdriver_dir/wait-for-layout.mjs"
status=0
ANDROID_SERIAL=$serial node "$android_dir/fixture-account.spec.mjs" "${FIXTURE_SCREENSHOTS:-$android_dir/fixture}" || status=$?
echo '--- native EMULATOR FIXTURE log lines'
adb -s "$serial" logcat -d -s BaseHero:I | grep 'EMULATOR FIXTURE' || true
echo '--- biometric prompts shown (system log)'
adb -s "$serial" logcat -d | grep -iE 'biometric|fingerprint' | grep -iE 'authenticat|success' | tail -20 || true
if [ "$status" != 0 ]; then
  adb -s "$serial" logcat -d -t 3000 | grep -Ei 'basehero|devicekeys|biometric|keystore|chromium|crash|fatal' | tail -120 >&2 || true
  exit "$status"
fi
echo 'android-fixture-emulator PASS (emulator evidence)'
