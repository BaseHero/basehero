#!/usr/bin/env bash
# Real-app WebDriver test on an x86_64 Android emulator.
#
#   nix develop .#androidEmulator --command bash apps/client/tests/webdriver/run-android.sh
#
# Builds and signs a probe APK with the non-default `webdriver` feature (APK=...
# to reuse one), creates its own disposable AVD, boots it headless, refuses any
# non-emulator adb device before installing, refuses to connect unless the host
# exposes loopback only, runs the shared spec, then stops only the PIDs it
# started and deletes the AVD.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

: "${ANDROID_HOME:?run in nix develop .#androidEmulator}"
adb start-server >/dev/null
refuse_attached_android
# Caller-supplied location is only a parent; cleanup removes only our own directory.
work=$(mktemp -d "${WEBDRIVER_WORK:-${TMPDIR:-/tmp}}/bh-webdriver-android.XXXXXX")
avd_home=$work/avd
avd_name=bh_webdriver_probe
serial=emulator-5554
mkdir -p "$avd_home"
export ANDROID_AVD_HOME=$avd_home

EMU_PID=""
cleanup() {
  if [ -n "$EMU_PID" ]; then
    adb -s "$serial" shell am force-stop app.basehero.client >/dev/null 2>&1 || true
    adb -s "$serial" emu kill >/dev/null 2>&1 || kill "$EMU_PID" 2>/dev/null || true
    wait "$EMU_PID" 2>/dev/null || true
    echo "stopped emulator $EMU_PID"
  fi
  rm -rf "$work"
  echo "removed $work"
}
trap cleanup EXIT


apk=${APK:-}
if [ -z "$apk" ]; then
  echo "--- building the APK with the webdriver feature"
  ( cd "$basehero_dir/apps/client" && cargo tauri android build --target x86_64 --apk --ci --features webdriver )
  unsigned=$(ls -t "$basehero_dir"/apps/client/src-tauri/gen/android/app/build/outputs/apk/*/release/*.apk | head -1)
  keystore=$work/debug.keystore
  keytool -genkeypair -keystore "$keystore" -storepass android -keypass android \
    -alias bhwebdriver -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=BaseHero WebDriver test"
  apk=$work/probe.apk
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$work/aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$apk" "$work/aligned.apk"
fi
[ -f "$apk" ] || { echo "missing APK $apk" >&2; exit 2; }
python3 -m unittest discover -s "$basehero_dir/scripts" -p test_webdriver_android_manifest.py
# APK= may point outside this worktree. Validate its binary manifest and
# packaged backup/transfer resources, never an unrelated Gradle merged XML.
python3 "$basehero_dir/scripts/webdriver_android_manifest.py" \
  "$apk" "$ANDROID_HOME/build-tools/35.0.0/aapt"
echo "APK $apk ($(stat -c %s "$apk") bytes)"

echo "--- creating disposable AVD $avd_name"
avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
[ -x "$avdmanager" ] || { echo "avdmanager not found under $ANDROID_HOME" >&2; exit 2; }
echo no | "$avdmanager" create avd -n "$avd_name" -k "system-images;android-36;google_apis;x86_64" -d pixel_6 --force >/dev/null

echo "--- booting the emulator headless"
refuse_attached_android
boot_start=$(date +%s%3N)
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics \
  -gpu swiftshader_indirect -memory 2048 -cores 4 -port 5554 -no-snapshot > "$work/emulator.log" 2>&1 &
EMU_PID=$!
echo "emulator pid $EMU_PID"
adb -s "$serial" wait-for-device
until [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
  kill -0 "$EMU_PID" 2>/dev/null || { echo "emulator exited before boot" >&2; exit 1; }
  sleep 1
done
echo "boot to sys.boot_completed: $(( $(date +%s%3N) - boot_start )) ms"

qemu=$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')
boot_qemu=$(adb -s "$serial" shell getprop ro.boot.qemu | tr -d '\r')
echo "ro.kernel.qemu='$qemu' ro.boot.qemu='$boot_qemu'"
case "$qemu$boot_qemu" in
  *1*) ;;
  *) echo "device does not report an emulator; refusing to install" >&2; exit 4 ;;
esac

refuse_occupied_port
adb -s "$serial" forward "tcp:$webdriver_port" "tcp:$webdriver_port" >/dev/null
adb -s "$serial" install -r "$apk" >/dev/null
# Unlock first: an Activity launched behind the keyguard can remain hidden and
# its WebView never receives a non-zero layout even when /status is ready.
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP >/dev/null
adb -s "$serial" shell wm dismiss-keyguard >/dev/null
adb -s "$serial" shell input keyevent 82 >/dev/null
adb -s "$serial" shell am start -n "$webdriver_activity"
wait_for_status ""

echo "--- device listeners (0.0.0.0 is upstream's own Android bind)"
port_hex=$(printf '%04X' "$webdriver_port")
adb -s "$serial" shell "cat /proc/net/tcp /proc/net/tcp6" | awk -v port=":$port_hex" 'NR == 1 || $2 ~ port { print $1, $2, $3, $4 }'

echo "--- waiting for a laid-out WebView"
layout_ready=0
if ! node "$webdriver_dir/wait-for-layout.mjs"; then
  echo '--- hidden WebView; restarting the emulator app once before refusing a blank screenshot' >&2
  adb -s "$serial" shell am force-stop app.basehero.client
  adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
  adb -s "$serial" shell wm dismiss-keyguard
  adb -s "$serial" shell am start -n "$webdriver_activity"
  wait_for_status ""
  node "$webdriver_dir/wait-for-layout.mjs" || layout_ready=1
fi
if [ "$layout_ready" != 0 ]; then
  echo '--- viewport failure: power, keyguard and focused window' >&2
  adb -s "$serial" shell dumpsys power | grep -E 'Wakefulness|Display Power|mHolding' >&2 || true
  adb -s "$serial" shell dumpsys window | grep -E 'mCurrentFocus|mDreamingLockscreen|mShowingLockscreen' >&2 || true
  adb -s "$serial" shell dumpsys activity activities | grep -E 'topResumedActivity|mResumedActivity' >&2 || true
  adb -s "$serial" shell dumpsys window windows | grep -A 30 'Window #.*app.basehero.client' >&2 || true
  adb -s "$serial" logcat -d -t 3000 | grep -Ei 'chromium|WebView|surface|bh_client|basehero|EGL|crash' | tail -100 >&2 || true
  exit 1
fi

require_loopback
ensure_webdriverio
run_spec
echo "webdriver-android PASS"
