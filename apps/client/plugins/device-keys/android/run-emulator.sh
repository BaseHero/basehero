#!/usr/bin/env bash
# Instrument the standalone Android library on a disposable API 36 x86_64 AVD.
# Run only from nix develop .#androidEmulator. Never connects to a physical device
# or to another emulator: every adb command names this run's own serial.
set -euo pipefail
source "$(dirname "$0")/../../../tests/webdriver/lib.sh"
source "$(dirname "$0")/../../../tests/android/emulator.sh"
module="$basehero_dir/apps/client/plugins/device-keys/android"
instrument=app.basehero.devicekeys.test/androidx.test.runner.AndroidJUnitRunner
: "${ANDROID_HOME:?run from nix develop .#androidEmulator}"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'KVM unavailable' >&2; exit 2; }
[ "$(df -Pk "$basehero_dir" | awk 'NR == 2 {print $4}')" -gt 5000000 ] || { echo 'need 5 GiB free' >&2; exit 2; }
adb start-server >/dev/null
port=$(free_emulator_port)
serial=emulator-$port
work=$(mktemp -d "${TMPDIR:-/tmp}/bh-devicekeys-emulator.XXXXXX")
export ANDROID_AVD_HOME="$work/avd"
mkdir -p "$ANDROID_AVD_HOME"
avd_name=${AVD_NAME:-bh_devicekeys_${work##*.}}
pid=''
finger_pid=''
cleanup() {
  if [ -n "$finger_pid" ]; then kill "$finger_pid" 2>/dev/null || true; wait "$finger_pid" 2>/dev/null || true; fi
  if [ -n "$pid" ]; then
    if kill -0 "$pid" 2>/dev/null && avd_on_serial; then timeout 5 adb -s "$serial" emu kill >/dev/null 2>&1 || true; fi
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

# The native probe is built ONLY into the androidTest APK; it is not a release
# or debug library artifact. In particular no production app dependency picks it up.
mkdir -p "$module/src/androidTest/jniLibs/x86_64"
"$ANDROID_HOME/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang" \
  -shared -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
  "$module/src/androidTest/native/devicekeys_probe.c" \
  -o "$module/src/androidTest/jniLibs/x86_64/libdevicekeys_probe.so"
"$basehero_dir/apps/client/src-tauri/gen/android/gradlew" -p "$module" assembleDebugAndroidTest --no-daemon
apk="$module/build/outputs/apk/androidTest/debug/bh-device-keys-android-debug-androidTest.apk"
[ -f "$apk" ] || { echo 'instrumentation APK missing' >&2; exit 2; }

avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
[ -x "$avdmanager" ] || exit 2
echo no | "$avdmanager" create avd -n "$avd_name" -k 'system-images;android-36;google_apis;x86_64' -d pixel_6 --force >/dev/null
emulator_port_free "$port" || { echo "emulator port $port was taken" >&2; exit 1; }
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics \
  -gpu swiftshader_indirect -memory 2048 -cores 4 -port "$port" -no-snapshot >"$work/emulator.log" 2>&1 &
pid=$!
wait_for_boot
# Guard each subsequent command, including the UI and test helpers, against a
# different emulator taking the serial after readiness.
adb() {
  kill -0 "$pid" 2>/dev/null && avd_on_serial || { echo 'lost disposable emulator' >&2; return 1; }
  command adb "$@"
}
[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || { echo 'not an emulator' >&2; exit 4; }
adb -s "$serial" shell setprop debug.checkjni 1
[ "$(adb -s "$serial" shell getprop debug.checkjni | tr -d '\r')" = 1 ] || { echo 'CheckJNI was not enabled' >&2; exit 1; }
set_pin
enroll 1
adb -s "$serial" install -r "$apk" >/dev/null

run_test() {
  local name=$1 fingerprint=${2:-yes} output
  echo "--- $name"
  if [ "$fingerprint" = yes ]; then
    adb -s "$serial" logcat -c
    # Tests log a token only AFTER asserting that no prompt completion occurred
    # without a finger. No ambient finger loop can race those assertions.
    ( sent=0; while :; do
        seen=$(adb -s "$serial" logcat -d -s DeviceKeysFingerprint:I | grep -c 'touch-' || true)
        while [ "$sent" -lt "$seen" ]; do
          adb -s "$serial" emu finger touch 1 >/dev/null
          sent=$((sent + 1))
        done
        sleep 0.3
      done ) &
    finger_pid=$!
  fi
  output=$(adb -s "$serial" shell am instrument -w -e class "app.basehero.devicekeys.DeviceKeysEmulatorTest#$name" "$instrument")
  if [ -n "$finger_pid" ]; then kill "$finger_pid" 2>/dev/null || true; wait "$finger_pid" 2>/dev/null || true; finger_pid=''; fi
  printf '%s\n' "$output"
  if [[ "$output" != *'OK (1 test)'* ]]; then
    echo '--- recent emulator exceptions'
    adb -s "$serial" logcat -d -t 2000 | grep -Ei 'devicekeys|biometric|keystore|exception|error' | tail -100 || true
    return 1
  fi
}
run_test cancelledCreationLeavesNothing no
run_test abortedCreationLeavesNothing no
run_test ordinaryReceiverAndPendingRoundTrip
run_test protectedReadRequiresAuthentication
run_test invalidMetadataAtCreationRollsBack no
run_test missingMetadataDoesNotRepairIt
run_test missingAliasAndFileAreInvalidated
run_test prepareEnrollmentChange
enroll 2
run_test enrollmentChangeInvalidatesControl no
echo 'android-device-keys-emulator PASS'
