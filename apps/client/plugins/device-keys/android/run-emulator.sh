#!/usr/bin/env bash
# Instrument the standalone Android library on a disposable API 36 x86_64 AVD.
# Run only from nix develop .#androidEmulator. Never connects to a physical device.
set -euo pipefail
source "$(dirname "$0")/../../../tests/webdriver/lib.sh"
module="$basehero_dir/apps/client/plugins/device-keys/android"
serial=emulator-5554
instrument=app.basehero.devicekeys.test/androidx.test.runner.AndroidJUnitRunner
: "${ANDROID_HOME:?run from nix develop .#androidEmulator}"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'KVM unavailable' >&2; exit 2; }
[ "$(df -Pk "$basehero_dir" | awk 'NR == 2 {print $4}')" -gt 5000000 ] || { echo 'need 5 GiB free' >&2; exit 2; }
adb start-server >/dev/null
refuse_attached_android
work=$(mktemp -d "${TMPDIR:-/tmp}/bh-devicekeys-emulator.XXXXXX")
export ANDROID_AVD_HOME="$work/avd"
mkdir -p "$ANDROID_AVD_HOME"
avd_name="bh_devicekeys_${work##*.}"
pid=''
finger_pid=''
avd_on_serial() {
  local name
  name=$(timeout 5 adb -s "$serial" emu avd name 2>/dev/null | tr -d '\r' | { IFS= read -r line || :; printf '%s' "$line"; }) || return 1
  [ "$name" = "$avd_name" ] && return 0
  [ -z "$name" ] && return 1
  return 2 # A different emulator occupies the serial.
}
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
refuse_attached_android
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics \
  -gpu swiftshader_indirect -memory 2048 -cores 4 -port 5554 -no-snapshot >"$work/emulator.log" 2>&1 &
pid=$!
ready=0
for _ in $(seq 1 240); do
  kill -0 "$pid" 2>/dev/null || { echo 'emulator died before boot' >&2; exit 1; }
  if avd_on_serial; then
    if [ "$(timeout 5 adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
      ready=1
      break
    fi
  else
    [ "$?" != 2 ] || { echo 'foreign emulator occupies serial' >&2; exit 1; }
  fi
  sleep 1
done
[ "$ready" = 1 ] || { echo 'emulator boot timed out or serial belongs to another AVD' >&2; exit 1; }
# Guard each subsequent command, including the UI and test helpers, against a
# different emulator taking the serial after readiness.
adb() {
  kill -0 "$pid" 2>/dev/null && avd_on_serial || { echo 'lost disposable emulator' >&2; return 1; }
  command adb "$@"
}
[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || { echo 'not an emulator' >&2; exit 4; }
adb -s "$serial" shell setprop debug.checkjni 1
[ "$(adb -s "$serial" shell getprop debug.checkjni | tr -d '\r')" = 1 ] || { echo 'CheckJNI was not enabled' >&2; exit 1; }
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
adb -s "$serial" shell wm dismiss-keyguard
adb -s "$serial" shell input keyevent 82
adb -s "$serial" shell locksettings set-pin 1234
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP
adb -s "$serial" shell wm dismiss-keyguard
adb -s "$serial" shell input text 1234
adb -s "$serial" shell input keyevent 66
adb -s "$serial" shell input keyevent 82

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
    adb -s "$serial" shell input tap 910 2230
    sleep 1
    text=$(screen)
    [[ "$text" == *'I AGREE'* ]] || { echo "unexpected agreement screen: $text" >&2; exit 1; }
    adb -s "$serial" shell input tap 910 2230
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
  adb -s "$serial" shell input tap 900 2230
}
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
