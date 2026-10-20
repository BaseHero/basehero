#!/usr/bin/env bash
# Own disposable API36 Fold AVD for a real camera QR scan (or permission refusal).
# nix develop .#androidEmulator --command env CARGO_TARGET_DIR=/tmp/basehero-camera-target \
#   bash apps/client/tests/android/run-scan.sh refusal|scan
# SCAN_IMAGE and SCAN_CANDIDATE are required in scan mode: both originate from a
# live showing host. The emulator's back camera renders SCAN_IMAGE; the app's
# own decoder reads its frames. No JS scan callback is injected.
set -euo pipefail
source "$(dirname "$0")/../webdriver/lib.sh"
source "$(dirname "$0")/emulator.sh"
mode=${1:-}
[[ $mode == refusal || $mode == scan || $mode == sync ]] || { echo 'usage: run-scan.sh refusal|scan|sync' >&2; exit 2; }
: "${ANDROID_HOME:?use .#androidEmulator}"
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM unavailable' >&2; exit 2; }
if [[ $mode != refusal ]]; then
  [[ -f ${SCAN_IMAGE:-} && -n ${SCAN_CANDIDATE:-} ]] || { echo 'need genuine SCAN_IMAGE and SCAN_CANDIDATE' >&2; exit 2; }
fi
command adb start-server >/dev/null
work=$(mktemp -d /tmp/bh-camera-avd.XXXXXX)
export ANDROID_AVD_HOME=$work/avd
mkdir -p "$ANDROID_AVD_HOME"
avd_name=bh_camera_${work##*.}
port=$(free_emulator_port)
serial=emulator-$port
pid=''
born=''
shots=${SCAN_SCREENSHOTS:-"${TMPDIR:-/tmp}/basehero-camera-$mode-screens"}
mkdir -p "$shots"
start_time() {
  local line rest
  IFS= read -r line < "/proc/$1/stat" || return 1
  rest="${line##*) }"
  local -a fields
  read -ra fields <<< "$rest"
  [[ ${fields[0]} != Z ]] || return 1
  printf '%s' "${fields[19]}"
}
own_pid() { [[ -n $pid && -n $born && $(start_time "$pid" 2>/dev/null) == "$born" ]]; }
cleanup() {
  if own_pid && avd_on_serial; then
    timeout 10 adb -s "$serial" logcat -b all -d -v epoch > "$shots/logcat.log" 2>&1 || true
    cp "$ANDROID_AVD_HOME/$avd_name.avd/config.ini" "$shots/avd-config.ini" 2>/dev/null || true
    timeout 5 adb -s "$serial" forward --remove "tcp:$webdriver_port" >/dev/null 2>&1 || true
    timeout 5 adb -s "$serial" emu kill >/dev/null 2>&1 || true
  fi
  if own_pid; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  cp "$work/emulator.log" "$shots/emulator.log" 2>/dev/null || true
  rm -rf "$work"
  echo "stopped only own emulator $pid $serial; screenshots $shots"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

unsigned=${SCAN_UNSIGNED_APK:-"$basehero_dir/apps/client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"}
[[ -f $unsigned ]] || { echo "missing unsigned APK $unsigned" >&2; exit 2; }
keytool -genkeypair -keystore "$work/run.keystore" -storepass android -keypass android -alias bhcamera \
  -keyalg RSA -keysize 2048 -validity 1 -dname 'CN=BaseHero camera emulator test' >/dev/null 2>&1
"$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$work/aligned.apk"
"$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/run.keystore" --ks-pass pass:android \
  --key-pass pass:android --out "$work/camera.apk" "$work/aligned.apk"
python3 "$basehero_dir/scripts/webdriver_android_manifest.py" "$work/camera.apk" "$ANDROID_HOME/build-tools/35.0.0/aapt"
python3 "$basehero_dir/scripts/android_no_models.py" "$work/camera.apk" --expect-scanner
if [[ $mode == sync ]]; then
  : "${SYNC_UPDATE_UNSIGNED_APK:?matching newer test APK}" "${SYNC_RUN:?private evidence}"
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$SYNC_UPDATE_UNSIGNED_APK" "$work/update-aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/run.keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$work/update.apk" "$work/update-aligned.apk"
  python3 "$basehero_dir/scripts/webdriver_android_manifest.py" "$work/update.apk" "$ANDROID_HOME/build-tools/35.0.0/aapt"
  python3 "$basehero_dir/scripts/android_no_models.py" "$work/update.apk" --expect-scanner
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --print-certs "$work/camera.apk" > "$SYNC_RUN/v1-signature.txt"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --print-certs "$work/update.apk" > "$SYNC_RUN/v2-signature.txt"
  cmp "$SYNC_RUN/v1-signature.txt" "$SYNC_RUN/v2-signature.txt"
  sha256sum "$work/camera.apk" "$work/update.apk" > "$SYNC_RUN/signed-apks.sha256"
  export SYNC_UPDATE_APK="$work/update.apk"
fi

echo "own AVD $avd_name on $serial"
avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
echo no | "$avdmanager" create avd -n "$avd_name" -k 'system-images;android-36;google_apis;x86_64' -d pixel_fold --force >/dev/null
emulator_port_free "$port" || { echo 'emulator port occupied' >&2; exit 1; }
refuse_occupied_port
options=(-avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics -gpu swiftshader_indirect -memory 2048 -cores 4 -port "$port" -no-snapshot)
if [[ $mode != refusal ]]; then options+=(-camera-back "imagefile:$SCAN_IMAGE"); else options+=(-camera-back emulated); fi
"$ANDROID_HOME/emulator/emulator" "${options[@]}" > "$work/emulator.log" 2>&1 &
pid=$!
born=$(start_time "$pid")
echo "emulator pid=$pid birth=$born serial=$serial avd=$avd_name" | tee "$shots/identity.txt"
wait_for_boot
if [[ $mode == sync ]]; then
  # API36 google_apis is userdebug. Root only this owned AVD's adbd to read
  # cold SQLite evidence from the unchanged non-debuggable release APK.
  # App/Keystore permissions and native authentication stay unchanged.
  own_pid && avd_on_serial || { echo 'lost own emulator before root' >&2; exit 1; }
  command adb -s "$serial" root
  root_ready=0
  for _ in $(seq 1 30); do
    # adbd may be briefly offline. Process birth and console identity must
    # still match before any UID/sandbox probe; a foreign AVD is not offline.
    own_pid || { echo 'lost own emulator after root' >&2; exit 1; }
    if avd_on_serial; then
      own_pid || { echo 'lost own emulator before UID probe' >&2; exit 1; }
      if [[ $(timeout 5 adb -s "$serial" shell id -u 2>/dev/null | tr -d '\r') == 0 ]]; then
        root_ready=1
        break
      fi
    else
      [[ $? != 2 ]] || { echo 'foreign emulator after root' >&2; exit 1; }
    fi
    sleep 1
  done
  [[ $root_ready == 1 ]] || { echo 'owned adbd root readiness timed out' >&2; exit 1; }
fi
adb() {
  own_pid && avd_on_serial || { echo 'lost own emulator identity' >&2; return 1; }
  command adb "$@"
}
[[ $(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r') == 1 ]] || { echo 'not an emulator' >&2; exit 4; }
adb -s "$serial" shell svc power stayon true >/dev/null
if [[ $mode != refusal ]]; then
  # Joining creates this device's biometric-bound keys: the disposable AVD
  # needs a screen lock and an enrolled emulator finger, as on a real phone.
  set_pin
  enroll 1
  # Enrollment leaves a Settings task that can reopen its own PIN screen.
  adb -s "$serial" shell am force-stop com.android.settings
  if [[ $mode == sync ]]; then
    # A fresh Fold's Calendar onboarding can have a pending GMS sign-in task.
    # It surfaced over a later offline reopen. Finish only these setup tasks
    # on this identity-checked disposable AVD, before any app evidence exists.
    adb -s "$serial" shell am force-stop com.google.android.calendar
    adb -s "$serial" shell am force-stop com.google.android.gms
  fi
fi
adb -s "$serial" install -r "$work/camera.apk" >/dev/null
adb -s "$serial" forward "tcp:$webdriver_port" "tcp:$webdriver_port" >/dev/null
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP >/dev/null
adb -s "$serial" shell wm dismiss-keyguard >/dev/null
adb -s "$serial" shell input keyevent 82 >/dev/null
adb -s "$serial" logcat -c
adb -s "$serial" shell am start -n "$webdriver_activity" >/dev/null
wait_for_status ''
node "$webdriver_dir/wait-for-layout.mjs"
require_loopback
export ANDROID_SERIAL=$serial SCAN_EMU_PID=$pid SCAN_EMU_BIRTH=$born SCAN_AVD_NAME=$avd_name
scan_mode=$mode
[[ $mode != sync ]] || scan_mode=scan
node "$basehero_dir/apps/client/tests/android/scan.spec.mjs" \
  "$scan_mode" "$shots" "${SCAN_CANDIDATE:-}"
if [[ $mode == sync ]]; then
  node "$basehero_dir/apps/client/tests/android/sync-acceptance.spec.mjs"
fi
echo "android-camera-$mode PASS (own emulator evidence)"
