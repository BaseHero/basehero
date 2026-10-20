#!/usr/bin/env bash
# Real signed v1 -> v2 install -r on a disposable emulator; no real phone.
set -euo pipefail
source "$(dirname "$0")/../apps/client/tests/webdriver/lib.sh"
source "$(dirname "$0")/../apps/client/tests/android/emulator.sh"
: "${ANDROID_HOME:?run in nix develop .#androidEmulator}"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo 'KVM unavailable' >&2; exit 2; }
command adb start-server >/dev/null
work=$(mktemp -d "${TMPDIR:-/tmp}/bh-android-update.XXXXXX")
export ANDROID_AVD_HOME=$work/avd
mkdir -p "$ANDROID_AVD_HOME"
mode=${ANDROID_EMULATOR_TEST:-update}
[[ "$mode" == update || "$mode" == editor || "$mode" == continuity ]] || { echo "unknown emulator test: $mode" >&2; exit 2; }
avd_name=${AVD_NAME:-bh_${mode}_${work##*.}}
# Private emulator evidence outlives $work, which cleanup removes.
evidence="${CONTINUITY_SCREENSHOTS:-${TMPDIR:-/tmp}/bh-continuity-evidence}/$avd_name"
port=$(free_emulator_port)
serial=emulator-$port
pid=''
default_ime=''
instrument_host_pid=''
cleanup() {
  if [ -n "$instrument_host_pid" ]; then
    kill "$instrument_host_pid" 2>/dev/null || true
    wait "$instrument_host_pid" 2>/dev/null || true
  fi
  if [ -n "$pid" ]; then
    if kill -0 "$pid" 2>/dev/null && avd_on_serial; then
      if [ -n "$default_ime" ]; then timeout 5 adb -s "$serial" shell ime set "$default_ime" >/dev/null 2>&1 || true; fi
      timeout 5 adb -s "$serial" forward --remove "tcp:$webdriver_port" >/dev/null 2>&1 || true
      timeout 5 adb -s "$serial" emu kill >/dev/null 2>&1 || true
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    echo "stopped emulator $pid"
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

keytool -genkeypair -keystore "$work/update.keystore" -storepass android -keypass android \
  -alias bhupdate -keyalg RSA -keysize 2048 -validity 1 -dname 'CN=BaseHero disposable emulator update'
unsigned="$basehero_dir/apps/client/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"
aapt="$ANDROID_HOME/build-tools/35.0.0/aapt"
sign() {
  local version=$1 expected=$2
  (cd "$basehero_dir/apps/client" && cargo tauri android build --target x86_64 --apk --ci \
    --features webdriver,emulator-fixture --config "{\"version\":\"$version\"}")
  bash "$basehero_dir/scripts/android-release-check.sh" "$unsigned" --expect-fixture
  local code
  code=$($aapt dump badging "$unsigned" | grep '^package:' | grep -o "versionCode='[0-9]*'" | cut -d "'" -f 2)
  [ "$code" = "$expected" ] || { echo "wrong versionCode: $code, wanted $expected" >&2; exit 1; }
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$work/aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/update.keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$work/v$expected.apk" "$work/aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify "$work/v$expected.apk"
  python3 "$basehero_dir/scripts/webdriver_android_manifest.py" "$work/v$expected.apk" "$aapt"
}
build_continuity_instrumentation() {
  local android="$basehero_dir/apps/client/src-tauri/gen/android" project="$basehero_dir/apps/client/tests/android/instrument" test_apk
  "$android/gradlew" -p "$project" assembleRelease --no-daemon
  test_apk="$project/build/outputs/apk/release/basehero-continuity-instrument-release-unsigned.apk"
  [ -f "$test_apk" ] || { echo 'missing separate instrumentation APK' >&2; return 1; }
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$test_apk" "$work/test-aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/update.keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$work/test.apk" "$work/test-aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify "$work/test.apk"
}
build_continuity_ime() {
  local project="$basehero_dir/apps/client/tests/android/ime" unsigned_ime
  "$basehero_dir/apps/client/src-tauri/gen/android/gradlew" -p "$project" assembleRelease --no-daemon
  unsigned_ime="$project/build/outputs/apk/release/basehero-continuity-ime-release-unsigned.apk"
  [ -f "$unsigned_ime" ] || { echo 'missing disposable IME APK' >&2; return 1; }
  "$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned_ime" "$work/ime-aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$work/update.keystore" --ks-pass pass:android \
    --key-pass pass:android --out "$work/ime.apk" "$work/ime-aligned.apk"
  "$ANDROID_HOME/build-tools/35.0.0/apksigner" verify "$work/ime.apk"
}
ensure_avd() {
  local profile=${1:-pixel_6} avdmanager
  avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
  [ -x "$avdmanager" ] || { echo 'avdmanager not found' >&2; exit 2; }
  echo no | "$avdmanager" create avd -n "$avd_name" -k 'system-images;android-36;google_apis;x86_64' -d "$profile" --force >/dev/null
  echo "AVD profile: $profile (API 36 google_apis x86_64; emulator evidence)"
}
# Tauri maps x.y.z to x*1,000,000 + y*1,000 + z.
sign 0.1.0 1000

echo "--- creating disposable AVD $avd_name on $serial"
if [ "$mode" = update ]; then ensure_avd pixel_6; else ensure_avd pixel_fold; fi
if [ "$mode" = continuity ]; then build_continuity_ime; build_continuity_instrumentation; fi
emulator_port_free "$port" || { echo 'emulator port occupied' >&2; exit 1; }
refuse_occupied_port
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio -no-boot-anim -no-metrics \
  -gpu swiftshader_indirect -memory 2048 -cores 4 -port "$port" -no-snapshot >"$work/emulator.log" 2>&1 &
pid=$!
wait_for_boot
adb() {
  kill -0 "$pid" 2>/dev/null && avd_on_serial || { echo 'lost disposable emulator' >&2; return 1; }
  command adb "$@"
}
force_stop_live_app() {
  local before after old
  before=$(adb -s "$serial" shell 'pidof app.basehero.client || true' | tr -d '\r')
  [ -n "$before" ] || { echo 'WebDriver teardown ended the app: no live app PID before force-stop; refusing to claim continuity' >&2; return 1; }
  [[ "$before" =~ ^[0-9]+(\ [0-9]+)*$ ]] || { echo "invalid app PID before force-stop: $before" >&2; return 1; }
  echo "force-stopping live app PID(s): $before (emulator $serial)"
  adb -s "$serial" shell am force-stop app.basehero.client
  after=$(adb -s "$serial" shell 'pidof app.basehero.client || true' | tr -d '\r')
  [ -z "$after" ] || { echo "app still running after force-stop: $after" >&2; return 1; }
  for old in $before; do
    if adb -s "$serial" shell "test -e /proc/$old"; then
      echo "pre-stop app PID $old survived force-stop" >&2; return 1
    fi
  done
  echo "force-stop verified: app PID(s) $before gone (emulator evidence)"
}
reopen_diagnostics() {
  echo "app PID: $(adb -s "$serial" shell 'pidof app.basehero.client || true' | tr -d '\r')" >&2
  adb -s "$serial" shell dumpsys window | grep -m1 mCurrentFocus >&2 || true
  adb -s "$serial" shell logcat -d | grep -E 'Force stopping|finished inst|Start proc|START u0' >&2 || true
  cat "$work/instrument.log" >&2 || true
}
# Settings' confirm-device-credential Activity is not a showing keyguard.
# Type into it only when Android reports the app as its launch package.
# A bouncer instead requires a showing keyguard. Recheck after any keyevent.
credential_focus() {
  local state focus keyguard activities launcher='unavailable'
  state=$(adb -s "$serial" shell dumpsys window) || return 1
  focus=$(printf '%s\n' "$state" | grep -m1 mCurrentFocus || true)
  keyguard=$(printf '%s\n' "$state" | grep -E 'mShowingLockscreen=|mKeyguardShowing=|isKeyguardShowing=' || true)
  if [[ "$focus" == *' com.android.settings/'*ConfirmLock*'$InternalActivity'* ]]; then
    if activities=$(adb -s "$serial" shell dumpsys activity activities); then
      launcher=$(printf '%s\n' "$activities" | tr -d '\r' | awk '
        /ActivityRecord\{[^}]*com\.android\.settings\/[^}]*ConfirmLock[^}]*InternalActivity/ { confirm=1 }
        confirm && /launchedFromPackage=/ {
          sub(/^.*launchedFromPackage=/, ""); sub(/[[:space:]].*$/, ""); print; exit
        }
        confirm && /ActivityRecord\{/ && !/ConfirmLock/ { exit }
      ')
      [ -n "$launcher" ] || launcher=unavailable
    else
      launcher='query failed'
    fi
    if [ "$launcher" = app.basehero.client ]; then
      echo "PIN destination verified: $focus; keyguard: ${keyguard:-unavailable}; launcher: $launcher"
      return 0
    fi
  elif [[ "$focus" == *Keyguard*Bouncer* || "$focus" == *Bouncer*Keyguard* ]] &&
      [[ "$state" == *mShowingLockscreen=true* || "$state" == *mKeyguardShowing=true* || "$state" == *isKeyguardShowing=true* ]]; then
    echo "PIN destination verified: $focus; keyguard: ${keyguard:-unavailable}; launcher: not applicable"
    return 0
  fi
  echo "PIN destination not verified: $focus; keyguard: ${keyguard:-unavailable}; launcher: $launcher" >&2
  return 1
}
# Once its target dies, Android finishes the instrumentation and then
# force-stops the target package ("finished inst"). A launch that races that
# is killed, so wait for the instrumentation to end before the one reopen.
reopen_after_instrumentation() {
  local seen='' now focus i
  for _ in $(seq 1 20); do
    [ -n "$instrument_host_pid" ] && kill -0 "$instrument_host_pid" 2>/dev/null || break
    sleep 0.5
  done
  if [ -n "$instrument_host_pid" ] && kill -0 "$instrument_host_pid" 2>/dev/null; then
    echo 'instrumentation still attached 10 s after force-stop' >&2; reopen_diagnostics; return 1
  fi
  instrument_host_pid=''
  adb -s "$serial" shell input keyevent KEYCODE_WAKEUP >/dev/null
  adb -s "$serial" shell wm dismiss-keyguard >/dev/null
  adb -s "$serial" shell am start -W -n "$webdriver_activity"
  for i in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$webdriver_port/status" >/dev/null 2>&1; then
      echo "reopened app PID: $(adb -s "$serial" shell 'pidof app.basehero.client || true' | tr -d '\r')"
      return 0
    fi
    now=$(adb -s "$serial" shell 'pidof app.basehero.client || true' | tr -d '\r')
    [ -n "$now" ] && seen=$now
    if [ -n "$seen" ] && [ -z "$now" ]; then
      echo "reopened app PID $seen exited before /status" >&2; reopen_diagnostics; return 1
    fi
    # A lock or credential screen can sit over the launch; enter the
    # disposable PIN, as a person would, without launching again.
    if [ "$i" = 10 ]; then
      focus=$(adb -s "$serial" shell dumpsys window | grep -m1 mCurrentFocus | tr -d '\r')
      if [[ "$focus" == *NotificationShade* ]]; then
        # The shade may conceal the bouncer. Opening it changes focus, so
        # validate the actual destination again before sending any PIN bytes.
        adb -s "$serial" shell input keyevent 82
        sleep 0.2
        credential_focus || { reopen_diagnostics; return 1; }
      elif [[ "$focus" == *ConfirmLock* || "$focus" == *Keyguard*Bouncer* || "$focus" == *Bouncer*Keyguard* ]]; then
        credential_focus || { reopen_diagnostics; return 1; }
      fi
      if [[ "$focus" == *NotificationShade* || "$focus" == *ConfirmLock* || "$focus" == *Keyguard*Bouncer* || "$focus" == *Bouncer*Keyguard* ]]; then
        echo "reopen: verified credential focus after $focus; entering disposable PIN"
        adb -s "$serial" shell input text 1234
        adb -s "$serial" shell input keyevent 66
      else
        echo "reopen: no verified credential focus: $focus" >&2
        reopen_diagnostics; return 1
      fi
    fi
    sleep 0.5
  done
  echo 'no /status 60 s after reopening' >&2; reopen_diagnostics; return 1
}
[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || exit 4
adb -s "$serial" shell svc power stayon true
set_pin
enroll 1
# Enrollment leaves a Settings task which can later re-open its own PIN
# confirmation over our app. Finish that task on this verified disposable AVD.
adb -s "$serial" shell am force-stop com.android.settings
adb -s "$serial" install -r "$work/v1000.apk"
if [ "$mode" = continuity ]; then
  default_ime=$(adb -s "$serial" shell settings get secure default_input_method | tr -d '\r')
  [[ "$default_ime" == */* ]] || { echo "invalid default IME: $default_ime" >&2; exit 1; }
  adb -s "$serial" install -r "$work/ime.apk"
  adb -s "$serial" install -r "$work/test.apk"
  # Attach before any WebDriver before-state exists; injecting later would
  # restart the process whose Activity we purport to recreate.
  adb -s "$serial" logcat -c
  adb -s "$serial" shell am instrument -w -r \
    app.basehero.continuityinstrument/.ContinuityInstrumentation >"$work/instrument.log" 2>&1 &
  instrument_host_pid=$!
  instrument_ready=0
  for _ in $(seq 1 35); do
    if adb -s "$serial" shell logcat -d -s BhContinuityActivity:I '*:S' | grep -q 'ready pid='; then instrument_ready=1; break; fi
    kill -0 "$instrument_host_pid" 2>/dev/null || { echo 'instrumentation terminated before readiness' >&2; break; }
    sleep 1
  done
  if [ "$instrument_ready" != 1 ]; then
    echo 'instrumentation failed to start before WebDriver state:' >&2
    cat "$work/instrument.log" >&2
    mkdir -p "$evidence"
    adb -s "$serial" shell logcat -d >"$evidence/instrument-full.log" || true
    adb -s "$serial" shell dumpsys activity instrumentation >"$evidence/instrument-state.log" || true
    echo "instrumentation logs: $evidence/instrument-{full,state}.log" >&2
    exit 1
  fi
fi
adb -s "$serial" forward "tcp:$webdriver_port" "tcp:$webdriver_port" >/dev/null
adb -s "$serial" shell input keyevent KEYCODE_WAKEUP >/dev/null
adb -s "$serial" shell wm dismiss-keyguard >/dev/null
if [ "$mode" != continuity ]; then adb -s "$serial" logcat -c; fi
adb -s "$serial" shell am start -n "$webdriver_activity" >/dev/null
wait_for_status ''
require_loopback
if [ "$mode" = continuity ]; then
  export CONTINUITY_SCREENSHOTS="$evidence"
  echo "continuity screenshots (private emulator evidence): $CONTINUITY_SCREENSHOTS"
  ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/continuity.spec.mjs" live "$work/state.json"
  force_stop_live_app
  reopen_after_instrumentation
  ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/continuity.spec.mjs" reopen "$work/state.json"
  echo 'android-continuity-emulator PASS (emulator evidence, real device transitions)'
  exit 0
fi
if [ "$mode" = editor ]; then
  ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/editor.spec.mjs" before "$work/state.json"
  force_stop_live_app
  adb -s "$serial" shell am start -n "$webdriver_activity" >/dev/null
  wait_for_status ''
  ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/editor.spec.mjs" after "$work/state.json"
  echo 'android-editor-emulator PASS (emulator evidence, real force-stop)'
  exit 0
fi
ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/update.spec.mjs" before "$work/state.json"

# Preserve the v1 data and Keystore aliases. Gradle's second build replaces
# only the APK file; the installed v1 process is force-stopped before upgrading.
force_stop_live_app
sign 0.1.1 1001
adb -s "$serial" logcat -c # the after probe must see a fresh v2 Keystore load
adb -s "$serial" install -r "$work/v1001.apk"
installed=$(adb -s "$serial" shell dumpsys package app.basehero.client | grep -m1 'versionCode=' | tr -d '\r')
[[ "$installed" == *'versionCode=1001 '* ]] || { echo "v2 was not installed: $installed" >&2; exit 1; }
adb -s "$serial" shell am start -n "$webdriver_activity" >/dev/null
wait_for_status ''
ANDROID_SERIAL=$serial node "$basehero_dir/apps/client/tests/android/update.spec.mjs" after "$work/state.json"
echo 'android-update-emulator PASS (emulator evidence, real adb install -r)'
