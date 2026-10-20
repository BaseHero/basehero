#!/usr/bin/env bash
# Opt-in data and dependent library tests on an isolated x86_64 Android emulator.
# Run inside nix develop .#androidEmulator; never target an attached phone.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?run inside nix develop .#androidEmulator}"

started=$(date +%s%3N)
work=$(mktemp -d "${TMPDIR:-/tmp}/bh-data-android.XXXXXX")
emu_pid=
port=
serial=
remote=/data/local/tmp/bh-data
packages=()
read -r -a packages <<< "${DATA_ANDROID_PACKAGES:-bh-data}"
[ "${#packages[@]}" -gt 0 ] || { echo 'DATA_ANDROID_PACKAGES needs a package name' >&2; exit 2; }
for package in "${packages[@]}"; do
  [[ "$package" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid package name: $package" >&2; exit 2; }
done
examples=()
example_args=()
if [ -n "${DATA_ANDROID_EXAMPLES:-}" ]; then
  # Whitespace-separated example names, then optional common arguments after --.
  read -r -a words <<< "$DATA_ANDROID_EXAMPLES"
  arguments=0
  for word in "${words[@]}"; do
    if [ "$word" = -- ] && [ "$arguments" = 0 ]; then
      arguments=1
    elif [ "$arguments" = 0 ]; then
      [[ "$word" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid example name: $word" >&2; exit 2; }
      examples+=("$word")
    else
      # These become remote shell arguments. No interpolation or shell syntax.
      [[ "$word" =~ ^[a-zA-Z0-9_./=-]+$ ]] || { echo "invalid example argument: $word" >&2; exit 2; }
      example_args+=("$word")
    fi
  done
  [ "${#examples[@]}" -gt 0 ] || { echo 'DATA_ANDROID_EXAMPLES needs an example name' >&2; exit 2; }
  [ -n "${DATA_ANDROID_OUTPUT_DIR:-}" ] || { echo 'set DATA_ANDROID_OUTPUT_DIR to pull example output' >&2; exit 2; }
  [ ! -e "$DATA_ANDROID_OUTPUT_DIR" ] || { echo 'DATA_ANDROID_OUTPUT_DIR must not exist' >&2; exit 2; }
fi
cleanup() {
  if [ -n "$emu_pid" ]; then
    # Do not send adb emu kill: a replacement device could own this serial.
    kill "$emu_pid" 2>/dev/null || true
    wait "$emu_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

# Pick a port pair not used by another test (including a booting/offline
# emulator). Hold a per-port advisory lock until our emulator is gone.
adb start-server >/dev/null
for candidate in $(seq 5554 2 5584); do
  exec {candidate_fd}>"/tmp/bh-data-android-${UID}-${candidate}.lock"
  if ! flock -n "$candidate_fd"; then
    exec {candidate_fd}>&-
    continue
  fi
  if [ -n "$(ss -H -ltn "( sport = :$candidate or sport = :$((candidate + 1)) )")" ] ||
    adb devices | awk 'NR > 1 { print $1 }' | grep -Fxq "emulator-$candidate"; then
    flock -u "$candidate_fd"
    exec {candidate_fd}>&-
    continue
  fi
  port=$candidate
  break
done
[ -n "$port" ] || { echo 'no free emulator port pair in 5554–5584' >&2; exit 2; }
serial="emulator-$port"
avd_name="bh_data_$port"
export ANDROID_AVD_HOME="$work/avd"
mkdir -p "$ANDROID_AVD_HOME"
echo "selected $serial ($avd_name)"

# Cargo's JSON stream identifies executables from this build invocation; do
# not scan target/ for stale binaries left by other runs.
package_args=()
for package in "${packages[@]}"; do package_args+=(-p "$package"); done
cargo test --locked --target x86_64-linux-android "${package_args[@]}" --tests --no-run \
  --message-format=json > "$work/artifacts.jsonl"
cargo metadata --locked --no-deps --format-version 1 > "$work/metadata.json"
node - "$work/artifacts.jsonl" "$work/metadata.json" "${packages[@]}" > "$work/binaries.tsv" <<'JS'
const fs = require('node:fs');
const [events, metadata, ...packageNames] = process.argv.slice(2);
const packages = JSON.parse(fs.readFileSync(metadata, 'utf8')).packages;
const artifacts = fs.readFileSync(events, 'utf8').trim().split('\n').map(JSON.parse);
for (const packageName of packageNames) {
  const pkg = packages.find(p => p.name === packageName);
  if (!pkg) throw Error(`${packageName} package missing from Cargo metadata`);
  // --tests requests the library unit-test harness and every integration target.
  const expected = pkg.targets.filter(t => t.kind.includes('lib') || t.kind.includes('test'))
    .map(t => t.name).sort();
  if (!expected.some(name => pkg.targets.some(t => t.name === name && t.kind.includes('lib'))) ||
      !expected.some(name => pkg.targets.some(t => t.name === name && t.kind.includes('test')))) {
    throw Error(`${packageName} library or integration targets missing from Cargo metadata`);
  }
  const found = new Map();
  for (const a of artifacts) {
    if (a.reason !== 'compiler-artifact' || a.package_id !== pkg.id || !a.profile?.test ||
        !a.target?.kind?.some(kind => kind === 'lib' || kind === 'test')) continue;
    if (!expected.includes(a.target.name)) throw Error(`unexpected test artifact: ${packageName}/${a.target.name}`);
    if (!a.executable || !fs.existsSync(a.executable)) throw Error(`missing Android test executable: ${packageName}/${a.target.name}`);
    if (found.has(a.target.name)) throw Error(`duplicate test artifact: ${packageName}/${a.target.name}`);
    found.set(a.target.name, a.executable);
  }
  for (const name of expected) {
    if (!found.has(name)) throw Error(`missing Android test artifact: ${packageName}/${name}`);
    console.log(`${packageName}\t${name}\t${found.get(name)}`);
  }
}
JS

# Examples are opt-in; the consumer workload lives in a separate package.
# Both Cargo builds emit JSON from this invocation, never select cached files
# by glob. A caller can override the package for another example crate.
if [ "${#examples[@]}" -gt 0 ]; then
  example_package=${DATA_ANDROID_EXAMPLE_PACKAGE:-bh-data-consumers}
  for name in "${examples[@]}"; do
    cargo build --locked --target x86_64-linux-android -p "$example_package" \
      --example "$name" --message-format=json > "$work/example-$name.jsonl"
    node - "$work/example-$name.jsonl" "$work/metadata.json" "$example_package" "$name" >> "$work/examples.tsv" <<'JS'
const fs = require('node:fs');
const [events, metadata, packageName, name] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(metadata, 'utf8')).packages.find(p => p.name === packageName);
if (!pkg?.targets.some(t => t.name === name && t.kind.includes('example'))) {
  throw Error(`missing example target: ${packageName}/${name}`);
}
const artifacts = fs.readFileSync(events, 'utf8').trim().split('\n').map(JSON.parse)
  .filter(a => a.reason === 'compiler-artifact' && a.package_id === pkg.id &&
    a.target.name === name && a.target.kind.includes('example'));
if (artifacts.length !== 1 || !artifacts[0].executable || !fs.existsSync(artifacts[0].executable)) {
  throw Error(`missing Android example executable: ${packageName}/${name}`);
}
console.log(`${name}\t${artifacts[0].executable}`);
JS
  done
fi

avdmanager=$(find "$ANDROID_HOME/cmdline-tools" -type f -name avdmanager | sort | tail -1)
[ -x "$avdmanager" ] || { echo 'avdmanager not found' >&2; exit 2; }
if ! echo no | "$avdmanager" create avd -n "$avd_name" \
  -k 'system-images;android-36;google_apis;x86_64' -d pixel_6 --force > "$work/avdmanager.log" 2>&1; then
  cat "$work/avdmanager.log" >&2
  exit 1
fi
boot_start=$(date +%s%3N)
"$ANDROID_HOME/emulator/emulator" -avd "$avd_name" -no-window -no-audio \
  -no-boot-anim -no-metrics -gpu swiftshader_indirect -memory 2048 -cores 4 \
  -port "$port" -no-snapshot > "$work/emulator.log" 2>&1 &
emu_pid=$!
echo "started $serial pid $emu_pid"
booted=0
for _ in $(seq 1 240); do
  kill -0 "$emu_pid" 2>/dev/null || { echo 'emulator exited before boot' >&2; exit 1; }
  identity=$(adb -s "$serial" emu avd name 2>/dev/null | tr -d '\r' || true)
  case "$identity" in
    "$avd_name"$'\n'OK|"$avd_name"$'\n'OK$'\n')
      if [ "$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
        booted=1
        break
      fi ;;
    ''|*not\ found*|*offline*) ;;
    *) echo "refusing another AVD at $serial: $identity" >&2; exit 4 ;;
  esac
  sleep 1
done
[ "$booted" = 1 ] || { echo 'emulator boot timed out' >&2; exit 1; }
echo "boot time: $(( $(date +%s%3N) - boot_start )) ms"
qemu=$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r')
boot_qemu=$(adb -s "$serial" shell getprop ro.boot.qemu | tr -d '\r')
identity=$(adb -s "$serial" emu avd name | tr -d '\r')
if [ "$qemu" != 1 ] && [ "$boot_qemu" != 1 ]; then
  echo "refusing non-emulator $serial (ro.kernel.qemu=$qemu ro.boot.qemu=$boot_qemu)" >&2
  exit 4
fi
case "$identity" in
  "$avd_name"$'\n'OK|"$avd_name"$'\n'OK$'\n') ;;
  *) echo "refusing another AVD at $serial: $identity" >&2; exit 4 ;;
esac

adb -s "$serial" shell "mkdir -p $remote/bin $remote/tests"
adb -s "$serial" push libs/data/tests/conformance "$remote/tests/conformance" >/dev/null
adb -s "$serial" push libs/data/tests/fixtures "$remote/tests/fixtures" >/dev/null
failures=0
executed=0
# Keep the artifact list on fd 3: adb shell may consume standard input.
while IFS=$'\t' read -r -u 3 package name binary; do
  executed=$((executed + 1))
  adb -s "$serial" push "$binary" "$remote/bin/$package-$name" </dev/null >/dev/null
  adb -s "$serial" shell "chmod 700 $remote/bin/$package-$name" </dev/null
  echo "--- $package/$name"
  if adb -s "$serial" shell -n "cd $remote && BH_DATA_TEST_MANIFEST_DIR=$remote ./bin/$package-$name" > "$work/$package-$name.log" 2>&1; then
    cat "$work/$package-$name.log"
  else
    cat "$work/$package-$name.log" >&2
    failures=$((failures + 1))
  fi
done 3< "$work/binaries.tsv"
expected=$(wc -l < "$work/binaries.tsv")
if [ "$failures" -eq 0 ] && [ "$executed" -eq "$expected" ] && [ "${#examples[@]}" -gt 0 ]; then
  # Each named example receives the same optional arguments. --out should
  # point to $remote/out; this clean AVD has no output from prior runs.
  adb -s "$serial" shell "mkdir -p $remote/out"
  command_args=
  for arg in "${example_args[@]}"; do command_args+=" $arg"; done
  while IFS=$'\t' read -r -u 3 name binary; do
    adb -s "$serial" push "$binary" "$remote/bin/$name" </dev/null >/dev/null
    adb -s "$serial" shell "chmod 700 $remote/bin/$name" </dev/null
    echo "--- example $name"
    if ! adb -s "$serial" shell -n "cd $remote && ./bin/$name$command_args"; then
      failures=$((failures + 1))
    fi
  done 3< "$work/examples.tsv"
  if [ "$failures" -eq 0 ]; then
    adb -s "$serial" pull "$remote/out" "$DATA_ANDROID_OUTPUT_DIR" </dev/null >/dev/null
    echo "pulled example output to $DATA_ANDROID_OUTPUT_DIR"
  fi
fi
echo "total time: $(( $(date +%s%3N) - started )) ms; executed test binaries: $executed/$expected; failed binaries: $failures"
[ "$failures" -eq 0 ] && [ "$executed" -eq "$expected" ]
