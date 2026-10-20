#!/usr/bin/env bash
# Run inside `nix develop .#android`. This builds an unsigned release shell only.
set -euo pipefail
cd "$(dirname "$0")/.."
project=apps/client/src-tauri/gen/android
apk="$project/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk"

case "${1:-}" in
  build)
    case "${2:-}" in
      --sync-endpoint) test "$#" = 3; endpoint_args=(--sync-endpoint "$(realpath "$3")") ;;
      --local-only) test "$#" = 2; endpoint_args=(--local-only) ;;
      *) echo 'build requires --sync-endpoint FILE or explicit --local-only' >&2; exit 2 ;;
    esac
    mkdir -p "${CARGO_TARGET_DIR:-target}"
    endpoint_output=$(mktemp -d "${CARGO_TARGET_DIR:-target}/android-release-endpoint.XXXXXXXX")
    python3 scripts/sync_endpoint.py "${endpoint_args[@]}" --output "$endpoint_output" \
      --artifact "$apk" -- bash -c 'cd apps/client && cargo tauri android build --target aarch64 --apk --ci'
    printf 'Endpoint provenance: %s/sync-endpoint-provenance.json\n' "$endpoint_output"
    ;;
  check) ;;
  *) echo "usage: bash scripts/android-unsigned.sh build [--sync-endpoint FILE|--local-only] | check" >&2; exit 2 ;;
esac

python3 -m unittest discover -s scripts -p test_android_storage_boundary.py
python3 -m unittest discover -s scripts -p test_android_no_models.py

: "${ANDROID_HOME:?run in nix develop .#android}"
test -f "$apk"
merged="$project/app/build/intermediates/merged_manifest/universalRelease/processUniversalReleaseMainManifest/AndroidManifest.xml"
test -f "$merged"
python3 scripts/android_storage_boundary.py "$apk" "$ANDROID_HOME/build-tools/35.0.0/aapt" "$merged"
python3 - "$apk" "$ANDROID_HOME/build-tools/35.0.0/aapt" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

apk, aapt = sys.argv[1:]
config = json.loads(Path('apps/client/src-tauri/tauri.conf.json').read_text())
version = config['version']
major, minor, patch = map(int, version.split('.'))
# Tauri's Android versionCode for a stable x.y.z release.
expected_code = major * 1_000_000 + minor * 1_000 + patch
badging = subprocess.check_output([aapt, 'dump', 'badging', apk], text=True)
package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
abis = re.search(r'^native-code: (.*)$', badging, re.M)
assert package, 'APK has no readable package/version'
assert package.groups() == (config['identifier'], str(expected_code), version), package.groups()
assert abis and abis.group(1) == "'arm64-v8a'", abis.group(1) if abis else 'missing native code'
print(package.group(0))
print(abis.group(0))
PY

# An unsigned release is not installable. A debug-signed or release-signed APK
# must never be mislabeled as the safe intermediate produced by this script.
verify_output=$("$ANDROID_HOME/build-tools/35.0.0/apksigner" verify --verbose "$apk" 2>&1) && {
  echo 'refusing signed APK' >&2; exit 1;
}
if [[ "$verify_output" != *'DOES NOT VERIFY'* || "$verify_output" != *'Missing META-INF/MANIFEST.MF'* ]]; then
  printf 'unexpected APK signature check failure:\n%s\n' "$verify_output" >&2
  exit 1
fi
python3 - "$apk" <<'PY'
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1]) as apk:
    signatures = [name for name in apk.namelist() if name.upper().startswith('META-INF/') and name.upper().endswith(('.RSA', '.DSA', '.EC', '.SF'))]
    assert not signatures, signatures
print('unsigned release APK (apksigner: missing signature manifest)')
PY

# Whatever produced this APK, the release artifact must carry no test-only
# code: no WebDriver plugin classes, native-lib markers or manifest entries, no
# emulator fixture and no synthetic attestation. A build that accidentally
# enabled a test feature or leaked the Gradle module fails here.
bash scripts/android-release-check.sh "$apk"
python3 scripts/android_device_keys_packaging.py "$apk"
# No model, model runtime, ML Kit, Play Services, Firebase or data-transport
# component: neither in the packaged APK nor in Gradle's resolved runtime graph.
deps=$(mktemp)
trap 'rm -f "$deps"' EXIT
"$project/gradlew" -p "$project" :app:dependencies --configuration universalReleaseRuntimeClasspath --no-daemon -q > "$deps"
python3 scripts/android_no_models.py "$apk" --gradle-deps "$deps" --expect-scanner
