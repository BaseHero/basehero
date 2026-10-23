#!/usr/bin/env bash
# Assert an Android APK carries no test-only code: no WebDriver plugin, no
# emulator fixture and no synthetic attestation, in any packaged entry (dex,
# native libraries, manifest, resources and assets). A bare built library (for
# example `libbh_client_lib.so`) is scanned as one entry, so `check.sh android`
# uses these same markers on its arm64 build.
#
#   bash scripts/android-release-check.sh <apk|library>
#   bash scripts/android-release-check.sh <apk|library> --expect-fixture
#
# `--expect-fixture` is the positive control on an emulator fixture build: every
# fixture marker must be found there, so a passing release check is not vacuous.
set -euo pipefail
cd "$(dirname "$0")/.."
apk=${1:?usage: bash scripts/android-release-check.sh <apk|library> [--expect-fixture]}
mode=${2:-release}
case "$mode" in
  release) node scripts/check-webdriver-markers.mjs "$apk" --expect absent ;;
  --expect-fixture) ;;
  *) echo "usage: bash scripts/android-release-check.sh <apk|library> [--expect-fixture]" >&2; exit 2 ;;
esac
python3 - "$apk" "$mode" <<'PY'
import os
import sys
import zipfile

apk, mode = sys.argv[1:]
# Literal strings the emulator fixture compiles into the native library.
FIXTURE = [b'EMULATOR FIXTURE', b'Create emulator test account',
           b'Create test account and show kit', 'TEST ONLY — Password: '.encode()]
SYNTHETIC = [b'synthetic-attestation', b'synthetic_attestation', b'SYNTHETIC ATTESTATION']
def entries():
    if zipfile.is_zipfile(apk):
        with zipfile.ZipFile(apk) as archive:
            for name in archive.namelist():
                yield name, archive.read(name)
    else:
        with open(apk, 'rb') as library:
            yield os.path.basename(apk), library.read()
found = set()
for name, data in entries():
    found.update((marker, name) for marker in FIXTURE + SYNTHETIC if marker in data)
markers = {marker for marker, _ in found}
failures = []
if mode == 'release':
    failures = sorted(f'{marker.decode()} in {name}' for marker, name in found)
else:
    failures = [f'fixture marker missing: {m.decode()}' for m in FIXTURE if m not in markers]
    failures += sorted(f'{m.decode()} in {n}' for m, n in found if m in SYNTHETIC)
if failures:
    for failure in failures:
        print(f'android release check FAIL ({mode}): {failure}', file=sys.stderr)
    sys.exit(1)
print(f'ok: {apk} has no fixture or synthetic markers' if mode == 'release'
      else f'ok: {apk} carries the labelled emulator fixture and no synthetic markers')
PY
