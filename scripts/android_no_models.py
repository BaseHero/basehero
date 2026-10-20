#!/usr/bin/env python3
"""Refuse an Android package that bundles, or can fetch, an on-device model.

The client's QR scanner is algorithmic. This checks what the build actually
resolved and packaged, not source declarations: model files and model
runtimes, ML Kit, Play Services (including its optional-module loader),
Firebase and Google data-transport components, in every APK entry (dex,
native libraries, assets, resources and the binary manifest), and optionally
in Gradle's resolved runtime dependency graph.

    python3 scripts/android_no_models.py <apk> [--gradle-deps <file>] [--expect-scanner]

`--gradle-deps` takes the output of
`gradlew :app:dependencies --configuration universalReleaseRuntimeClasspath`.
`--expect-scanner` is the positive control: the app's own QR adapter must ship.
"""
import re
import sys
import zipfile
from pathlib import Path

MODEL_SUFFIXES = ('.tflite', '.tfl', '.lite', '.onnx', '.ort', '.ptl', '.pte', '.pb',
                  '.mlmodel', '.task', '.binarypb', '.gguf', '.safetensors')
NAME_MARKERS = ('mlkit', 'barhopper', 'tensorflow', 'tflite', 'onnxruntime', 'mediapipe',
                'firebase', 'datatransport', 'play-services', 'transport-api',
                'transport-backend', 'transport-runtime', 'vision-common')
# Class descriptors (dex), dotted names (manifest, resources, properties) and
# native-library strings, in UTF-8 and the binary manifest's UTF-16.
CONTENT_MARKERS = ('com/google/mlkit', 'com.google.mlkit',
                   'com/google/android/gms', 'com.google.android.gms',
                   'com/google/android/datatransport', 'com.google.android.datatransport',
                   'com/google/firebase', 'com.google.firebase',
                   'org/tensorflow', 'org.tensorflow', 'TfLite', 'tflite',
                   'barhopper', 'mlkit_barcode_models', 'com/google/android/odml')
GRADLE_GROUPS = ('com.google.mlkit', 'com.google.android.gms', 'com.google.android.datatransport',
                 'com.google.firebase', 'org.tensorflow', 'com.google.ai.edge',
                 'com.google.android.odml', 'com.google.mediapipe',
                 'com.microsoft.onnxruntime', 'org.pytorch')
SCANNER = b'Lapp/basehero/qrscan/QrScanPlugin;'


def apk_failures(apk):
    failures, scanner = [], False
    patterns = [(m, m.encode()) for m in CONTENT_MARKERS]
    patterns += [(m, m.encode('utf-16-le')) for m in CONTENT_MARKERS]
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            lower = name.lower()
            if lower.endswith(MODEL_SUFFIXES):
                failures.append(f'model file {name}')
            failures += [f'{marker} entry {name}' for marker in NAME_MARKERS if marker in lower]
            data = archive.read(name)
            seen = sorted({marker for marker, pattern in patterns if pattern in data})
            failures += [f'{marker} in {name}' for marker in seen]
            scanner = scanner or (name.endswith('.dex') and SCANNER in data)
    return failures, scanner


def gradle_failures(text):
    found = set()
    for line in text.splitlines():
        match = re.search(r'[+\\]--- ([\w.-]+):([\w.-]+)', line)
        if match and match.group(1).startswith(GRADLE_GROUPS):
            found.add(f'{match.group(1)}:{match.group(2)} in Gradle runtime graph')
    return sorted(found)


def main(argv):
    if not argv or argv[0].startswith('-'):
        raise SystemExit(__doc__)
    apk, rest = Path(argv[0]), argv[1:]
    deps = expect = None
    while rest:
        flag = rest.pop(0)
        if flag == '--gradle-deps' and rest:
            deps = Path(rest.pop(0))
        elif flag == '--expect-scanner':
            expect = True
        else:
            raise SystemExit(f'unknown argument {flag}')
    failures, scanner = apk_failures(apk)
    if deps is not None:
        text = deps.read_text()
        if 'RuntimeClasspath' not in text or '+--- ' not in text:
            failures.append(f'{deps} is not a resolved Gradle runtime dependency report')
        failures += gradle_failures(text)
    if expect and not scanner:
        failures.append('the app QR adapter class is missing from dex')
    if failures:
        for failure in failures:
            print(f'android no-models check FAIL: {failure}', file=sys.stderr)
        return 1
    print(f'ok: {apk} has no model files, model runtimes, ML Kit, Play Services, Firebase or '
          f'data-transport components' + (' (resolved Gradle graph too)' if deps else '')
          + ('; app QR adapter present' if expect else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
