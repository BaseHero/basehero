import importlib.util
import contextlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('no_models', Path(__file__).with_name('android_no_models.py'))
no_models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(no_models)

CLEAN_DEX = b'dex\n035\x00Lapp/basehero/qrscan/QrScanPlugin;\x00Lcom/google/zxing/qrcode/QRCodeReader;'
GRAPH = '''universalReleaseRuntimeClasspath - Runtime classpath of /universalRelease.
+--- androidx.camera:camera-core:1.5.1
\\--- com.google.zxing:core:3.5.4
'''


class NoModelsTests(unittest.TestCase):
    def apk(self, entries):
        handle = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        with zipfile.ZipFile(handle.name, 'w') as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return handle.name

    def run_check(self, entries, *flags, graph=None, expected_failure=None):
        args = [self.apk(entries), *flags]
        if graph is not None:
            deps = Path(tempfile.mkdtemp()) / 'deps.txt'
            deps.write_text(graph)
            self.addCleanup(deps.unlink)
            args += ['--gradle-deps', str(deps)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = no_models.main(args)
        if expected_failure is None:
            self.assertEqual(stderr.getvalue(), '')
            self.assertTrue(stdout.getvalue().startswith('ok: '))
        else:
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn(expected_failure, stderr.getvalue())
            self.assertTrue(all(line.startswith('android no-models check FAIL: ')
                                for line in stderr.getvalue().splitlines()))
        return result

    def test_clean_scanner_package_and_graph_pass(self):
        self.assertEqual(self.run_check({'classes.dex': CLEAN_DEX, 'AndroidManifest.xml': b'x'},
                                        '--expect-scanner', graph=GRAPH), 0)

    def test_expected_negative_cases_do_not_pollute_successful_test_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.test_model_files_and_native_runtime_rejected()
        self.assertEqual(output.getvalue(), '')

    def test_model_files_and_native_runtime_rejected(self):
        for name in ('assets/mlkit_barcode_models/x.tflite', 'assets/detector.onnx',
                     'lib/x86_64/libbarhopper_v3.so', 'lib/arm64-v8a/libtensorflowlite_jni.so',
                     'play-services-mlkit-barcode-scanning.properties'):
            with self.subTest(name=name):
                reason = f'model file {name}' if name.endswith(('.tflite', '.onnx')) else f' entry {name}'
                self.assertEqual(self.run_check({'classes.dex': CLEAN_DEX, name: b'\x00'},
                                                expected_failure=reason), 1)

    def test_sdk_classes_and_manifest_components_rejected(self):
        for name, data in (('classes2.dex', b'Lcom/google/mlkit/vision/barcode/BarcodeScanning;'),
                           ('classes.dex', b'Lcom/google/android/gms/dynamite/DynamiteModule;'),
                           ('classes.dex', b'Lcom/google/android/datatransport/runtime/T;'),
                           ('AndroidManifest.xml',
                            'com.google.mlkit.common.internal.MlKitInitProvider'.encode('utf-16-le'))):
            with self.subTest(name=name, data=data[:24]):
                marker = ('com/google/mlkit' if b'mlkit/' in data else
                          'com/google/android/gms' if b'/gms/' in data else
                          'com/google/android/datatransport' if b'datatransport' in data else
                          'com.google.mlkit')
                self.assertEqual(self.run_check({'classes9.dex': CLEAN_DEX, name: data},
                                                expected_failure=marker), 1)

    def test_resolved_graph_rejects_ml_and_play_services(self):
        for dependency in ('com.google.mlkit:barcode-scanning:17.3.0',
                           'com.google.android.gms:play-services-mlkit-barcode-scanning:18.1.0',
                           'com.google.android.datatransport:transport-runtime:2.2.6'):
            with self.subTest(dependency=dependency):
                graph = GRAPH + f'|    \\--- {dependency}\n'
                self.assertEqual(self.run_check({'classes.dex': CLEAN_DEX}, graph=graph,
                                                expected_failure=f'{dependency.rsplit(":", 1)[0]} in Gradle runtime graph'), 1)
        self.assertEqual(self.run_check({'classes.dex': CLEAN_DEX}, graph='BUILD FAILED',
                                        expected_failure='is not a resolved Gradle runtime dependency report'), 1)

    def test_positive_control_requires_the_adapter(self):
        self.assertEqual(self.run_check({'classes.dex': b'dex\n035\x00'}, '--expect-scanner',
                                        expected_failure='the app QR adapter class is missing from dex'), 1)


if __name__ == '__main__':
    unittest.main()
