import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest


class EndpointTests(unittest.TestCase):
    def test_build_process_consumes_snapshot_and_records_artifact_hash(self):
        import subprocess
        import sys
        script = pathlib.Path(__file__).with_name('sync_endpoint.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / 'endpoint.json'
            raw = b'{"appraisal":"hardware","edge_url":"https://fixture.invalid","recovery_key":"0001ab"}\n'
            source.write_bytes(raw)
            artifact = root / 'fixture.apk'
            # A portable process-boundary fixture, not an Android build.
            command = [sys.executable, '-c',
                       'import os,pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(pathlib.Path(os.environ["BH_SYNC_ENDPOINT"]).read_bytes())',
                       str(artifact)]
            run = subprocess.run([sys.executable, str(script), '--sync-endpoint', str(source),
                                  '--output', str(root / 'out'), '--artifact', str(artifact), '--', *command],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(artifact.read_bytes(), raw)
            proof = json.loads((root / 'out/sync-endpoint-provenance.json').read_text())
            self.assertEqual(proof['artifact_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(proof['endpoint']['sha256'], hashlib.sha256(raw).hexdigest())
            source.write_bytes(b'')
            run = subprocess.run([sys.executable, str(script), '--sync-endpoint', str(source),
                                  '--output', str(root / 'invalid'), '--artifact', str(artifact), '--', *command],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse((root / 'invalid/sync-endpoint-provenance.json').exists())
            self.assertEqual(artifact.read_bytes(), raw, 'failed input must not invoke the builder')

    def test_explicit_modes_exact_bytes_hash_and_no_environment_fallback(self):
        script = pathlib.Path(__file__).with_name('sync_endpoint.py')
        self.assertTrue(script.exists(), 'endpoint handoff helper missing')
        spec = importlib.util.spec_from_file_location('sync_endpoint', script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / 'input.json'
            exact = b'{"appraisal": "hardware", "edge_url": "https://fixture.invalid", "recovery_key": "0001ab"}\n'
            source.write_bytes(exact)
            env, proof = module.prepare_endpoint(source, False, root / 'out', {'BH_SYNC_ENDPOINT': '/unrelated'})
            self.assertEqual(pathlib.Path(env['BH_SYNC_ENDPOINT']).read_bytes(), exact)
            self.assertEqual(proof['sha256'], hashlib.sha256(exact).hexdigest())
            source.write_bytes(b'changed after snapshot')
            self.assertEqual(pathlib.Path(env['BH_SYNC_ENDPOINT']).read_bytes(), exact)
            env, proof = module.prepare_endpoint(None, True, root / 'local', {'BH_SYNC_ENDPOINT': '/unrelated'})
            self.assertNotIn('BH_SYNC_ENDPOINT', env)
            self.assertEqual(proof, {'mode': 'local-only'})
            for path, local in ((None, False), (source, True), (root / 'missing', False)):
                with self.assertRaises((ValueError, OSError)):
                    module.prepare_endpoint(path, local, root / 'bad', {})
            for content in (b'', b'  ', b'{', b'{"appraisal":"synthetic"}', b'{"appraisal":"hardware","edge_url":"http://fixture.invalid","recovery_key":"0001ab"}',
                            # No recovery key, or not one as text.
                            b'{"appraisal":"hardware","edge_url":"https://fixture.invalid"}',
                            b'{"appraisal":"hardware","edge_url":"https://fixture.invalid","recovery_key":""}',
                            b'{"appraisal":"hardware","edge_url":"https://fixture.invalid","recovery_key":1}'):
                source.write_bytes(content)
                with self.assertRaises(ValueError):
                    module.prepare_endpoint(source, False, root / 'bad', {})


if __name__ == '__main__':
    unittest.main()
