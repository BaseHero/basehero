"""Local release boundary tests; all identities are throwaway fixtures."""
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
import sys

SCRIPT = pathlib.Path(__file__).with_name('prepare-sync-release.py')
sys.path.insert(0, str(SCRIPT.parent))


class ReleaseTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SCRIPT.is_file(), 'committed-source release builder is missing')
        spec = importlib.util.spec_from_file_location('sync_release', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_export_committed_product_only_in_private_and_public_repo(self):
        m = self.module()
        for prefix in ('', 'product/'):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as tmp:
                repo = pathlib.Path(tmp) / 'repo'
                product = repo / prefix
                product.mkdir(parents=True)
                def git(*args):
                    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
                git('init', '-q')
                (product / 'Cargo.lock').write_text('committed lock')
                (product / 'flake.lock').write_text('committed flake lock')
                (product / '.gitignore').write_text('sync_worker.wasm\n')
                git('add', '.')
                git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid', 'commit', '-qm', 'fixture')
                commit = git('rev-parse', 'HEAD')
                (product / 'Cargo.lock').write_text('dirty')
                (product / 'sync_worker.wasm').write_text('ignored development bytes')
                (product / 'untracked').write_text('never ship')
                output = pathlib.Path(tmp) / 'bundle'
                identity = m.export_source(product, commit, output)
                self.assertEqual(identity['source_commit'], commit)
                self.assertEqual(identity['product_tree'], git('rev-parse', f'{commit}:{prefix.rstrip("/")}' if prefix else f'{commit}^{{tree}}'))
                self.assertEqual((output / 'source/Cargo.lock').read_text(), 'committed lock')
                self.assertFalse((output / 'source/sync_worker.wasm').exists())
                self.assertFalse((output / 'source/untracked').exists())
                with self.assertRaises(ValueError):
                    m.export_source(product, commit, output)
                with self.assertRaises(ValueError):
                    m.export_source(product, 'HEAD', pathlib.Path(tmp) / 'mutable')
                self.assertEqual((product / 'Cargo.lock').read_text(), 'dirty')

    def test_manifest_refuses_tampered_added_and_linked_artifacts(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / 'worker').mkdir()
            artifact = root / 'worker/edge.mjs'
            artifact.write_text('release')
            manifest = {'artifacts': m.hash_tree(root / 'worker', 'worker')}
            m.verify_artifacts(root, manifest)
            artifact.write_text('tamper')
            with self.assertRaises(ValueError):
                m.verify_artifacts(root, manifest)
            artifact.write_text('release')
            (root / 'worker/extra').write_text('injection')
            with self.assertRaises(ValueError):
                m.verify_artifacts(root, manifest)
            (root / 'worker/extra').unlink()
            artifact.unlink()
            artifact.symlink_to('/etc/hostname')
            with self.assertRaises(ValueError):
                m.verify_artifacts(root, manifest)

    def inputs(self):
        return {
            'cloudflare': {'account_id': 'a' * 32, 'name': 'fixture-sync',
                          'route': {'pattern': 'edge.invalid', 'custom_domain': True},
                          'bucket': 'fixture-private', 'receipt_key_binding': 'RECEIPT_KEY',
                          'receipt_cert_file': '/fixture/receipt.cert'},
            'authz': {'backends': [{'url': 'https://authz.invalid/v1/channel', 'ready': True}],
                      'image': 'bh-authz:fixture', 'image_id': 'sha256:' + '1' * 64,
                      'archive_sha256': '2' * 64, 'registry_manifest_file': None,
                      'protected_mount': '/protected/authz',
                      'uid': 1000, 'gid': 1000, 'quote_socket': '/run/fixture.sock',
                      'files': {key: '/fixture/' + key for key in
                                ('permit_key', 'permit_cert', 'recovery_key', 'recovery_cert', 'policy', 'policy_signature', 'collateral')},
                      'roughtime': [{'address': '192.0.2.1:2002', 'key': '11' * 32},
                                   {'address': '192.0.2.2:2002', 'key': '22' * 32}],
                      'time_config': [1000000000, 100, 1000000, 120000000000, 1000]},
            'endpoint': {'edge_url': 'https://edge.invalid', 'hosting_root': '11' * 32,
                         'app_root': '22' * 32, 'policy': '01', 'policy_signature': '02',
                         'recovery_key': '03', 'max_lifetime_secs': 86400, 'max_uncertainty_secs': 30,
                         'build_floor': 1, 'appraisal': 'hardware'}}

    def test_explicit_inputs_and_negative_cases(self):
        import copy
        m = self.module()
        good = self.inputs()
        m.validate_inputs(good)
        cases = [('authz', 'protected_mount', ''), ('authz', 'uid', 0),
                 ('authz', 'roughtime', []), ('authz', 'time_config', [1, 1, 1, 1, 1]),
                 ('authz', 'image', 'bh-authz:latest'),
                 ('authz', 'backends', [{'url': 'http://authz.invalid', 'ready': True}]),
                 ('endpoint', 'appraisal', 'synthetic'),
                 ('endpoint', 'edge_url', 'http://edge.invalid'),
                 ('cloudflare', 'receipt_key_binding', 'actual-secret-value')]
        for section, key, value in cases:
            bad = copy.deepcopy(good)
            bad[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_inputs(bad)
        for section in good:
            for key in good[section]:
                bad = copy.deepcopy(good)
                del bad[section][key]
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    m.validate_inputs(bad)
        bad = copy.deepcopy(good)
        bad['endpoint']['edge_url'] = 'https://$INHERITED.invalid'
        bad['cloudflare']['route']['pattern'] = '$INHERITED.invalid'
        with self.assertRaises(ValueError):
            m.validate_inputs(bad)
        bad = copy.deepcopy(good)
        bad['authz']['permit_seed'] = 'SECRET-MUST-NOT-BE-LOGGED'
        with self.assertRaises(ValueError) as raised:
            m.validate_inputs(bad)
        self.assertNotIn('SECRET', str(raised.exception))

    def test_missing_recovery_input_refused_before_startup(self):
        m = self.module()
        good = self.inputs()
        good['authz']['image'] = 'registry.invalid/throwaway/authz@sha256:' + 'a' * 64
        good['authz']['registry_manifest_file'] = '/fixture/registry.json'
        m.validate_inputs(good, preparation=True)  # References only: none of these files exists.
        for name in ('recovery_key', 'recovery_cert'):
            bad = json.loads(json.dumps(good))
            del bad['authz']['files'][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'authz.files.' + name):
                m.validate_inputs(bad, preparation=True)
            bad = json.loads(json.dumps(good))
            bad['authz']['files'][name] = None
            with self.subTest(name=name), self.assertRaises(ValueError):
                m.validate_inputs(bad, preparation=True)

    def test_registry_reference_requires_matching_public_manifest_and_image_config(self):
        import hashlib
        m = self.module()
        self.assertTrue(callable(getattr(m, 'verify_image_reference', None)), 'verified registry handoff missing')
        actual = {'reference': 'bh-authz:fixture', 'image_id': 'sha256:' + '1' * 64,
                  'archive_sha256': '2' * 64}
        a = self.inputs()['authz']
        self.assertIsNone(m.verify_image_reference(actual, a))
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'public-image-manifest.json'
            raw = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                              'config': {'digest': actual['image_id']}, 'layers': []}).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            a['image'] = 'registry.invalid/throwaway/authz@sha256:' + digest
            a['registry_manifest_file'] = str(path)
            self.assertEqual(m.verify_image_reference(actual, a), digest)
            good = self.inputs()
            good['authz'] = a
            m.validate_inputs(good)
            import sync_deployment
            app, _ = sync_deployment.render(good, actual)
            self.assertEqual(json.loads(app['docker_compose_file'])['services']['authz']['pull_policy'], 'missing')
            path.write_bytes(raw + b' ')
            with self.assertRaises(ValueError):
                m.verify_image_reference(actual, a)
            path.write_bytes(raw)
            a['image_id'] = 'sha256:' + '3' * 64
            with self.assertRaises(ValueError):
                m.verify_image_reference(actual, a)
            a['image_id'] = actual['image_id']
            wrong = raw.replace(('1' * 64).encode(), ('4' * 64).encode())
            path.write_bytes(wrong)
            a['image'] = 'registry.invalid/throwaway/authz@sha256:' + hashlib.sha256(wrong).hexdigest()
            with self.assertRaises(ValueError):
                m.verify_image_reference(actual, a)

    def test_render_worker_and_public_endpoint_only(self):
        m = self.module()
        values = self.inputs()
        rendered = m.render(values, 'fixture-public-receipt-cert')
        self.assertNotIn('compose.json', rendered)
        self.assertEqual(rendered['endpoint.json'], values['endpoint'])
        worker = rendered['wrangler.json']
        self.assertEqual(worker['r2_buckets'][0]['binding'], 'BODIES')
        self.assertEqual({b['name'] for b in worker['durable_objects']['bindings']}, {'LOG', 'RELAY'})
        self.assertNotIn('RECEIPT_KEY', worker['vars'])
        self.assertEqual(json.loads(worker['vars']['AUTHZ_BACKENDS']), values['authz']['backends'])

    def test_emitted_authz_image_closure_and_fail_closed_binary(self):
        import io
        import os
        import tarfile
        bundle = os.environ.get('BH_RELEASE_TEST_BUNDLE')
        if not bundle:
            self.skipTest('set BH_RELEASE_TEST_BUNDLE for actual artifact smoke')
        bundle = pathlib.Path(bundle)
        m = self.module()
        manifest = json.loads((bundle / 'manifest.json').read_text())
        m.verify_artifacts(bundle, manifest)
        archive = bundle / 'authz/image.tar.gz'
        self.assertEqual(m.image_identity(archive), manifest['image'])
        names = set()
        with tarfile.open(archive) as tar:
            item, = json.load(tar.extractfile('manifest.json'))
            config = json.load(tar.extractfile(item['Config']))['config']
            self.assertEqual(config['User'], '65532:65532')
            self.assertTrue(any('ca-bundle.crt' in item for item in config['Env']))
            for layer in item['Layers']:
                raw = tar.extractfile(layer).read()
                self.assertNotIn(('21' * 32).encode(), raw, 'throwaway permit seed leaked into image')
                with tarfile.open(fileobj=io.BytesIO(raw)) as content:
                    names.update(member.name.lstrip('./') for member in content)
        self.assertIn(config['Entrypoint'][0].lstrip('/'), names)
        for path in (bundle / 'authz/closure.txt').read_text().splitlines():
            self.assertTrue(any(name == path.lstrip('/') or name.startswith(path.lstrip('/') + '/') for name in names), path)
        for name in names:
            self.assertFalse(name.endswith(('/bin/rustc', '/bin/cargo', '/bin/gcc')), name)
            self.assertNotIn('fixture', name)
        binary = bundle / 'authz/bh-authz'
        for args, refusal in [([], '--permit-key is required'), (['--synthetic-attestation'], 'unknown flag --synthetic-attestation')]:
            run = subprocess.run([str(binary), *args], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn(refusal, run.stderr)
            self.assertEqual(run.stdout, '')

    def test_release_workerd_checks_disable_cloudflare_metadata_fetch(self):
        for script in (SCRIPT.with_name('check-sync-release-config.mjs'),
                       SCRIPT.parent.parent / 'tests/sync-worker/test/edge.test.mjs'):
            self.assertIn('cf: false', script.read_text(), str(script))

    def test_packaging_validator_never_issues_signatures(self):
        production = SCRIPT.with_name('sync_release_validator.rs').read_text().split('#[cfg(test)]')[0]
        self.assertNotIn('::sign(', production)
        self.assertNotIn('.sign(', production)

    def test_incomplete_operator_input_names_requirements(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'cloudflare'):
            m.validate_inputs({})


if __name__ == '__main__':
    unittest.main()
