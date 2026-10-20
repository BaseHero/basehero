"""Offline measured candidate and measured bootstrap; throwaway identities only."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Executables present in the pinned dstack guest image.
GUEST_COMMANDS = ('bash', 'sh', 'printf', 'mkdir', 'chmod', 'chown', 'stat', 'jq',
                  'cat', 'rm', 'test', '[', 'env', 'id', 'head', 'tr', 'mktemp')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.packaging = module(HERE / 'prepare-sync-release.py', 'sync_release')
        self.wrapper = module(HERE / 'sync_deployment.py', 'sync_deployment')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.image = {'reference': 'bh-authz:fixture', 'image_id': 'sha256:' + '1' * 64,
                      'archive_sha256': '2' * 64}
        raw = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                          'config': {'digest': self.image['image_id']}, 'layers': []}).encode()
        manifest = self.root / 'registry.json'
        manifest.write_bytes(raw)
        self.inputs = {
            'cloudflare': {'account_id': 'a' * 32, 'name': 'fixture-sync', 'bucket': 'fixture-private',
                           'route': {'pattern': 'edge.invalid', 'custom_domain': True},
                           'receipt_key_binding': 'RECEIPT_KEY', 'receipt_cert_file': str(self.root / 'missing-receipt')},
            'authz': {'backends': [{'url': 'https://authz.invalid/v1/channel', 'ready': True}],
                      'image': 'registry.invalid/throwaway/authz@sha256:' + hashlib.sha256(raw).hexdigest(),
                      'image_id': self.image['image_id'], 'archive_sha256': self.image['archive_sha256'],
                      'registry_manifest_file': str(manifest),
                      'protected_mount': str(self.root / 'protected'), 'uid': os.getuid(), 'gid': os.getgid(),
                      'quote_socket': str(self.root / 'missing-quote'),
                      'files': {key: str(self.root / ('missing-' + key)) for key in
                                ('permit_key', 'permit_cert', 'policy', 'policy_signature', 'collateral')},
                      'roughtime': [{'address': '192.0.2.1:2002', 'key': '11' * 32},
                                   {'address': '192.0.2.2:2002', 'key': '22' * 32}],
                      'time_config': [1000000000, 100, 1000000, 120000000000, 1000]},
            'endpoint': {'edge_url': 'https://edge.invalid', 'hosting_root': '11' * 32,
                         'app_root': '22' * 32, 'policy': '', 'policy_signature': '',
                         'max_lifetime_secs': 86400, 'max_uncertainty_secs': 30,
                         'build_floor': 1, 'appraisal': 'hardware'}}

    def test_candidate_is_complete_deterministic_and_policy_independent(self):
        """Catches policy-derived or partial/noncanonical candidate hashes."""
        self.packaging.validate_inputs(self.inputs, preparation=True)
        first = self.wrapper.render(self.inputs, self.image)
        app, digest = first
        self.assertEqual(app['manifest_version'], 2)
        self.assertEqual(app['runner'], 'docker-compose')
        self.assertEqual(app['features'], ['kms', 'tproxy-net'])
        self.assertFalse(app['public_logs'] or app['public_sysinfo'] or app['public_tcbinfo'])
        self.assertNotIn('user_config', app)
        self.assertNotIn('ssh', json.dumps(app).lower())
        self.assertEqual(digest, hashlib.sha256(json.dumps(app, sort_keys=True, separators=(',', ':'),
                                                        ensure_ascii=False).encode()).hexdigest())
        changed_policy = copy.deepcopy(self.inputs)
        changed_policy['endpoint']['policy'] = 'deadbeef'
        changed_policy['endpoint']['policy_signature'] = 'cafe'
        self.assertEqual(first, self.wrapper.render(changed_policy, self.image))
        for section, field, value in [('endpoint', 'hosting_root', '33' * 32),
                                      ('authz', 'image', 'registry.invalid/throwaway/other@sha256:' + 'f' * 64),
                                      ('authz', 'protected_mount', str(self.root / 'other')),
                                      ('authz', 'quote_socket', '/tmp/other.sock')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.inputs)
                changed[section][field] = value
                self.assertNotEqual(digest, self.wrapper.render(changed, self.image)[1])
        changed = copy.deepcopy(self.inputs)
        changed['authz']['roughtime'][0]['address'] = '192.0.2.3:2002'
        self.assertNotEqual(digest, self.wrapper.render(changed, self.image)[1])
        self.assertNotIn('fixture-secret', json.dumps(app))

    def test_registry_file_relocation_is_not_preparation_identity_but_bytes_are_checked(self):
        """Catches binding a host-only pathname or skipping raw registry verification."""
        relocated = self.root / 'other-registry.json'
        original = Path(self.inputs['authz']['registry_manifest_file'])
        relocated.write_bytes(original.read_bytes())
        changed = copy.deepcopy(self.inputs)
        changed['authz']['registry_manifest_file'] = str(relocated)
        self.assertEqual(self.packaging.deployment_inputs(self.inputs),
                         self.packaging.deployment_inputs(changed))
        self.assertEqual(self.wrapper.render(self.inputs, self.image),
                         self.wrapper.render(changed, self.image))
        self.assertEqual(self.packaging.verify_image_reference(self.image, changed['authz']),
                         hashlib.sha256(original.read_bytes()).hexdigest())
        changed['authz']['protected_mount'] = str(self.root / 'different-mount')
        self.assertNotEqual(self.packaging.deployment_inputs(self.inputs),
                            self.packaging.deployment_inputs(changed))
        changed['authz']['protected_mount'] = self.inputs['authz']['protected_mount']
        relocated.write_bytes(original.read_bytes() + b'\n')
        with self.assertRaises(ValueError):
            self.packaging.verify_image_reference(self.image, changed['authz'])

    def test_authz_port_is_published_beyond_loopback_for_the_gateway(self):
        """Catches a loopback-only port that the dstack gateway cannot reach over WireGuard."""
        app, _ = self.wrapper.render(self.inputs, self.image)
        service = json.loads(app['docker_compose_file'])['services']['authz']
        self.assertEqual(service['ports'], ['7801:7801'])
        self.assertIn('0.0.0.0:7801', service['command'])
        self.assertNotIn('port_policy', app)

    def test_canonical_app_compose_fixed_vector(self):
        """Catches changed command, mount, bootstrap, settings, or JSON encoding."""
        value = copy.deepcopy(self.inputs)
        value['authz']['image'] = 'registry.invalid/bh/authz@sha256:' + 'a' * 64
        value['authz']['uid'] = value['authz']['gid'] = 1000
        value['authz']['protected_mount'] = '/protected/authz'
        value['authz']['quote_socket'] = '/run/quote.sock'
        self.assertEqual(self.wrapper.render(value, self.image)[1],
                         'df5de343008dc0848b63964a0716599fcd79a3c242521fd0490f6dc04adf1612')

    def test_saved_provider_response_must_match_hash_and_compose(self):
        """Catches adoption of a provider-selected hash or a differently normalized object."""
        app, digest = self.wrapper.render(self.inputs, self.image)
        self.wrapper.compare_provider_response(app, digest, {'compose_hash': digest, 'compose_file': app})
        for response in ({'compose_hash': 'f' * 64},
                         {'compose_hash': digest, 'compose_file': {**app, 'public_logs': True}},
                         {'compose_hash': digest, 'compose_file': {**app, 'docker_compose_file': '{}'}}):
            with self.assertRaises(ValueError):
                self.wrapper.compare_provider_response(app, digest, response)

    def test_fixed_bootstrap_materializes_exact_secrets_with_private_permissions(self):
        """Catches missing mounts, leaky output, loose permissions, and an absent-secret success."""
        app, _ = self.wrapper.render(self.inputs, self.image, runtime_dir=str(self.root / 'runtime'),
                                     registry_config_dir=str(self.root / 'docker'))
        script = app['pre_launch_script']
        service = json.loads(app['docker_compose_file'])['services']['authz']
        mounts = {v['target']: v['source'] for v in service['volumes']}
        sentinel = 'PRIVATE-ENCRYPTED-SENTINEL-491'
        env = {**os.environ, 'DSTACK_DOCKER_REGISTRY': 'registry.invalid',
               'DSTACK_DOCKER_USERNAME': sentinel, 'DSTACK_DOCKER_PASSWORD': sentinel}
        (self.root / 'home').mkdir()
        env['HOME'] = str(self.root / 'home')
        if not shutil.which('jq'):
            self.skipTest('host jq is required to execute the pinned guest bootstrap')
        guest_bin = self.root / 'guest-bin'
        guest_bin.mkdir()
        for command in GUEST_COMMANDS:
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f'host lacks guest command {command}')
            (guest_bin / command).symlink_to(Path(executable).resolve())
        env['PATH'] = str(guest_bin)
        env.pop('DOCKER_CONFIG', None)
        env.pop('GH_TOKEN', None)
        env.pop('GITHUB_TOKEN', None)
        for name in self.wrapper.RUNTIME_FILES:
            env[self.wrapper.RUNTIME_FILES[name]] = sentinel + '\n' + name
            self.assertEqual(mounts['/run/config/' + name], str(self.root / 'runtime' / name))
        script_file = self.root / 'pre-launch.sh'
        script_file.write_text(script)
        run = subprocess.run(['bash', '-c', 'source "$1"; bash -c \'printf %s "${DOCKER_CONFIG-unset}"\'',
                              'bash', str(script_file)], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, str(self.root / 'docker'))
        self.assertFalse((self.root / 'home/.docker').exists())
        default_script = self.wrapper.render(self.inputs, self.image)[0]['pre_launch_script']
        self.assertIn('/dstack/bh-registry/config.json', default_script)
        self.assertNotIn('/root/', default_script)
        self.assertNotIn(sentinel, run.stdout + run.stderr + json.dumps(app))
        registry_file = self.root / 'docker/config.json'
        self.assertEqual(registry_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'docker').stat().st_mode & 0o777, 0o700)
        registry = json.loads(registry_file.read_text())['auths']
        self.assertEqual(list(registry), ['registry.invalid'])
        self.assertEqual(registry['registry.invalid']['auth'],
                         base64.b64encode((sentinel + ':' + sentinel).encode()).decode())
        self.assertEqual((self.root / 'runtime').stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / 'protected').stat().st_mode & 0o777, 0o700)
        for name in self.wrapper.RUNTIME_FILES:
            file = self.root / 'runtime' / name
            self.assertEqual(file.read_bytes(), env[self.wrapper.RUNTIME_FILES[name]].encode())
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        env.pop(self.wrapper.RUNTIME_FILES['policy'])
        failed = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn(sentinel, failed.stdout + failed.stderr)
        self.assertNotIn('PRIVATE-', failed.stdout + failed.stderr)

    def test_config_file_set_and_endpoint_hash_are_verified(self):
        """Catches root/config mismatch, untracked added files and endpoint hash substitution."""
        root = self.root / 'configured'
        (root / 'config').mkdir(parents=True)
        (root / 'config/endpoint.json').write_text('{"appraisal":"hardware"}')
        manifest = {'artifacts': self.packaging.hash_tree(root / 'config', 'config'),
                    'public_config_sha256': self.packaging.sha256(root / 'config/endpoint.json')}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        self.packaging.verify_config(root)
        manifest['public_config_sha256'] = 'f' * 64
        (root / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.packaging.verify_config(root)
        manifest['public_config_sha256'] = self.packaging.sha256(root / 'config/endpoint.json')
        (root / 'manifest.json').write_text(json.dumps(manifest))
        (root / 'config/extra').write_text('extra')
        with self.assertRaises(ValueError):
            self.packaging.verify_config(root)
        (root / 'config/extra').unlink()
        (root / 'unexpected').write_text('extra')
        with self.assertRaises(ValueError):
            self.packaging.verify_config(root)
        (root / 'unexpected').unlink()
        (root / 'config/endpoint.json').write_text('changed')
        with self.assertRaises(ValueError):
            self.packaging.verify_config(root)


if __name__ == '__main__':
    unittest.main()
