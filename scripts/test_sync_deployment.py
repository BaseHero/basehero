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
from unittest import mock
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
                                ('permit_key', 'permit_cert', 'recovery_key', 'recovery_cert', 'policy', 'policy_signature', 'collateral')},
                      'roughtime': [{'address': '192.0.2.1:2002', 'key': '11' * 32},
                                   {'address': '192.0.2.2:2002', 'key': '22' * 32}],
                      'time_config': [1000000000, 100, 1000000, 120000000000, 1000]},
            'endpoint': {'edge_url': 'https://edge.invalid', 'hosting_root': '11' * 32,
                         'app_root': '22' * 32, 'policy': '', 'policy_signature': '',
                         'recovery_key': '03', 'max_lifetime_secs': 86400, 'max_uncertainty_secs': 30,
                         'build_floor': 1, 'appraisal': 'hardware'}}

    def test_candidate_is_complete_deterministic_and_policy_independent(self):
        """Catches policy-derived or partial/noncanonical candidate hashes."""
        inputs = copy.deepcopy(self.inputs)
        inputs['authz']['uid'] = inputs['authz']['gid'] = 1000
        self.packaging.validate_inputs(inputs, preparation=True)
        first = self.wrapper.render(inputs, self.image)
        app, digest = first
        self.assertEqual(app['manifest_version'], 2)
        self.assertEqual(app['runner'], 'docker-compose')
        self.assertEqual(app['features'], ['kms', 'tproxy-net'])
        self.assertFalse(app['public_logs'] or app['public_sysinfo'] or app['public_tcbinfo'])
        self.assertNotIn('user_config', app)
        self.assertNotIn('ssh', json.dumps(app).lower())
        self.assertEqual(digest, hashlib.sha256(json.dumps(app, sort_keys=True, separators=(',', ':'),
                                                        ensure_ascii=False).encode()).hexdigest())
        changed_policy = copy.deepcopy(inputs)
        changed_policy['endpoint']['policy'] = 'deadbeef'
        changed_policy['endpoint']['policy_signature'] = 'cafe'
        self.assertEqual(first, self.wrapper.render(changed_policy, self.image))
        for section, field, value in [('endpoint', 'hosting_root', '33' * 32),
                                      ('authz', 'image', 'registry.invalid/throwaway/other@sha256:' + 'f' * 64),
                                      ('authz', 'protected_mount', str(self.root / 'other')),
                                      ('authz', 'quote_socket', '/tmp/other.sock')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(inputs)
                changed[section][field] = value
                self.assertNotEqual(digest, self.wrapper.render(changed, self.image)[1])
        changed = copy.deepcopy(inputs)
        changed['authz']['roughtime'][0]['address'] = '192.0.2.3:2002'
        self.assertNotEqual(digest, self.wrapper.render(changed, self.image)[1])
        self.assertNotIn('fixture-secret', json.dumps(app))

    def test_preparation_rejects_root_uid_or_gid(self):
        """Catches accepting a root deployment identity for either credential."""
        inputs = copy.deepcopy(self.inputs)
        inputs['authz']['uid'] = inputs['authz']['gid'] = 1000
        self.packaging.validate_inputs(inputs, preparation=True)
        for key in ('uid', 'gid'):
            with self.subTest(key=key):
                rooted = copy.deepcopy(inputs)
                rooted['authz'][key] = 0
                with self.assertRaisesRegex(ValueError, 'explicit non-root ' + key + ' required'):
                    self.packaging.validate_inputs(rooted, preparation=True)

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
                         '7046dca5b0acb4e372a16271765d422efb425bb421109bcc5e5d6ee5da40d43e')

    def test_recovery_inputs_reach_private_runtime_files_and_service_arguments(self):
        app, _ = self.wrapper.render(self.inputs, self.image, runtime_dir=str(self.root / 'runtime'),
                                     registry_config_dir=str(self.root / 'docker'))
        service = json.loads(app['docker_compose_file'])['services']['authz']
        for name in ('recovery_key', 'recovery_cert'):
            env_name = 'BH_AUTHZ_' + name.upper()
            target = '/run/config/' + name
            self.assertIn(env_name, app['allowed_envs'])
            self.assertIn(env_name, app['pre_launch_script'])
            self.assertIn(['--' + name.replace('_', '-'), target],
                          [service['command'][i:i + 2] for i in range(len(service['command']) - 1)])
            self.assertIn({'type': 'bind', 'source': str(self.root / 'runtime' / name),
                           'target': target, 'read_only': True, 'bind': {'create_host_path': False}},
                          service['volumes'])
        self.assertNotIn('PRIVATE-ENCRYPTED-SENTINEL', json.dumps(app))

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
        # Probe only fake parent values; never print real host environment values.
        parent_secret = 'PARENT-UNRELATED-CREDENTIAL-SENTINEL'
        for name in ('home', 'gh-config', 'xdg-config', 'xdg-data', 'xdg-cache'):
            (self.root / name).mkdir()
        # Explicit child environment: no host credentials or XDG state cross into it.
        env = {'DSTACK_DOCKER_REGISTRY': 'registry.invalid',
               'DSTACK_DOCKER_USERNAME': sentinel, 'DSTACK_DOCKER_PASSWORD': sentinel,
               'HOME': str(self.root / 'home'), 'GH_CONFIG_DIR': str(self.root / 'gh-config'),
               'XDG_CONFIG_HOME': str(self.root / 'xdg-config'),
               'XDG_DATA_HOME': str(self.root / 'xdg-data'),
               'XDG_CACHE_HOME': str(self.root / 'xdg-cache'), 'LC_ALL': 'C'}
        guest_bin = self.root / 'guest-bin'
        guest_bin.mkdir()
        for command in GUEST_COMMANDS:
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f'host lacks guest command {command}')
            (guest_bin / command).symlink_to(Path(executable).resolve())
        for command in GUEST_COMMANDS:
            self.assertTrue((guest_bin / command).resolve().is_file(), f'{command} stub must resolve')
        isolation = shutil.which('unshare')
        self.assertIsNotNone(isolation, 'Linux network isolation required')
        env['PATH'] = str(guest_bin)
        for name in self.wrapper.RUNTIME_FILES:
            env[self.wrapper.RUNTIME_FILES[name]] = sentinel + '\n' + name + '\n'
            self.assertEqual(mounts['/run/config/' + name], str(self.root / 'runtime' / name))
        script_file = self.root / 'pre-launch.sh'
        script_file.write_text(script)
        with mock.patch.dict(os.environ, {
            'BH_FIXTURE_UNRELATED_CREDENTIAL': parent_secret,
            'XDG_DATA_HOME': str(self.root / 'parent-data-sentinel'),
            'XDG_CACHE_HOME': str(self.root / 'parent-cache-sentinel'),
            'XDG_CONFIG_HOME': str(self.root / 'parent-config-sentinel'),
            'GH_CONFIG_DIR': str(self.root / 'parent-gh-sentinel'),
            'HOME': str(self.root / 'parent-home-sentinel'),
        }):
            probe = subprocess.run([isolation, '-rn', '--map-current-user', 'bash', '--noprofile', '--norc', '-c',
                                    'printf "%s\\n" "${BH_FIXTURE_UNRELATED_CREDENTIAL-unset}" '
                                    '"${XDG_DATA_HOME-unset}" "${XDG_CACHE_HOME-unset}" '
                                    '"${XDG_CONFIG_HOME-unset}" "${GH_CONFIG_DIR-unset}" "${HOME-unset}"'],
                                   env=env, capture_output=True, text=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout.splitlines(),
                         ['unset', str(self.root / 'xdg-data'), str(self.root / 'xdg-cache'),
                          str(self.root / 'xdg-config'), str(self.root / 'gh-config'), str(self.root / 'home')])
        self.assertNotIn(parent_secret, probe.stdout + probe.stderr)
        run = subprocess.run([isolation, '-rn', '--map-current-user', 'bash', '--noprofile', '--norc', '-c',
                              'source "$1"; bash --noprofile --norc -c \'printf %s "${DOCKER_CONFIG-unset}"\'',
                              'bash', str(script_file)], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, str(self.root / 'docker'))
        self.assertFalse((self.root / 'home/.docker').exists())
        default_script = self.wrapper.render(self.inputs, self.image)[0]['pre_launch_script']
        self.assertIn('/dstack/bh-registry/config.json', default_script)
        self.assertNotIn('/root/', default_script)
        self.assertNotIn(sentinel, run.stdout + run.stderr + json.dumps(app))
        def assert_private(path, mode):
            stat = path.stat()
            self.assertEqual(stat.st_mode & 0o777, mode, str(path))
            self.assertEqual((stat.st_uid, stat.st_gid),
                             (self.inputs['authz']['uid'], self.inputs['authz']['gid']), str(path))

        registry_file = self.root / 'docker/config.json'
        assert_private(registry_file, 0o600)
        assert_private(self.root / 'docker', 0o700)
        registry = json.loads(registry_file.read_text())['auths']
        self.assertEqual(list(registry), ['registry.invalid'])
        self.assertEqual(registry['registry.invalid']['auth'],
                         base64.b64encode((sentinel + ':' + sentinel).encode()).decode())
        assert_private(self.root / 'runtime', 0o700)
        assert_private(self.root / 'protected', 0o700)
        for name in self.wrapper.RUNTIME_FILES:
            file = self.root / 'runtime' / name
            self.assertEqual(file.read_bytes(), env[self.wrapper.RUNTIME_FILES[name]].encode())
            assert_private(file, 0o600)
        for missing in ('recovery_key', 'recovery_cert', 'policy'):
            absent_env = {**env}
            absent_env.pop(self.wrapper.RUNTIME_FILES[missing])
            failed = subprocess.run([isolation, '-rn', '--map-current-user', 'bash', '--noprofile', '--norc', str(script_file)],
                                    env=absent_env, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0, missing)
            self.assertIn('missing_' + missing, failed.stderr)
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
