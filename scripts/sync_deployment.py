"""Offline Phala dstack 0.5.9 AppComposeV2 candidate; never provisions a VM."""
import hashlib
import json
import shlex
from urllib.parse import urlsplit

RUNTIME_DIR = '/dstack/bh-authz-runtime'
REGISTRY_CONFIG_DIR = '/dstack/bh-registry'
RUNTIME_FILES = {
    'permit_key': 'BH_AUTHZ_PERMIT_KEY',
    'permit_cert': 'BH_AUTHZ_PERMIT_CERT',
    'policy': 'BH_AUTHZ_POLICY',
    'policy_signature': 'BH_AUTHZ_POLICY_SIGNATURE',
    'collateral': 'BH_AUTHZ_COLLATERAL',
}
REGISTRY_ENVS = ('DSTACK_DOCKER_REGISTRY', 'DSTACK_DOCKER_USERNAME', 'DSTACK_DOCKER_PASSWORD')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def bootstrap(authz, registry, runtime_dir=RUNTIME_DIR, registry_config_dir=REGISTRY_CONFIG_DIR):
    """Fixed measured recipe: no operator-supplied commands or secret values."""
    data = shlex.quote(authz['protected_mount'])
    runtime = shlex.quote(runtime_dir)
    uid_gid = shlex.quote(f"{authz['uid']}:{authz['gid']}")
    registry_dir = shlex.quote(registry_config_dir)
    registry_file = shlex.quote(registry_config_dir + '/config.json')
    registry_filter = shlex.quote(
        f'{{auths:{{{json.dumps(registry)}:{{auth:((env.DSTACK_DOCKER_USERNAME + ":" + env.DSTACK_DOCKER_PASSWORD) | @base64)}}}}}}')
    lines = [
        '#!/bin/bash', 'set +x', 'set -eu', 'umask 077',
        f"if [ \"${{DSTACK_DOCKER_REGISTRY-}}\" != {shlex.quote(registry)} ]; then echo registry_input_missing >&2; exit 1; fi",
        'if [ -z "${DSTACK_DOCKER_USERNAME-}" ] || [ -z "${DSTACK_DOCKER_PASSWORD-}" ]; then echo registry_credentials_missing >&2; exit 1; fi',
        # Standard Docker client credentials; neither credential enters argv.
        # Docker/dstack pull compatibility remains an operational qualification.
        f'if ! mkdir -p -m 700 -- {registry_dir} || ! chmod 700 -- {registry_dir}; then echo registry_config_unusable >&2; exit 1; fi',
        f'if ! ( umask 077; jq -n {registry_filter} > {registry_file} && chmod 600 -- {registry_file} ); then echo registry_config_unusable >&2; exit 1; fi',
        f'export DOCKER_CONFIG={registry_dir}',
        f'if [ -e {data} ]; then',
        f'  if [ ! -d {data} ] || [ "$(stat -c %u:%g -- {data})" != {uid_gid} ]; then echo data_directory_unusable >&2; exit 1; fi',
        'else',
        f'  if ! mkdir -p -m 700 -- {data} || ! chown {uid_gid} -- {data}; then echo data_directory_unusable >&2; exit 1; fi',
        'fi',
        f'if ! mkdir -p -m 700 -- {runtime} || ! chmod 700 -- {runtime} || ! chown {uid_gid} -- {runtime}; then echo runtime_directory_unusable >&2; exit 1; fi',
    ]
    for name, env in RUNTIME_FILES.items():
        target = shlex.quote(runtime_dir + '/' + name)
        # A shell environment cannot represent NUL; values otherwise retain
        # exact bytes (including trailing newlines) through the builtin printf.
        lines.extend([
            f'if [ -z "${{{env}-}}" ]; then echo missing_{name} >&2; exit 1; fi',
            f'if ! ( umask 077; printf %s "${{{env}}}" > {target} && chmod 600 -- {target} && chown {uid_gid} -- {target} ); then echo runtime_file_unusable >&2; exit 1; fi',
        ])
    lines.extend(['unset ' + ' '.join((*REGISTRY_ENVS, *RUNTIME_FILES.values())), ''])
    return '\n'.join(lines)


def render(inputs, image_identity, runtime_dir=RUNTIME_DIR, registry_config_dir=REGISTRY_CONFIG_DIR):
    """Compute a local candidate, never a verified hardware measurement."""
    a, endpoint = inputs['authz'], inputs['endpoint']
    if '@sha256:' not in a['image']:
        raise ValueError('measured deployment requires immutable registry image')
    registry = a['image'].split('/', 1)[0]
    if registry in ('', 'localhost'):
        raise ValueError('registry host required')
    def mount(source, target, read_only=True):
        return {'type': 'bind', 'source': source, 'target': target, 'read_only': read_only,
                'bind': {'create_host_path': False}}
    command = ['--listen', '0.0.0.0:7801', '--db', '/data/authz.sqlite',
               '--edge', 'wss://' + urlsplit(endpoint['edge_url']).netloc + '/v1/data',
               '--hosting-root', endpoint['hosting_root'], '--app-root', endpoint['app_root'],
               '--quote-socket', '/run/quote.sock', '--time-config', ','.join(map(str, a['time_config']))]
    volumes = [mount(a['protected_mount'], '/data', False), mount(a['quote_socket'], '/run/quote.sock')]
    for name in RUNTIME_FILES:
        target = '/run/config/' + name
        volumes.append(mount(runtime_dir + '/' + name, target))
        command.extend(['--' + name.replace('_', '-'), target])
    for server in a['roughtime']:
        command.extend(['--roughtime', server['address'] + '=' + server['key']])
    compose = {'services': {'authz': {
        'image': a['image'], 'pull_policy': 'missing', 'user': f"{a['uid']}:{a['gid']}",
        'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'logging': {'driver': 'none'}, 'ulimits': {'core': {'soft': 0, 'hard': 0}},
        # All CVM interfaces: the dstack gateway connects to the CVM's WireGuard
        # address, never its loopback.
        'ports': ['7801:7801'], 'volumes': volumes, 'command': command,
        'restart': 'unless-stopped'}}}
    # Sorted compact JSON is the provision API's dstack 0.5.9 canonicalization,
    # not the four-space serialization of the JS SDK. A later provider response
    # MUST be compared, not adopted as a replacement candidate.
    app = {
        'manifest_version': 2, 'name': '', 'runner': 'docker-compose',
        'features': ['kms', 'tproxy-net'], 'tproxy_enabled': True,
        'no_instance_id': False, 'storage_fs': 'zfs',
        'pre_launch_script': bootstrap(a, registry, runtime_dir, registry_config_dir),
        'docker_compose_file': canonical(compose).decode('utf-8'),
        'kms_enabled': True, 'gateway_enabled': True, 'local_key_provider_enabled': False,
        'public_logs': False, 'public_sysinfo': False, 'public_tcbinfo': False,
        'secure_time': False,
        'allowed_envs': [*REGISTRY_ENVS, *RUNTIME_FILES.values()],
    }
    return app, hashlib.sha256(canonical(app)).hexdigest()


def compare_provider_response(candidate, expected_hash, response):
    """Compare saved, unauthenticated JSON only. No provider calls or trust transfer."""
    if (not isinstance(response, dict) or response.get('compose_hash') != expected_hash or
            ('compose_file' in response and response['compose_file'] != candidate)):
        raise ValueError('saved provider compose differs from local candidate')
