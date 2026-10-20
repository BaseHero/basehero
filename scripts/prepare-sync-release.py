#!/usr/bin/env python3
"""Local committed-source sync packaging. Never deploys or contacts a provider."""
import argparse
import hashlib
import io
import ipaddress
from urllib.parse import urlsplit
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

import sync_deployment

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fresh_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError('output must not exist')
    path.mkdir(parents=True)
    return path.resolve()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def export_source(product, commit, output):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('source must be an exact committed revision (40 lowercase hex characters)')
    if git(product, 'rev-parse', '--verify', commit + '^{commit}') != commit:
        raise ValueError('source is not a commit')
    prefix = git(product, 'rev-parse', '--show-prefix').rstrip('/')
    revision = commit + ':' + prefix if prefix else commit + '^{tree}'
    tree = git(product, 'rev-parse', revision)
    repository = git(product, 'rev-parse', '--show-toplevel')
    archive = subprocess.check_output(['git', '-C', repository, 'archive', revision])
    output = fresh_directory(output)
    source = output / 'source'
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        # Product source has no links. Refuse them rather than following a
        # future committed link out of the immutable source boundary.
        if any(not (entry.isfile() or entry.isdir()) for entry in tar):
            raise ValueError('source export contains unsupported entries')
        tar.extractall(source, filter='data')
    return {'source_commit': commit, 'product_tree': tree,
            'locks': {name: sha256(source / name) for name in ('Cargo.lock', 'flake.lock')}}


def hash_tree(root, prefix):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('artifact contains unsupported entries')
        if path.is_file():
            result[prefix + '/' + path.relative_to(root).as_posix()] = sha256(path)
    return result


def verify_artifacts(bundle, manifest):
    expected = manifest['artifacts']
    if not expected:
        raise ValueError('empty artifact manifest')
    actual = {}
    for name in expected:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or len(path.parts) < 2:
            raise ValueError('invalid artifact path')
    for top in {Path(name).parts[0] for name in expected}:
        directory = bundle / top
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('missing artifact directory')
        actual.update(hash_tree(directory, top))
    if actual != expected:
        raise ValueError('artifact hash or file set mismatch')


def object_keys(value, keys, where):
    if not isinstance(value, dict):
        raise ValueError('required operator object: ' + where)
    for key in keys:
        if key not in value:
            raise ValueError('required operator input: ' + where + '.' + key)
    if set(value) != set(keys):
        raise ValueError('unknown operator field in ' + where)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute_path(value):
    return (isinstance(value, str) and value.startswith('/') and value != '/' and
            all(ord(c) >= 32 for c in value) and '..' not in Path(value).parts and '$' not in value)


def https(value):
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return (parsed.scheme == 'https' and bool(parsed.hostname) and not parsed.username and
            not parsed.password and not parsed.query and not parsed.fragment and
            '$' not in value and all(c.isascii() and not c.isspace() for c in value))


def validate_inputs(value, preparation=False):
    object_keys(value, ('cloudflare', 'authz', 'endpoint'), 'inputs')
    cf, authz, endpoint = (value[k] for k in ('cloudflare', 'authz', 'endpoint'))
    object_keys(cf, ('account_id', 'name', 'route', 'bucket', 'receipt_key_binding', 'receipt_cert_file'), 'cloudflare')
    object_keys(authz, ('backends', 'image', 'image_id', 'archive_sha256', 'registry_manifest_file', 'protected_mount', 'uid', 'gid',
                        'quote_socket', 'files', 'roughtime', 'time_config'), 'authz')
    object_keys(endpoint, ('edge_url', 'hosting_root', 'app_root', 'policy', 'policy_signature',
                           'max_lifetime_secs', 'max_uncertainty_secs', 'build_floor', 'appraisal'), 'endpoint')
    # The Rust app parser is authoritative for endpoint fields. These early
    # transport guards also reject inputs before any private file is opened.
    require(endpoint['appraisal'] == 'hardware' and https(endpoint['edge_url']), 'endpoint requires hardware appraisal and HTTPS')
    require(isinstance(cf['account_id'], str) and re.fullmatch('[0-9a-f]{32}', cf['account_id']), 'cloudflare.account_id required')
    for key in ('name', 'bucket'):
        require(isinstance(cf[key], str) and re.fullmatch('[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', cf[key]), 'invalid cloudflare.' + key)
    object_keys(cf['route'], ('pattern', 'custom_domain'), 'cloudflare.route')
    require(cf['route']['custom_domain'] is True and
            cf['route']['pattern'] == urlsplit(endpoint['edge_url']).netloc and
            urlsplit(endpoint['edge_url']).path in ('', '/'),
            'route must be the endpoint custom domain (no path)')
    require(cf['receipt_key_binding'] == 'RECEIPT_KEY', 'required Worker secret binding: RECEIPT_KEY')
    require(absolute_path(cf['receipt_cert_file']), 'receipt certificate file required')
    require(isinstance(authz['backends'], list) and len(authz['backends']) > 0, 'authz.backends required')
    for backend in authz['backends']:
        object_keys(backend, ('url', 'ready'), 'authz.backends')
        require(https(backend['url']) and urlsplit(backend['url']).path == '/v1/channel' and
                type(backend['ready']) is bool, 'backends require explicit HTTPS channel URLs and readiness')
    require(any(b['ready'] for b in authz['backends']), 'at least one ready backend required')
    image = authz['image']
    require(isinstance(image, str) and
            (re.fullmatch(r'bh-authz:[a-z0-9-]+', image) or
             re.fullmatch(r'[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9/_.-]*@sha256:[0-9a-f]{64}', image)) and
            not image.endswith((':latest', ':local')) and
            (not preparation or '@sha256:' in image),
            'exact local tag or immutable registry image reference required')
    require(absolute_path(authz['registry_manifest_file']) if '@sha256:' in image else
            authz['registry_manifest_file'] is None, 'public registry manifest file required only for a registry reference')
    require(isinstance(authz['image_id'], str) and re.fullmatch('sha256:[0-9a-f]{64}', authz['image_id']), 'image config digest required')
    require(isinstance(authz['archive_sha256'], str) and re.fullmatch('[0-9a-f]{64}', authz['archive_sha256']), 'image archive hash required')
    for key in ('protected_mount', 'quote_socket'):
        require(absolute_path(authz[key]), 'required host path: authz.' + key)
    for key in ('uid', 'gid'):
        require(type(authz[key]) is int and 0 < authz[key] < 2**32 - 1, 'explicit non-root ' + key + ' required')
    object_keys(authz['files'], ('permit_key', 'permit_cert', 'policy', 'policy_signature', 'collateral'), 'authz.files')
    require(all(absolute_path(p) for p in authz['files'].values()), 'absolute runtime file references required')
    require(isinstance(authz['roughtime'], list) and len(authz['roughtime']) == 2, 'exactly two Roughtime pins required')
    for server in authz['roughtime']:
        object_keys(server, ('address', 'key'), 'authz.roughtime')
        require(isinstance(server['key'], str) and re.fullmatch('[0-9a-f]{64}', server['key']) and
                server['key'] != '0' * 64, 'Roughtime public key required')
        try:
            host, port = server['address'].rsplit(':', 1)
            ipaddress.ip_address(host.strip('[]'))
            require(0 < int(port) <= 65535, 'Roughtime port required')
        except (ValueError, AttributeError):
            raise ValueError('Roughtime requires a literal IP:port') from None
    require(authz['roughtime'][0]['key'] != authz['roughtime'][1]['key'] and
            authz['roughtime'][0]['address'] != authz['roughtime'][1]['address'], 'independent Roughtime pins required')
    time = authz['time_config']
    require(isinstance(time, list) and len(time) == 5 and
            all(type(n) is int and 0 <= n < 2**64 for n in time) and
            time[0] == 1000000000 and time[1] < 1000000 and time[3] > 0 and time[4] > 0,
            'qualified time_config [1000000000, drift_ppm, smear_us, max_age_ticks, max_width_ms] required')


def render(value, receipt_cert):
    cf, a, endpoint = (value[k] for k in ('cloudflare', 'authz', 'endpoint'))
    return {
        'endpoint.json': endpoint,
        'wrangler.json': {
            'name': cf['name'], 'account_id': cf['account_id'],
            'main': 'worker/services/sync-worker/src/edge.mjs', 'compatibility_date': '2026-07-01',
            'workers_dev': False, 'preview_urls': False, 'routes': [cf['route']],
            'vars': {'HOSTING_ROOT': endpoint['hosting_root'], 'RECEIPT_CERT': receipt_cert,
                     'AUTHZ_BACKENDS': json.dumps(a['backends'], separators=(',', ':'))},
            'rules': [{'type': 'CompiledWasm', 'globs': ['**/*.wasm']}],
            'durable_objects': {'bindings': [{'name': 'LOG', 'class_name': 'LogObject'},
                                             {'name': 'RELAY', 'class_name': 'PairingRelay'}]},
            'migrations': [{'tag': 'v1', 'new_sqlite_classes': ['LogObject', 'PairingRelay']}],
            'r2_buckets': [{'binding': 'BODIES', 'bucket_name': cf['bucket']}]}}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def logged(command, cwd, logs, name, env=None):
    with (logs / (name + '.stdout')).open('wb') as out, (logs / (name + '.stderr')).open('wb') as err:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=out, stderr=err)
    (logs / (name + '.exit')).write_text(str(result.returncode) + '\n')
    if result.returncode:
        raise ValueError('local build failed; inspect ' + name + '.stderr/.stdout/.exit')
    return (logs / (name + '.stdout')).read_text().strip()


def image_identity(archive):
    with tarfile.open(archive) as tar:
        entries = json.load(tar.extractfile('manifest.json'))
        require(len(entries) == 1 and len(entries[0]['RepoTags']) == 1, 'expected one local image')
        config = tar.extractfile(entries[0]['Config']).read()
        return {'reference': entries[0]['RepoTags'][0],
                'image_id': 'sha256:' + hashlib.sha256(config).hexdigest(),
                'archive_sha256': sha256(archive)}


def verify_image_reference(actual, authz):
    require((authz['image_id'], authz['archive_sha256']) ==
            (actual['image_id'], actual['archive_sha256']), 'operator image identity differs from bundle')
    if authz['image'] == actual['reference'] and authz['registry_manifest_file'] is None:
        return None
    require('@sha256:' in authz['image'] and absolute_path(authz['registry_manifest_file']),
            'operator image identity differs from bundle')
    raw = Path(authz['registry_manifest_file']).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    manifest = json.loads(raw)
    require(authz['image'].endswith('@sha256:' + digest) and manifest.get('schemaVersion') == 2 and
            manifest.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json',
                                          'application/vnd.docker.distribution.manifest.v2+json') and
            manifest.get('config', {}).get('digest') == actual['image_id'],
            'registry manifest digest/config differs from bundle')
    return digest


def build_release(commit, output):
    identity = export_source(ROOT, commit, output)
    output = output.resolve()
    source, logs = output / 'source', output / 'logs'
    logs.mkdir()
    # The driver itself must be the reviewed version; dirty source and ignored
    # artifacts are never inputs to the package builds.
    require(sha256(Path(__file__)) == sha256(source / 'scripts/prepare-sync-release.py'),
            'run the release builder from the requested committed version')
    authz = output / 'authz'
    authz.mkdir()
    paths = logged(['nix', 'build', 'path:.#authz', 'path:.#authz-image', '--no-link',
                    '--print-out-paths', '--cores', '4', '--max-jobs', '1', '-L'], source, logs, 'authz').splitlines()
    require(len(paths) == 2, 'expected authz package and image')
    package, image = map(Path, paths)
    shutil.copy2(package / 'bin/bh-authz', authz / 'bh-authz')
    shutil.copy2(image, authz / 'image.tar.gz')
    # Validator is a local packaging tool, not part of the runtime image.
    env = {**os.environ, 'CARGO_TARGET_DIR': str(Path(os.environ.get('CARGO_TARGET_DIR', output / 'target')).resolve()),
           'CARGO_BUILD_JOBS': '4', 'RUSTC_WRAPPER': ''}
    logged(['nix', 'develop', 'path:.', '--command', 'cargo', 'build', '--locked', '-p', 'bh-authz',
            '--example', 'sync-release-validator'], source, logs, 'validator', env)
    tools = output / 'tools'
    tools.mkdir()
    shutil.copy2(Path(env['CARGO_TARGET_DIR']) / 'debug/examples/sync-release-validator', tools / 'validate')
    # Capture the required Nix runtime closure for both the executable and
    # tooling. The image contains only the authz binary's closure plus CA roots.
    closure = logged(['nix-store', '-qR', str(package)], source, logs, 'closure')
    (authz / 'closure.txt').write_text(closure + '\n')
    worker_env = {**env, 'CARGO_TARGET_DIR': env['CARGO_TARGET_DIR'] + '/worker'}
    logged(['nix', 'develop', 'path:.#cryptoWorker', '--command', 'bash',
            'scripts/build-sync-worker-release.sh', str(output / 'worker')], source, logs, 'worker', worker_env)
    artifacts = {}
    for directory in ('authz', 'worker', 'tools'):
        artifacts.update(hash_tree(output / directory, directory))
    manifest = {'format': 1, **identity, 'artifacts': artifacts,
                'image': image_identity(authz / 'image.tar.gz'), 'public_config_sha256': None}
    write_json(output / 'manifest.json', manifest)
    verify_artifacts(output, manifest)
    print('local release bundle: ' + str(output))


def bundle_inputs(bundle, inputs, preparation):
    bundle = bundle.resolve()
    manifest = json.loads((bundle / 'manifest.json').read_text())
    require(manifest.get('format') == 1, 'unsupported bundle manifest')
    verify_artifacts(bundle, manifest)
    input_bytes = inputs.read_bytes()
    value = json.loads(input_bytes)
    validate_inputs(value, preparation=preparation)
    actual_image = image_identity(bundle / 'authz/image.tar.gz')
    require(actual_image == manifest['image'], 'bundle image identity mismatch')
    registry_digest = verify_image_reference(actual_image, value['authz'])
    return bundle, manifest, input_bytes, value, actual_image, registry_digest


def deployment_inputs(value):
    # Policy/signature arrive after measurement. Source FILE references are
    # local validation inputs, not VM paths or measured deployment settings.
    public = json.loads(json.dumps(value))
    for key in ('policy', 'policy_signature'):
        del public['endpoint'][key]
    del public['authz']['files']
    del public['authz']['registry_manifest_file']
    del public['cloudflare']['receipt_cert_file']
    return hashlib.sha256(sync_deployment.canonical(public)).hexdigest()


def prepare_deployment(bundle, inputs, output):
    bundle, manifest, input_bytes, value, actual_image, registry_digest = bundle_inputs(bundle, inputs, True)
    validation = subprocess.run([str(bundle / 'tools/validate'), 'prepare', '-'],
                                input=input_bytes, capture_output=True)
    require(validation.returncode == 0, 'Rust app endpoint preparation rejected inputs')
    app, candidate = sync_deployment.render(value, actual_image)
    output = fresh_directory(output)
    deployment = output / 'deployment'
    deployment.mkdir()
    write_json(deployment / 'app-compose.json', app)
    (deployment / 'compose.json').write_bytes(app['docker_compose_file'].encode('utf-8'))
    write_json(output / 'manifest.json', {
        'format': 1, 'source_commit': manifest['source_commit'], 'product_tree': manifest['product_tree'],
        'bundle_manifest_sha256': sha256(bundle / 'manifest.json'),
        'deployment_inputs_sha256': deployment_inputs(value),
        'image': actual_image, 'deployment_image': value['authz']['image'],
        'registry_manifest_sha256': registry_digest,
        'compose_sha256_candidate': candidate, 'artifacts': hash_tree(deployment, 'deployment')})
    verify_deployment(output, bundle, value)
    print('local deployment candidate: ' + candidate)


def verify_deployment(deployment, bundle=None, value=None):
    deployment = deployment.resolve()
    manifest = json.loads((deployment / 'manifest.json').read_text())
    require(manifest.get('format') == 1, 'unsupported deployment manifest')
    require({p.name for p in deployment.iterdir()} == {'manifest.json', 'deployment'},
            'unexpected deployment file')
    verify_artifacts(deployment, manifest)
    app = json.loads((deployment / 'deployment/app-compose.json').read_bytes())
    require(hashlib.sha256(sync_deployment.canonical(app)).hexdigest() == manifest['compose_sha256_candidate'] and
            (deployment / 'deployment/compose.json').read_bytes() == app['docker_compose_file'].encode('utf-8'),
            'deployment compose candidate mismatch')
    if bundle is not None and value is not None:
        bundle_manifest = json.loads((bundle / 'manifest.json').read_text())
        require(manifest['bundle_manifest_sha256'] == sha256(bundle / 'manifest.json') and
                manifest['source_commit'] == bundle_manifest['source_commit'] and
                manifest['product_tree'] == bundle_manifest['product_tree'] and
                manifest['deployment_inputs_sha256'] == deployment_inputs(value),
                'prepared deployment inputs or bundle differ')
        expected, candidate = sync_deployment.render(value, manifest['image'])
        require(app == expected and candidate == manifest['compose_sha256_candidate'] and
                manifest['deployment_image'] == value['authz']['image'],
                'prepared deployment differs from final inputs')
    return manifest


def verify_config(output):
    output = output.resolve()
    manifest = json.loads((output / 'manifest.json').read_text())
    require({p.name for p in output.iterdir()} == {'manifest.json', 'config'},
            'unexpected configuration file')
    verify_artifacts(output, manifest)
    require(manifest.get('public_config_sha256') == sha256(output / 'config/endpoint.json'),
            'endpoint differs from public config identity')
    return output / 'config/endpoint.json'


def configure(bundle, inputs, deployment, output):
    bundle, manifest, input_bytes, value, actual_image, registry_digest = bundle_inputs(bundle, inputs, False)
    require('@sha256:' in value['authz']['image'], 'final measured configuration requires immutable registry image')
    prepared = verify_deployment(deployment, bundle, value)
    require(prepared['image'] == actual_image and prepared['registry_manifest_sha256'] == registry_digest,
            'prepared image differs from bundle')
    # The Rust endpoint parser and signature/key/certificate authorities stay
    # strict. An approved signed checker build must pin the prepared candidate.
    validation = subprocess.run([str(bundle / 'tools/validate'), 'final', '-', prepared['compose_sha256_candidate']],
                                input=input_bytes, capture_output=True)
    require(validation.returncode == 0, 'Rust endpoint/policy/key/certificate/checker validation refused inputs')
    rendered = render(value, validation.stdout.decode().strip())
    output = fresh_directory(output)
    config = output / 'config'
    config.mkdir()
    for name, data in rendered.items():
        write_json(config / name, data)
    shutil.copyfile(deployment / 'deployment/compose.json', config / 'compose.json')
    shutil.copytree(bundle / 'worker', config / 'worker')
    write_json(output / 'manifest.json', {
        'format': 1, 'source_commit': manifest['source_commit'], 'product_tree': manifest['product_tree'],
        'bundle_manifest_sha256': sha256(bundle / 'manifest.json'),
        'deployment_manifest_sha256': sha256(deployment / 'manifest.json'),
        'compose_sha256_candidate': prepared['compose_sha256_candidate'],
        'operator_inputs_sha256': hashlib.sha256(input_bytes).hexdigest(),
        'public_config_sha256': sha256(config / 'endpoint.json'), 'image': actual_image,
        'deployment_image': value['authz']['image'],
        'registry_manifest_sha256': registry_digest, 'artifacts': hash_tree(config, 'config')})
    verify_config(output)
    print('local configuration: ' + str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    build = sub.add_parser('build')
    build.add_argument('--source', required=True)
    build.add_argument('--output', required=True, type=Path)
    prep = sub.add_parser('prepare-deployment')
    prep.add_argument('--bundle', required=True, type=Path)
    prep.add_argument('--inputs', required=True, type=Path)
    prep.add_argument('--output', required=True, type=Path)
    config = sub.add_parser('configure')
    config.add_argument('--bundle', required=True, type=Path)
    config.add_argument('--deployment', required=True, type=Path)
    config.add_argument('--inputs', required=True, type=Path)
    config.add_argument('--output', required=True, type=Path)
    verified = sub.add_parser('verify-config')
    verified.add_argument('--config', required=True, type=Path)
    compared = sub.add_parser('compare-provision')
    compared.add_argument('--deployment', required=True, type=Path)
    compared.add_argument('--response', required=True, type=Path)
    args = parser.parse_args()
    if args.operation == 'build':
        build_release(args.source, args.output)
    elif args.operation == 'prepare-deployment':
        prepare_deployment(args.bundle, args.inputs, args.output)
    elif args.operation == 'configure':
        configure(args.bundle, args.inputs, args.deployment, args.output)
    elif args.operation == 'verify-config':
        print(verify_config(args.config))
    else:
        prepared = verify_deployment(args.deployment)
        app = json.loads((args.deployment / 'deployment/app-compose.json').read_bytes())
        sync_deployment.compare_provider_response(app, prepared['compose_sha256_candidate'],
                                                  json.loads(args.response.read_bytes()))
        print('saved response matches local candidate; provider authenticity and hardware unverified')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        # Input values and dependency diagnostics can contain secrets. Commands
        # keep their complete local build logs separately; this is data-free.
        print('sync release failed: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
