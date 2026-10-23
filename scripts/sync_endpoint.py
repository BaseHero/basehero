#!/usr/bin/env python3
"""Snapshot a public app endpoint; build.rs remains its authoritative parser."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def prepare_endpoint(source, local_only, output, environment):
    env = {key: value for key, value in environment.items() if key != 'BH_SYNC_ENDPOINT'}
    if (source is None) == (not local_only):
        raise ValueError('choose exactly one of --sync-endpoint FILE or --local-only')
    if local_only:
        return env, {'mode': 'local-only'}
    raw = Path(source).read_bytes()
    # Early, data-free transport/mode refusal, and the home's recovery-key
    # certificate must be there. Rust build.rs checks all ten fields, their
    # types and the certificate's root; this is not an alternate endpoint
    # authority.
    try:
        value = json.loads(raw)
        valid = (value['appraisal'] == 'hardware' and value['edge_url'].startswith('https://')
                 and isinstance(value['recovery_key'], str) and value['recovery_key'] != '')
    except (ValueError, KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError('a nonempty hardware/HTTPS endpoint JSON file with its recovery key is required')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    snapshot = output / 'sync-endpoint.json'
    with snapshot.open('xb') as stream:
        stream.write(raw)
    env['BH_SYNC_ENDPOINT'] = str(snapshot)
    return env, {'mode': 'configured', 'sha256': hashlib.sha256(raw).hexdigest()}


def record_endpoint(output, proof, artifact):
    with Path(artifact).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    (Path(output) / 'sync-endpoint-provenance.json').write_text(json.dumps(
        {'endpoint': proof, 'artifact': Path(artifact).name, 'artifact_sha256': digest},
        indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--sync-endpoint', type=Path)
    mode.add_argument('--local-only', action='store_true')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('build command required')
    try:
        env, proof = prepare_endpoint(args.sync_endpoint, args.local_only, args.output, os.environ)
        subprocess.run(command, env=env, check=True)
        args.output.mkdir(parents=True, exist_ok=True)
        record_endpoint(args.output, proof, args.artifact)
    except (ValueError, OSError, subprocess.CalledProcessError):
        parser.exit(1, 'endpoint build handoff failed; no release provenance written\n')


if __name__ == '__main__':
    main()
