#!/usr/bin/env python3
"""Sign a packaged BaseHero.app archive with the app-signing certificate.

Runs wherever `rcodesign` runs, Linux included, from a PEM key and
certificate; no keychain. rcodesign signs the nested Mach-O files, the
Keychain helper with the hardened runtime and its own identifier, then seals
the app. The output is a new deterministic archive; the key is never printed.
"""
import argparse
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile

_spec = importlib.util.spec_from_file_location("mac_package", Path(__file__).with_name("mac_package.py"))
package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(package)

HELPER = "Contents/MacOS/" + package.HELPER


def extract(archive, directory):
    """Unpack only BaseHero.app's own directories and regular files."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            parts = member.name.split("/")
            if parts[0] != package.BUNDLE or ".." in parts or not (member.isdir() or member.isfile()):
                raise ValueError(f"unexpected archive entry: {member.name}")
        tar.extractall(directory, members=members, filter="data")
    return directory / package.BUNDLE


def sign_bundle(app, rcodesign, key, certificate):
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    identifier = package.bundle_identifier(info.get("CFBundleIdentifier", ""))
    if not (app / HELPER).is_file():
        raise ValueError("bundle has no Keychain helper")
    # The helper's signature depends only on its bytes, these settings, the
    # certificate and the rcodesign version, so an unchanged helper keeps its
    # cdhash. Scoped settings apply to the helper alone.
    subprocess.run([
        str(rcodesign), "sign",
        "--pem-file", str(key), "--pem-file", str(certificate),
        "--timestamp-url", "none",
        "--code-signature-flags", f"{HELPER}:runtime",
        "--binary-identifier", f"{HELPER}:{identifier}.keychain-helper",
        str(app),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def sign_archive(source, output, rcodesign, key, certificate):
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    with tempfile.TemporaryDirectory() as work:
        app = extract(source, Path(work))
        sign_bundle(app, rcodesign, key, certificate)
        package.archive_bundle(app, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="packaged BaseHero-macos-aarch64.app.tar.gz")
    parser.add_argument("output", type=Path, help="signed archive to create")
    parser.add_argument("--rcodesign", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path, help="PEM private key")
    parser.add_argument("--certificate", required=True, type=Path, help="PEM certificate")
    args = parser.parse_args()
    sign_archive(args.archive, args.output.resolve(), args.rcodesign, args.key, args.certificate)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        print("mac signing failed: rcodesign refused the bundle", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, tarfile.TarError) as error:
        print(f"mac signing failed: {error}", file=sys.stderr)
        sys.exit(1)
