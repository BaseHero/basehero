#!/usr/bin/env python3
"""Sign a packaged app with rcodesign, preserving the helper's stable identity."""
import argparse
import importlib.util
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tarfile
import tempfile

_spec = importlib.util.spec_from_file_location("mac_package", Path(__file__).with_name("mac_package.py"))
package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(package)
HELPER = "Contents/MacOS/" + package.HELPER


def extract(archive, directory):
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            parts = member.name.split("/")
            if parts[0] != package.BUNDLE or ".." in parts or not (member.isdir() or member.isfile()):
                raise ValueError(f"unexpected archive entry: {member.name}")
        tar.extractall(directory, members=members, filter="data")
    return directory / package.BUNDLE


def sign_archive(source, output, rcodesign, key, certificate):
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    with tempfile.TemporaryDirectory() as work:
        app = extract(source, Path(work))
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != "app.basehero" or not (app / HELPER).is_file():
            raise ValueError("unexpected app identifier or missing Keychain helper")
        package.verify_helper((app / HELPER).read_bytes())
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or Path(executable).name != executable or not (app / "Contents/MacOS" / executable).is_file():
            raise ValueError("missing app executable")
        # Scoped flags apply only to the helper; its cdhash stays stable across updates.
        subprocess.run([
            str(rcodesign), "sign", "--pem-file", str(key), "--pem-file", str(certificate),
            "--timestamp-url", "none", "--code-signature-flags", f"{HELPER}:runtime",
            "--binary-identifier", f"{HELPER}:app.basehero.keychain-helper", str(app),
        ], check=True)
        for binary in (app / "Contents/MacOS" / executable, app / HELPER):
            subprocess.run([str(rcodesign), "verify", str(binary)], check=True)
        result = subprocess.run(
            [str(rcodesign), "print-signature-info", str(app / HELPER)],
            check=True, stdout=subprocess.PIPE, text=True,
        )
        identifiers = re.findall(r"(?m)^[ \t]+identifier: ([^\s]+)[ \t]*$", result.stdout)
        if identifiers != ["app.basehero.keychain-helper"]:
            raise ValueError("Keychain helper signing identifier mismatch")
        package.archive_bundle(app, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--rcodesign", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    args = parser.parse_args()
    sign_archive(args.archive, args.out, args.rcodesign, args.key, args.certificate)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        print("mac signing failed: rcodesign refused the bundle", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, tarfile.TarError) as error:
        print(f"mac signing failed: {error}", file=sys.stderr)
        sys.exit(1)
