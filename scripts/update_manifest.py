#!/usr/bin/env python3
"""Produce a Tauri updater manifest for the signed macOS app."""
import argparse
import base64
import binascii
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def manifest(version, signature, notes, pub_date):
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version, re.ASCII):
        raise ValueError("version must be X.Y.Z")
    # The release job runs with the signing key, but the manifest is unsigned.
    # Refuse to publish a version that differs from the signer's trusted comment.
    try:
        lines = base64.b64decode(signature, validate=True).decode("utf-8").splitlines()
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("signature must be base64-encoded minisign text") from exc
    if len(lines) != 4 or not lines[2].startswith("trusted comment: "):
        raise ValueError("signature must contain a signed version")
    comment = lines[2][len("trusted comment: "):]
    signed_versions = [
        field.removeprefix("version:")
        for field in comment.split("\t")
        if field.startswith("version:")
    ]
    if signed_versions != [version]:
        raise ValueError("signed version must equal manifest version")
    return {
        "version": version,
        "notes": notes,
        "pub_date": pub_date,
        "platforms": {
            "darwin-aarch64": {
                "signature": signature,
                "url": f"https://github.com/BaseHero/basehero/releases/download/v{version}/BaseHero-{version}-macos-arm64.app.tar.gz",
            }
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--notes", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    document = manifest(args.version, args.signature.read_text().strip(), args.notes,
                        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    args.out.write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
