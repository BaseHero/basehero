#!/usr/bin/env python3
"""Produce a Tauri updater manifest for the signed macOS app."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


def manifest(version, signature, notes, pub_date):
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version, re.ASCII):
        raise ValueError("version must be X.Y.Z")
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
