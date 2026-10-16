"""mac_sign with a recording stand-in for rcodesign; real signatures are checked on a Mac."""
import importlib.util
import io
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("mac_sign.py")
spec = importlib.util.spec_from_file_location("mac_sign", SCRIPT)
sign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign)

# Records its arguments and marks every Mach-O it would sign.
FAKE = """#!/usr/bin/env python3
import json, os, pathlib, sys
open(os.environ['BH_TEST_LOG'], 'a').write(json.dumps(sys.argv[1:]) + '\\n')
if os.environ.get('BH_TEST_FAIL'):
    sys.exit(1)
app = pathlib.Path(sys.argv[-1])
for name in ('bh-client', 'bh-keychain-helper'):
    path = app / 'Contents/MacOS' / name
    path.write_bytes(path.read_bytes() + b' signed')
"""


class MacSignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.tool = self.root / "rcodesign"
        self.tool.write_text(FAKE)
        self.tool.chmod(0o755)
        self.log = self.root / "log"
        self.key, self.cert = self.root / "key.pem", self.root / "cert.pem"
        self.key.write_text("-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n")
        self.cert.write_text("-----BEGIN CERTIFICATE-----\n")
        os.environ["BH_TEST_LOG"] = str(self.log)
        self.addCleanup(os.environ.pop, "BH_TEST_LOG", None)

    def archive(self, extra=None, helper=True, identifier="app.basehero.client.updatedemo"):
        path = self.root / f"in-{len(list(self.root.iterdir()))}.tar.gz"
        files = {
            "BaseHero.app/Contents/Info.plist": plistlib.dumps({"CFBundleIdentifier": identifier, "CFBundleExecutable": "bh-client"}),
            "BaseHero.app/Contents/MacOS/bh-client": b"app",
        }
        if helper:
            files["BaseHero.app/Contents/MacOS/bh-keychain-helper"] = b"helper"
        with tarfile.open(path, "w:gz") as tar:
            for directory in ("BaseHero.app", "BaseHero.app/Contents", "BaseHero.app/Contents/MacOS"):
                info = tarfile.TarInfo(directory)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
            for info in extra or []:
                tar.addfile(info, io.BytesIO(b"x" * info.size) if info.isfile() else None)
        return path

    def run_script(self, source, output, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), str(source), str(output), "--rcodesign", str(self.tool),
                               "--key", str(self.key), "--certificate", str(self.cert)],
                              capture_output=True, text=True, env={**os.environ, **(env or {})})

    def test_signs_helper_with_its_own_identity_then_rearchives(self):
        output = self.root / "signed.tar.gz"
        result = self.run_script(self.archive(), output)
        self.assertEqual(result.returncode, 0, result.stderr)
        [args] = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(args[0], "sign")
        pairs = dict(zip(args[1:-1:2], args[2:-1:2]))
        self.assertEqual(pairs["--code-signature-flags"], "Contents/MacOS/bh-keychain-helper:runtime")
        self.assertEqual(pairs["--binary-identifier"], "Contents/MacOS/bh-keychain-helper:app.basehero.client.updatedemo.keychain-helper")
        self.assertEqual(pairs["--timestamp-url"], "none", "no call to Apple's timestamp server")
        self.assertEqual(sorted(a for i, a in enumerate(args) if args[i - 1] == "--pem-file"), sorted([str(self.key), str(self.cert)]))
        self.assertTrue(args[-1].endswith("/BaseHero.app"))
        with tarfile.open(output, "r:gz") as tar:
            self.assertEqual(tar.extractfile("BaseHero.app/Contents/MacOS/bh-keychain-helper").read(), b"helper signed")
            self.assertEqual(tar.extractfile("BaseHero.app/Contents/MacOS/bh-client").read(), b"app signed")
            self.assertTrue(all(m.uid == 0 and m.uname == "" for m in tar.getmembers()), "deterministic packager archive")
        self.assertNotIn("SECRETKEYMATERIAL", result.stdout + result.stderr)

    def test_refuses_bundles_it_must_not_sign(self):
        link = tarfile.TarInfo("BaseHero.app/Contents/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        escape = tarfile.TarInfo("BaseHero.app/../escape")
        escape.size = 1
        other = tarfile.TarInfo("Other.app")
        other.type = tarfile.DIRTYPE
        cases = [self.archive([link]), self.archive([escape]), self.archive([other]),
                 self.archive(helper=False), self.archive(identifier="App.BaseHero")]
        for index, source in enumerate(cases):
            output = self.root / f"refused-{index}.tar.gz"
            with self.subTest(index=index):
                result = self.run_script(source, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
        self.assertFalse((self.root / "escape").exists())

    def test_a_failed_signature_writes_nothing_and_never_prints_the_key(self):
        output = self.root / "signed.tar.gz"
        result = self.run_script(self.archive(), output, {"BH_TEST_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertNotIn("SECRETKEYMATERIAL", result.stdout + result.stderr)
        existing = self.root / "existing.tar.gz"
        existing.write_bytes(b"keep")
        self.assertNotEqual(self.run_script(self.archive(), existing).returncode, 0)
        self.assertEqual(existing.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
