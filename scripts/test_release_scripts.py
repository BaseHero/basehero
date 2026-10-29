"""Release packaging contracts; no credentials or network required."""
import base64
import hashlib
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import mac_package, mac_sign
from scripts.mac_package import check_loads, verify_helper
from scripts.update_manifest import manifest


def fixture_signature(version):
    # This fixture exercises the release script's parsing, not cryptography.
    # The updater's signature verification is exercised separately in Rust.
    comment = f"timestamp:1\tfile:archive\tversion:{version}"
    return base64.b64encode(f"untrusted comment: test\nbytes\ntrusted comment: {comment}\nbytes\n".encode()).decode()


class ReleaseScriptsTests(unittest.TestCase):
    def test_manifest_points_at_this_release(self):
        signature = fixture_signature("0.1.3")
        m = manifest("0.1.3", signature=signature, notes="n", pub_date="2026-10-28T00:00:00Z")
        self.assertEqual(m["version"], "0.1.3")
        self.assertEqual(m["platforms"]["darwin-aarch64"], {
            "signature": signature,
            "url": "https://github.com/BaseHero/basehero/releases/download/v0.1.3/BaseHero-0.1.3-macos-arm64.app.tar.gz",
        })
        self.assertEqual(m["pub_date"], "2026-10-28T00:00:00Z")
        self.assertEqual(m["notes"], "n")

    def test_a_version_must_be_x_y_z(self):
        for version in ("1.2", "v1.2.3", "01.2.3", "1.2.3/evil"):
            with self.subTest(version=version):
                self.assertRaises(ValueError, manifest, version, fixture_signature("0.1.3"), "n", "d")

    def test_manifest_refuses_an_older_signed_archive_offered_as_newer(self):
        with self.assertRaisesRegex(ValueError, "signed version"):
            manifest("0.1.4", fixture_signature("0.1.3"), "n", "d")

    def test_manifest_refuses_a_signature_without_a_version(self):
        unsigned_version = base64.b64encode(
            b"untrusted comment: test\nbytes\ntrusted comment: timestamp:1\tfile:archive\nbytes\n"
        ).decode()
        with self.assertRaisesRegex(ValueError, "signed version"):
            manifest("0.1.4", unsigned_version, "n", "d")

    def test_a_changed_helper_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "bh-keychain-helper"
            sums = Path(tmp) / "SHA256SUMS"
            helper.write_bytes(b"canonical bytes")
            sums.write_text(f"{hashlib.sha256(helper.read_bytes()).hexdigest()}  bh-keychain-helper\n")
            verify_helper(b"canonical bytes", sums)
            self.assertRaisesRegex(ValueError, "SHA256SUMS", verify_helper, b"other bytes", sums)

    def test_loads_outside_the_system_are_refused(self):
        check_loads(["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/AppKit.framework/AppKit"])
        self.assertRaises(ValueError, check_loads, ["/usr/lib/libSystem.B.dylib", "/nix/store/x-libsodium/lib/libsodium.26.dylib"])
        self.assertRaises(ValueError, check_loads, ["@rpath/libfoo.dylib"])

    def make_archive(self, directory, helper_bytes):
        app = directory / mac_package.BUNDLE
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "app.basehero", "CFBundleExecutable": "basehero",
        }))
        (app / "Contents/MacOS/basehero").write_bytes(b"main executable")
        (app / mac_sign.HELPER).write_bytes(helper_bytes)
        archive = directory / "unsigned.tar.gz"
        mac_package.archive_bundle(app, archive)
        return archive

    def test_mac_sign_refuses_changed_helper_before_using_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = self.make_archive(directory, b"tampered helper")
            with mock.patch.object(mac_sign.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "SHA256SUMS"):
                    mac_sign.sign_archive(archive, directory / "signed.tar.gz", "rcodesign", "key", "cert")
                run.assert_not_called()

    def test_mac_sign_verifies_both_binaries_and_helper_identifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = self.make_archive(directory, (mac_package.HELPER_DIR / mac_package.HELPER).read_bytes())
            def rcodesign(args, **kwargs):
                if args[1] == "print-signature-info":
                    return subprocess.CompletedProcess(args, 0, "  identifier: app.basehero.keychain-helper\n", "")
                return subprocess.CompletedProcess(args, 0)
            with mock.patch.object(mac_sign.subprocess, "run", side_effect=rcodesign) as run:
                mac_sign.sign_archive(archive, directory / "signed.tar.gz", "rcodesign", "key", "cert")
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual([command[1] for command in commands], [
                    "sign", "verify", "verify", "print-signature-info",
                ])
                self.assertEqual([Path(command[2]).name for command in commands[1:3]], [
                    "basehero", mac_package.HELPER,
                ])
                self.assertTrue((directory / "signed.tar.gz").is_file())

    def test_updater_signer_uses_env_key_not_conflicting_file_option(self):
        workflow = (mac_package.ROOT.parent / ".github/workflows/app-release.yml").read_text()
        self.assertIn('"$RUNNER_TEMP/cargo-tauri" signer sign --app-version "$VERSION" "signed/$archive"', workflow)
        self.assertNotIn("signer sign -f", workflow)

    def test_mac_sign_refuses_wrong_helper_identifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = self.make_archive(directory, (mac_package.HELPER_DIR / mac_package.HELPER).read_bytes())
            def rcodesign(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, "  identifier: app.basehero.other\n", "")
            with mock.patch.object(mac_sign.subprocess, "run", side_effect=rcodesign):
                with self.assertRaisesRegex(ValueError, "identifier mismatch"):
                    mac_sign.sign_archive(archive, directory / "signed.tar.gz", "rcodesign", "key", "cert")
            self.assertFalse((directory / "signed.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
