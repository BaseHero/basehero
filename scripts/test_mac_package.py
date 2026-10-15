"""Portable fixtures for the Mac packaging boundary (not a native signature test)."""
import importlib.util
import pathlib
import plistlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("mac_package.py")
spec = importlib.util.spec_from_file_location("mac_package", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class MacPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.app = self.root / "BaseHero.app"
        (self.app / "Contents" / "MacOS").mkdir(parents=True)
        (self.app / "Contents" / "MacOS" / "bh-client").write_bytes(b"binary")
        self.plist = self.app / "Contents" / "Info.plist"
        self.plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "app.basehero.client", "CFBundleVersion": "42", "CFBundleExecutable": "bh-client"}))

    def test_canonical_release_number(self):
        for value in ("", "0", "00", "01", "-1", "1.0", "+1", "18446744073709551616"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                package.release_number(value)
        self.assertEqual(package.release_number("18446744073709551615"), 18446744073709551615)

    def test_bundle_validation_rejects_links_identity_and_version(self):
        with mock.patch.object(package, "inspect_macho", return_value=False):
            package.validate_bundle(self.app, 42)
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 43)
            info = plistlib.loads(self.plist.read_bytes())
            info["CFBundleIdentifier"] = "app.other.client"
            self.plist.write_bytes(plistlib.dumps(info))
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 42)
            info["CFBundleIdentifier"] = "app.basehero.client"
            self.plist.write_bytes(plistlib.dumps(info))
            (self.app / "Contents" / "shared").symlink_to("/usr/lib")
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 42)

    def test_only_in_bundle_links_are_materialized(self):
        target = self.app / "Contents" / "MacOS" / "bh-client"
        alias = target.parent / "alias"
        alias.symlink_to("bh-client")
        package.materialize_links(self.app)
        self.assertFalse(alias.is_symlink())
        self.assertEqual(alias.read_bytes(), target.read_bytes())
        alias.unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"EXTERNAL PRIVATE BYTES")
        alias.symlink_to(outside)
        with self.assertRaises(ValueError):
            package.materialize_links(self.app)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve().read_bytes(), b"EXTERNAL PRIVATE BYTES")
        self.assertEqual(target.read_bytes(), b"binary")

    def test_external_macho_dependency_and_rpath_refused(self):
        # Fixtures stub the host-only `file`/`otool` calls; native build inspects real files.
        with mock.patch.object(package, "inspect_macho", side_effect=lambda path: path.name == "bh-client"), mock.patch.object(package, "run", return_value="arm64"), mock.patch.object(package, "macho_loads", return_value=(["/nix/store/libiconv.2.dylib"], [])):
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 42)
        with mock.patch.object(package, "inspect_macho", side_effect=lambda path: path.name == "bh-client"), mock.patch.object(package, "run", return_value="arm64"), mock.patch.object(package, "macho_loads", return_value=(["/usr/lib/libSystem.B.dylib"], ["/opt/external-build"])):
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 42)

    def test_tracked_private_subtree_and_public_root_refused_but_nested_export_allowed(self):
        repo = self.root / "checkout"
        private = repo / "basehero"
        public = self.root / "public"
        export = repo / "export"
        for root in (private, public, export):
            (root / "scripts").mkdir(parents=True)
            (root / "scripts" / "mac_package.py").write_text("# script\n")
            (root / "Cargo.lock").touch()
        for git_root in (repo, public):
            subprocess.run(["git", "init", "-q", str(git_root)], check=True)
            subprocess.run(["git", "-C", str(git_root), "add", "--", "basehero/scripts/mac_package.py" if git_root == repo else "scripts/mac_package.py"], check=True)
        with mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "run", side_effect=RuntimeError("build reached")):
            for root in (private, public):
                with self.subTest(root=root), mock.patch.object(package, "ROOT", root), self.assertRaisesRegex(ValueError, "source-only export"):
                    package.build(42, self.root / "out")
            with mock.patch.object(package, "ROOT", export), self.assertRaisesRegex(RuntimeError, "build reached"):
                package.build(42, self.root / "out")

    def test_current_target_bundle_selected_without_old_default_fallback(self):
        export = self.root / "export"
        (export / "apps" / "client" / "src-tauri").mkdir(parents=True)
        (export / "Cargo.lock").touch()
        (export / "scripts").mkdir()
        shutil.copyfile(SCRIPT.with_name("check-webdriver-markers.mjs"), export / "scripts" / "check-webdriver-markers.mjs")
        old = export / "target" / "release" / "bundle" / "macos" / "BaseHero.app"
        current = export / "target" / "mac-package" / "aarch64-apple-darwin" / "release" / "bundle" / "macos" / "BaseHero.app"
        for app, payload in ((old, b"OLD COMMIT"), (current, b"PREVIOUS PACKAGE")):
            (app / "Contents" / "MacOS").mkdir(parents=True)
            (app / "Contents" / "Info.plist").write_bytes(self.plist.read_bytes())
            (app / "Contents" / "MacOS" / "bh-client").write_bytes(payload)
        tools = self.root / "bin"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text("#!/usr/bin/env python3\nimport os, pathlib, plistlib, sys\n"
                         "args=sys.argv[1:]\nassert args[:2] == ['tauri','build']\n"
                         "assert args[args.index('--target')+1] == 'aarch64-apple-darwin'\n"
                         "assert args[-2:] == ['--', '--locked']\n"
                         "assert os.environ.get('CARGO_BUILD_TARGET') == 'aarch64-apple-darwin'\n"
                         "app=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'aarch64-apple-darwin/release/bundle/macos/BaseHero.app'\n"
                         "assert not app.exists(), 'old selected output was not cleared'\n"
                         "(app/'Contents/MacOS').mkdir(parents=True)\n"
                         "(app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'app.basehero.client','CFBundleVersion':'0.1.0','CFBundleExecutable':'bh-client'}))\n"
                         "(app/'Contents/MacOS/bh-client').write_bytes(b'CURRENT COMMIT' + (b' tauri_plugin_webdriver' if os.environ.get('BH_TEST_INJECT_WEBDRIVER') else b''))\n")
        cargo.chmod(0o755)
        codesign = tools / "codesign"
        codesign.write_text("#!/bin/sh\nexit 0\n")
        codesign.chmod(0o755)
        output = self.root / "out"
        env = {"PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "CARGO_TARGET_DIR": str(self.root / "inherited-target"),
               "CARGO_BUILD_TARGET": "x86_64-apple-darwin"}
        with mock.patch.dict(os.environ, env), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            package.build(42, output)
        with tarfile.open(output / package.NAME, "r:gz") as archive:
            self.assertEqual(archive.extractfile("BaseHero.app/Contents/MacOS/bh-client").read(), b"CURRENT COMMIT")
        self.assertEqual((old / "Contents" / "MacOS" / "bh-client").read_bytes(), b"OLD COMMIT")
        # The next successful fake Cargo build includes a real marker in the
        # selected executable. Run the actual landed Node checker, not a stub.
        rejected = self.root / "rejected"
        with mock.patch.dict(os.environ, {**env, "BH_TEST_INJECT_WEBDRIVER": "1"}), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            with self.assertRaises(subprocess.CalledProcessError):
                package.build(43, rejected)
        self.assertFalse((rejected / package.NAME).exists())
        self.assertIn(b"tauri_plugin_webdriver", (current / "Contents" / "MacOS" / "bh-client").read_bytes())

    def test_archive_entries_are_real_files_and_relative(self):
        with mock.patch.object(package, "inspect_macho", return_value=False):
            output = self.root / "BaseHero-macos-aarch64.app.tar.gz"
            package.archive_bundle(self.app, output)
            with tarfile.open(output, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual(members[0].name, "BaseHero.app")
                self.assertTrue(all(m.isdir() or m.isfile() for m in members))
                self.assertTrue(all(m.name == "BaseHero.app" or m.name.startswith("BaseHero.app/") for m in members))
                self.assertTrue(any(m.name.endswith("/Info.plist") for m in members))


if __name__ == "__main__":
    unittest.main()
