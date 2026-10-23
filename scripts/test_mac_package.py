"""Portable fixtures for the Mac packaging boundary (not a native signature test)."""
import hashlib
import importlib.util
import json
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
ROOT_SHA1 = "0ce10d31b5a12378c8bb85527be3a8e0a5a52ea7"
# Fake `cargo build` for the Keychain helper: records its environment and
# writes the binary where the packager expects it.
FAKE_HELPER_BUILD = (
    "if args[0] == 'build':\n"
    "    import json\n"
    "    out=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'aarch64-apple-darwin/keychain-helper'\n"
    "    out.mkdir(parents=True, exist_ok=True)\n"
    "    (out/'bh-keychain-helper').write_bytes(b'HELPER ' + os.environ['BH_APP_IDENTIFIER'].encode())\n"
    "    keys=['BH_APP_IDENTIFIER','BH_KEYCHAIN_CALLER_ROOT','RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR','CARGO_ENCODED_RUSTFLAGS']\n"
    "    record={'args': args, 'env': {k: os.environ.get(k) for k in keys}}\n"
    "    open(os.environ['BH_TEST_LOG'], 'a').write(json.dumps(record) + '\\n')\n"
    "    sys.exit(0)\n"
)
spec = importlib.util.spec_from_file_location("mac_package", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class MacPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        # The fake Cargo builder emits these canonical bytes for the pin build.
        # Only a real Mac build supplies the committed production pin.
        fake_pin = hashlib.sha256(b"HELPER app.basehero.client").hexdigest()
        patch = mock.patch.object(package, "EXPECTED_HELPER_SHA256", fake_pin, create=True)
        patch.start()
        self.addCleanup(patch.stop)
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
                    package.build(42, self.root / "out", signing_root=ROOT_SHA1, local_only=True)
            with mock.patch.object(package, "ROOT", export), self.assertRaisesRegex(RuntimeError, "build reached"):
                package.build(42, self.root / "out", signing_root=ROOT_SHA1, local_only=True)

    def test_current_target_bundle_selected_without_old_default_fallback(self):
        export = self.root / "export"
        (export / "apps" / "client" / "src-tauri" / "src").mkdir(parents=True)
        (export / "apps" / "client" / "src-tauri" / "src" / "eff_large_wordlist-LICENSE.md").write_text("EFF attribution and CC BY 4.0\n")
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
                         "args=sys.argv[1:]\n" + FAKE_HELPER_BUILD + "assert args[:2] == ['tauri','build']\n"
                         "assert args[args.index('--target')+1] == 'aarch64-apple-darwin'\n"
                         "assert args[-2:] == ['--', '--locked']\n"
                         "assert os.environ.get('CARGO_BUILD_TARGET') == 'aarch64-apple-darwin'\n"
                         "assert pathlib.Path(os.environ['BH_SYNC_ENDPOINT']).read_bytes() == pathlib.Path(os.environ['BH_TEST_ENDPOINT']).read_bytes()\n"
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
        endpoint = self.root / 'endpoint.json'
        endpoint.write_text(json.dumps({'edge_url': 'https://edge.invalid', 'hosting_root': '11' * 32,
                                       'app_root': '22' * 32, 'policy': '', 'policy_signature': '',
                                       'recovery_key': '03', 'max_lifetime_secs': 86400, 'max_uncertainty_secs': 30,
                                       'build_floor': 1, 'appraisal': 'hardware'}) + '\n')
        env = {'BH_TEST_ENDPOINT': str(endpoint),"PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "CARGO_TARGET_DIR": str(self.root / "inherited-target"),
               "CARGO_BUILD_TARGET": "x86_64-apple-darwin",
               "BH_TEST_LOG": str(self.root / "cargo.log")}
        with mock.patch.dict(os.environ, env), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            package.build(42, output, signing_root=ROOT_SHA1, sync_endpoint=endpoint)
        proof = json.loads((output / 'sync-endpoint-provenance.json').read_text())
        self.assertEqual(proof['endpoint']['sha256'], hashlib.sha256(endpoint.read_bytes()).hexdigest())
        self.assertEqual(proof['artifact_sha256'], hashlib.sha256((output / package.NAME).read_bytes()).hexdigest())
        with tarfile.open(output / package.NAME, "r:gz") as archive:
            self.assertEqual(archive.extractfile("BaseHero.app/Contents/MacOS/bh-client").read(), b"CURRENT COMMIT")
            self.assertIn(b"EFF attribution", archive.extractfile("BaseHero.app/Contents/Resources/Licenses/eff_large_wordlist-LICENSE.md").read())
        self.assertEqual((old / "Contents" / "MacOS" / "bh-client").read_bytes(), b"OLD COMMIT")
        # The next successful fake Cargo build includes a real marker in the
        # selected executable. Run the actual landed Node checker, not a stub.
        rejected = self.root / "rejected"
        with mock.patch.dict(os.environ, {**env, "BH_TEST_INJECT_WEBDRIVER": "1"}), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            with self.assertRaises(subprocess.CalledProcessError):
                package.build(43, rejected, signing_root=ROOT_SHA1, sync_endpoint=endpoint)
        self.assertFalse((rejected / package.NAME).exists())
        self.assertIn(b"tauri_plugin_webdriver", (current / "Contents" / "MacOS" / "bh-client").read_bytes())

    def test_separate_identifier_is_built_and_validated(self):
        for value in ("", "basehero", "App.BaseHero", "app..basehero", "app.basehero.", "app.base hero", "app.basehero/x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                package.bundle_identifier(value)
        demo = package.bundle_identifier("app.basehero.client.updatedemo")
        with mock.patch.object(package, "inspect_macho", return_value=False):
            with self.assertRaises(ValueError):
                package.validate_bundle(self.app, 42, demo)
        export = self.root / "export"
        (export / "apps" / "client" / "src-tauri" / "src").mkdir(parents=True)
        (export / "apps" / "client" / "src-tauri" / "src" / "eff_large_wordlist-LICENSE.md").write_text("EFF\n")
        (export / "Cargo.lock").touch()
        (export / "scripts").mkdir()
        shutil.copyfile(SCRIPT.with_name("check-webdriver-markers.mjs"), export / "scripts" / "check-webdriver-markers.mjs")
        tools = self.root / "bin"
        tools.mkdir()
        cargo = tools / "cargo"
        # Tauri takes the identifier from the --config overlay; the fake records it.
        cargo.write_text("#!/usr/bin/env python3\nimport json, os, pathlib, plistlib, sys\n"
                         "args=sys.argv[1:]\n" + FAKE_HELPER_BUILD + "config=json.loads(args[args.index('--config')+1])\n"
                         "assert config['bundle'] == {'active': True}\n"
                         "app=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'aarch64-apple-darwin/release/bundle/macos/BaseHero.app'\n"
                         "(app/'Contents/MacOS').mkdir(parents=True)\n"
                         "(app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':config.get('identifier','app.basehero.client'),'CFBundleVersion':'0.1.0','CFBundleExecutable':'bh-client'}))\n"
                         "(app/'Contents/MacOS/bh-client').write_bytes(b'binary')\n")
        cargo.chmod(0o755)
        codesign = tools / "codesign"
        codesign.write_text("#!/bin/sh\nexit 0\n")
        codesign.chmod(0o755)
        env = {"PATH": str(tools) + os.pathsep + os.environ["PATH"], "BH_TEST_LOG": str(self.root / "cargo.log")}
        with mock.patch.dict(os.environ, env), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            package.build(42, self.root / "demo", demo, ROOT_SHA1, local_only=True)
            package.build(43, self.root / "production", signing_root=ROOT_SHA1, local_only=True)
        for output, identifier in (("demo", demo), ("production", "app.basehero.client")):
            with tarfile.open(self.root / output / package.NAME, "r:gz") as archive:
                info = plistlib.loads(archive.extractfile("BaseHero.app/Contents/Info.plist").read())
            self.assertEqual(info["CFBundleIdentifier"], identifier)
            with tarfile.open(self.root / output / package.NAME, "r:gz") as archive:
                helper = archive.extractfile("BaseHero.app/Contents/MacOS/bh-keychain-helper").read()
            self.assertEqual(helper, b"HELPER " + identifier.encode(), "the helper is built for the same identity")

    def test_keychain_helper_is_built_alone_reproducibly_and_signed_first(self):
        export = self.root / "export"
        (export / "apps" / "client" / "src-tauri" / "src").mkdir(parents=True)
        (export / "apps" / "client" / "src-tauri" / "src" / "eff_large_wordlist-LICENSE.md").write_text("EFF\n")
        (export / "Cargo.lock").touch()
        (export / "scripts").mkdir()
        shutil.copyfile(SCRIPT.with_name("check-webdriver-markers.mjs"), export / "scripts" / "check-webdriver-markers.mjs")
        tools = self.root / "bin"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text("#!/usr/bin/env python3\nimport json, os, pathlib, plistlib, sys\n"
                         "args=sys.argv[1:]\n" + FAKE_HELPER_BUILD +
                         "app=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'aarch64-apple-darwin/release/bundle/macos/BaseHero.app'\n"
                         "(app/'Contents/MacOS').mkdir(parents=True)\n"
                         "(app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'app.basehero.client','CFBundleVersion':'0.1.0','CFBundleExecutable':'bh-client'}))\n"
                         "(app/'Contents/MacOS/bh-client').write_bytes(b'binary')\n")
        cargo.chmod(0o755)
        codesign = tools / "codesign"
        codesign.write_text("#!/bin/sh\necho \"$*\" >> \"$BH_TEST_SIGN_LOG\"\n")
        codesign.chmod(0o755)
        log, signs = self.root / "cargo.log", self.root / "codesign.log"
        env = {"PATH": str(tools) + os.pathsep + os.environ["PATH"], "BH_TEST_LOG": str(log), "BH_TEST_SIGN_LOG": str(signs),
               "CARGO_ENCODED_RUSTFLAGS": "-Cdebuginfo=2", "RUSTFLAGS": "-Ctarget-cpu=native"}
        for bad in (None, "", ROOT_SHA1.upper(), ROOT_SHA1[:-1], ROOT_SHA1 + "0"):
            with self.subTest(root=bad), self.assertRaises(ValueError):
                package.certificate_root(bad)
        with mock.patch.dict(os.environ, env), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            with self.assertRaises(ValueError):
                package.build(42, self.root / "unrooted", signing_root="", local_only=True)
            package.build(42, self.root / "out", signing_root=ROOT_SHA1, local_only=True)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(records), 2, "verify a canonical helper before building the requested identity")
        pin_record, record = records
        self.assertEqual(pin_record["env"]["BH_APP_IDENTIFIER"], "app.basehero.client")
        self.assertEqual(pin_record["env"]["BH_KEYCHAIN_CALLER_ROOT"], "0" * 40)
        self.assertEqual(record["args"], ["build", "--locked", "--profile", "keychain-helper", "-p", "bh-mac-keychain-helper",
                                          "--bin", "bh-keychain-helper", "--target", "aarch64-apple-darwin"])
        self.assertEqual(record["env"]["BH_APP_IDENTIFIER"], "app.basehero.client")
        self.assertEqual(record["env"]["BH_KEYCHAIN_CALLER_ROOT"], ROOT_SHA1)
        self.assertIsNone(record["env"]["CARGO_ENCODED_RUSTFLAGS"], "no inherited flags reach the helper")
        # Neither the checkout path nor Cargo's home may reach the helper's bytes.
        flags = record["env"]["RUSTFLAGS"].split()
        cargo_home = os.environ.get("CARGO_HOME") or str(pathlib.Path.home() / ".cargo")
        self.assertEqual(flags[:2], [f"--remap-path-prefix={export}=/basehero", f"--remap-path-prefix={cargo_home}=/cargo"])
        # Unused dylibs (the Nix store's libiconv) are not linked at all, and no
        # debug map of object paths feeds the linker's content-hash UUID.
        self.assertEqual(flags[2:], ["-Clink-arg=-Wl,-dead_strip_dylibs", "-Clink-arg=-Wl,-S"])
        self.assertEqual(pathlib.Path(record["env"]["CARGO_TARGET_DIR"]), export / "target" / "keychain-helper")
        calls = signs.read_text().splitlines()
        helper = [i for i, c in enumerate(calls) if c.endswith("Contents/MacOS/bh-keychain-helper")]
        app = [i for i, c in enumerate(calls) if c.endswith("/BaseHero.app") and "--sign" in c]
        self.assertEqual(len(helper), 1)
        self.assertLess(helper[0], app[0], "nested code is signed before the app seals it")
        self.assertIn("--options runtime", calls[helper[0]])
        self.assertIn("--identifier app.basehero.client.keychain-helper", calls[helper[0]])
        with tarfile.open(self.root / "out" / package.NAME, "r:gz") as archive:
            member = archive.getmember("BaseHero.app/Contents/MacOS/bh-keychain-helper")
            self.assertEqual(member.mode & 0o777, 0o755)
        # A changed build must not produce a package even if the requested
        # identity's helper and Tauri executable both built successfully.
        with mock.patch.object(package, "EXPECTED_HELPER_SHA256", "0" * 64), mock.patch.dict(os.environ, env), mock.patch.object(package, "ROOT", export), mock.patch.object(package.sys, "platform", "darwin"), mock.patch.object(package.os, "uname", return_value=type("Uname", (), {"machine": "arm64"})()), mock.patch.object(package, "inspect_macho", return_value=False):
            with self.assertRaisesRegex(ValueError, "Keychain helper.*SHA-256"):
                package.build(43, self.root / "changed", signing_root=ROOT_SHA1, local_only=True)
        self.assertFalse((self.root / "changed" / package.NAME).exists())

    def test_eff_wordlist_notice_is_in_packaged_app(self):
        export = self.root / "export"
        source = export / "apps/client/src-tauri/src/eff_large_wordlist-LICENSE.md"
        source.parent.mkdir(parents=True)
        source.write_text("EFF attribution and CC BY 4.0\n")
        with mock.patch.object(package, "ROOT", export), mock.patch.object(package, "inspect_macho", return_value=False):
            package.bundle_notices(self.app)
            output = self.root / "package.tar.gz"
            package.archive_bundle(self.app, output)
        with tarfile.open(output, "r:gz") as archive:
            notice = archive.extractfile(
                "BaseHero.app/Contents/Resources/Licenses/eff_large_wordlist-LICENSE.md"
            )
            self.assertEqual(notice.read(), source.read_bytes())

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
