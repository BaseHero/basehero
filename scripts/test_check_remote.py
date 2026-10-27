"""The opt-in remote stage must scope its operator credential to core tests."""

import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check.sh")


class RemoteStageTest(unittest.TestCase):
    def test_remote_passes_dev_credentials_only_to_core_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "check.sh").write_bytes(SCRIPT.read_bytes())
            token_file = root / ".config/basehero/dev-operator-token"
            token_file.parent.mkdir(parents=True)
            token_file.write_text("test-only-secret\n")
            cargo = root / "cargo"
            cargo.write_text("#!/bin/sh\n"
                             "[ \"$*\" = 'test -p bh-core --features test-support -- --nocapture' ] || exit 10\n"
                             "[ \"$BH_TEST_SERVER\" = https://dev-api.basehero.com ] || exit 11\n"
                             "[ \"$BH_TEST_OPERATOR_TOKEN\" = test-only-secret ] || exit 12\n"
                             "[ \"$HOME\" != \"$TEST_ORIGINAL_HOME\" ] || exit 13\n"
                             "[ \"$GH_CONFIG_DIR\" = \"$HOME/gh\" ] || exit 14\n"
                             "[ \"$XDG_CONFIG_HOME\" = \"$HOME/config\" ] || exit 15\n"
                             "[ -z \"${GH_TOKEN:-}${GITHUB_TOKEN:-}\" ] || exit 16\n"
                             "printf 'core tests invoked\\n'\n")
            cargo.chmod(0o700)
            env = {"HOME": str(root), "GH_CONFIG_DIR": str(root / "gh"),
                   "XDG_CONFIG_HOME": str(root / "xdg"), "TEST_ORIGINAL_HOME": str(root),
                   "GH_TOKEN": "test-credential", "GITHUB_TOKEN": "test-credential",
                   "PATH": f"{root}:{os.environ['PATH']}"}
            self.assertEqual(shutil.which("cargo", path=env["PATH"]), str(cargo))
            result = subprocess.run(["unshare", "-rn", "--", "bash", "--noprofile", "--norc",
                                     str(root / "scripts/check.sh"), "remote"],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "core tests invoked\n")
            self.assertNotIn("test-only-secret", result.stderr + result.stdout)

    def test_remote_requires_token_before_starting_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "check.sh").write_bytes(SCRIPT.read_bytes())
            cargo = root / "cargo"
            cargo.write_text("#!/bin/sh\nprintf 'unexpected cargo call\\n'\n")
            cargo.chmod(0o700)
            env = {"HOME": str(root), "GH_CONFIG_DIR": str(root / "gh"),
                   "XDG_CONFIG_HOME": str(root / "xdg"), "PATH": f"{root}:{os.environ['PATH']}"}
            self.assertEqual(shutil.which("cargo", path=env["PATH"]), str(cargo))
            result = subprocess.run(["unshare", "-rn", "--", "bash", "--noprofile", "--norc",
                                     str(root / "scripts/check.sh"), "remote"],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unexpected cargo call", result.stdout)


if __name__ == "__main__":
    unittest.main()
