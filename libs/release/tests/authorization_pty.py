"""Owned PTY integration checks for the authorization CLI; invoked by authorization.rs."""
import hashlib
import json
import os
import pathlib
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time

SIGNER = sys.argv[1]
RELEASE_SIGNER = sys.argv[2]
ROOT = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61"


def wait_echo_off(slave, child):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if not termios.tcgetattr(slave)[3] & termios.ECHO:
            return
        if child.poll() is not None:
            raise AssertionError("signer exited before hiding input")
        time.sleep(0.01)
    raise AssertionError("signer did not hide terminal input")


def failure(args, initial_echo=True, fake_stty=None, restored=None):
    master, slave = pty.openpty()
    child = None
    try:
        before = termios.tcgetattr(slave)
        if not initial_echo:
            before[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, before)
        before = termios.tcgetattr(slave)
        env = os.environ.copy()
        if fake_stty:
            env["PATH"] = str(fake_stty) + os.pathsep + env["PATH"]
        child = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if fake_stty is None or restored is not None:
            if initial_echo:
                wait_echo_off(slave, child)
            os.write(master, b"NOT_A_SEED_SENTINEL\n")
        stdout, stderr = child.communicate(timeout=4)
        assert child.returncode == 1, f"wrong failure exit: {child.returncode}"
        assert stdout == b"", f"failure wrote public output: {stdout!r}"
        assert stderr == b"authorization failed\n", f"non-fixed stderr: {stderr!r}"
        assert termios.tcgetattr(slave) == before, "terminal state was not restored"
        if restored is not None:
            assert restored.read_text() == "restored\n", "opaque state was not restored as one argument"
            restored.unlink()
        readable, _, _ = select.select([master], [], [], 0)
        if readable:
            assert b"NOT_A_SEED_SENTINEL" not in os.read(master, 4096), "seed input was echoed"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=4)
        os.close(master)
        os.close(slave)


def metadata_signer_invalid_seed_keeps_prompt_and_newline(args, fake_stty=None, initial_echo=True, restored=None):
    master, slave = pty.openpty()
    child = None
    try:
        before = termios.tcgetattr(slave)
        if not initial_echo:
            before[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, before)
        before = termios.tcgetattr(slave)
        env = os.environ.copy()
        if fake_stty:
            env["PATH"] = str(fake_stty) + os.pathsep + env["PATH"]
        child = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if initial_echo:
            wait_echo_off(slave, child)
        os.write(master, b"invalid\n")
        stdout, stderr = child.communicate(timeout=4)
        assert child.returncode == 1
        assert stdout == b""
        assert stderr == (b"Paste release seed (64 hex characters), then press Enter: "
                          b"\nexpected exactly 64 lowercase hexadecimal seed characters on stdin\n"), stderr
        assert termios.tcgetattr(slave) == before
        if restored is not None:
            assert restored.read_text() == "restored\n", "metadata signer did not restore opaque state"
            restored.unlink()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=4)
        os.close(master)
        os.close(slave)


def bsd_stty_adapter(temp, real_stty):
    fake = temp / "bsd-bin"
    fake.mkdir()
    native = temp / "native-stty-mode"
    restored = temp / "bsd-restored"
    stty = fake / "stty"
    # The real installed stty controls the owned PTY. Only its public -g
    # representation is translated; restoration must pass the BSD value intact
    # as exactly one argument, then replay the captured native mode.
    stty.write_text(f'''#!/usr/bin/env python3
import pathlib, subprocess, sys
real = {real_stty!r}
native = pathlib.Path({str(native)!r})
restored = pathlib.Path({str(restored)!r})
bsd = "gfmt1:cflag=1:iflag=2:oflag=3:lflag=4"
args = sys.argv[1:]
if args == ["-g"]:
    result = subprocess.run([real, "-g"], stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode: sys.exit(result.returncode)
    native.write_bytes(result.stdout)
    print(bsd)
elif args == ["-echo"]:
    sys.exit(subprocess.run([real, "-echo"], stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode)
elif args == [bsd]:
    result = subprocess.run([real, native.read_text().strip()], stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0: restored.write_text("restored\\n")
    sys.exit(result.returncode)
else:
    sys.stderr.write("BSD_FAKE_WRONG_ARGUMENTS\\n")
    sys.exit(7)
''')
    stty.chmod(0o700)
    return fake, restored


def authorization_sign_success(args, fake_stty, restored):
    master, slave = pty.openpty()
    child = None
    try:
        before = termios.tcgetattr(slave)
        env = os.environ.copy()
        env["PATH"] = str(fake_stty) + os.pathsep + env["PATH"]
        child = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        wait_echo_off(slave, child)
        os.write(master, b"2a" * 32 + b"\n")
        stdout, stderr = child.communicate(timeout=4)
        assert child.returncode == 0, (child.returncode, stderr)
        assert stderr == b"", stderr
        assert json.loads(stdout)["value"]["kind"] == "receipt"
        assert termios.tcgetattr(slave) == before
        assert restored.read_text() == "restored\n", "successful signing did not restore opaque mode"
        restored.unlink()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=4)
        os.close(master)
        os.close(slave)


with tempfile.TemporaryDirectory() as temp:
    temp = pathlib.Path(temp)
    request = {
        "format": 1,
        "public_commit": "a" * 40,
        "product_tree": "b" * 40,
        "root": ROOT,
        "artifacts": [],
        "operation": {"kind": "receipt", "leaf_public_key": "cd" * 32},
    }
    raw = json.dumps(request, separators=(",", ":")).encode()
    request_file = temp / "request.json"
    request_file.write_bytes(raw)
    args = [SIGNER, "sign", str(request_file), "--request-sha256", hashlib.sha256(raw).hexdigest(),
            "--expected-root", ROOT, "--public-commit", "a" * 40, "--product-tree", "b" * 40,
            "--kind", "receipt", "--artifacts", str(temp)]
    # A real PTY with echo initially on; invalid input after echo is disabled.
    failure(args)
    # The guard must not turn on a terminal whose echo was already disabled.
    failure(args, initial_echo=False)
    # Fail stty -echo on a real PTY. Child diagnostic must never escape.
    real_stty = shutil.which("stty")
    assert real_stty is not None
    fake = temp / "fake-bin"
    fake.mkdir()
    stty = fake / "stty"
    stty.write_text('#!/bin/sh\nif [ "$1" = "-echo" ]; then printf "UNTRUSTED_CHILD_STDERR\\n" >&2; printf "UNTRUSTED_CHILD_STDOUT\\n"; exit 7; fi\nexec "' + real_stty + '" "$@"\n')
    stty.chmod(0o700)
    failure(args, fake_stty=fake)
    archive = temp / "app.tar.gz"
    archive.write_bytes(b"fixture archive")
    notes = temp / "notes.txt"
    notes.write_text("fixture notes")
    metadata_args = [RELEASE_SIGNER,"sign","1","macos-aarch64","stable","a"*40,str(archive),str(notes)]
    metadata_signer_invalid_seed_keeps_prompt_and_newline(metadata_args)
    bsd_fake, restored = bsd_stty_adapter(temp, real_stty)
    for echo_on in [True, False]:
        failure(args, initial_echo=echo_on, fake_stty=bsd_fake, restored=restored)
        metadata_signer_invalid_seed_keeps_prompt_and_newline(metadata_args, fake_stty=bsd_fake, initial_echo=echo_on, restored=restored)
    authorization_sign_success(args, bsd_fake, restored)
print("owned PTY failures and BSD-format signing: echo modes, refusal, metadata signer prompt, restored state")
