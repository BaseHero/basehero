#!/usr/bin/env python3
"""Build a link-free, ad-hoc signed arm64 Tauri app from a source-only export.

Run inside `git archive HEAD:basehero` unpacked outside the repository. No
release signing key or production update endpoint is used by this tool; the
app-signing certificate's SHA-1 is public and only compiled into the Keychain
helper, which accepts an app signed with that certificate as its caller.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile

from sync_endpoint import prepare_endpoint, record_endpoint

ROOT = Path(__file__).resolve().parent.parent
NAME = "BaseHero-macos-aarch64.app.tar.gz"
BUNDLE = "BaseHero.app"
SYSTEM = ("/usr/lib/", "/System/Library/")
SODIUM = "libsodium.26.dylib"
HELPER = "bh-keychain-helper"
# A fixed build identity makes this unsigned-byte pin independent of the
# certificate root and bundle identifier supplied for each package. The
# canonical helper is never shipped; the requested identity is built below.
PIN_IDENTIFIER = "app.basehero.client"
PIN_ROOT = "0" * 40
EXPECTED_HELPER_SHA256 = "afd4a76923f88e02718649ce7b5f4fe8476cdc14d87a8a8b0dd693f79de2509e"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run(*args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True, capture_output=True).stdout


def release_number(text):
    if not re.fullmatch(r"[1-9][0-9]*", text, flags=re.ASCII) or int(text) > 2**64 - 1:
        raise ValueError("release number must be a canonical positive decimal u64")
    return int(text)


def bundle_identifier(text):
    if not re.fullmatch(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+", text, flags=re.ASCII):
        raise ValueError("bundle identifier must be a lowercase reverse-DNS name")
    return text


def certificate_root(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9a-f]{40}", text, flags=re.ASCII):
        raise ValueError("signing root must be the certificate's lowercase SHA-1")
    return text


def build_helper(identifier, root, triple):
    """Build the Keychain helper alone, so its bytes depend only on its own
    source, its locked dependencies, the pinned toolchain and these inputs.
    App changes never reach it; neither do this checkout's or Cargo's paths."""
    target_dir = ROOT / "target" / "keychain-helper"
    cargo_home = os.environ.get("CARGO_HOME") or str(Path.home() / ".cargo")
    env = {key: value for key, value in os.environ.items()
           if key not in ("CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS") and not key.startswith("CARGO_PROFILE_")}
    env.update({
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_BUILD_TARGET": triple,
        "BH_APP_IDENTIFIER": identifier,
        "BH_KEYCHAIN_CALLER_ROOT": root,
        # Unused dylibs stay unlinked, so no Nix store path reaches a load
        # command. -S keeps the object-path debug map out of the link, so the
        # linker's content-derived LC_UUID doesn't depend on the checkout path.
        "RUSTFLAGS": f"--remap-path-prefix={ROOT}=/basehero --remap-path-prefix={cargo_home}=/cargo"
                     " -Clink-arg=-Wl,-dead_strip_dylibs -Clink-arg=-Wl,-S",
    })
    run("cargo", "build", "--locked", "--profile", "keychain-helper", "-p", "bh-mac-keychain-helper",
        "--bin", HELPER, "--target", triple, cwd=ROOT, env=env)
    return target_dir / triple / "keychain-helper" / HELPER


def verify_helper_pin(data):
    actual = sha256(data)
    if actual != EXPECTED_HELPER_SHA256:
        raise ValueError(
            f"Keychain helper unsigned SHA-256 changed: expected {EXPECTED_HELPER_SHA256}, got {actual}; "
            "to update it deliberately, review helper source, locked deps, toolchain, "
            "SDK and profile, then rebuild the canonical helper "
            "(app.basehero.client, 40 zeroes as root) and update EXPECTED_HELPER_SHA256"
        )


def entries(app):
    # os.walk with followlinks=False still lists links to directories; include
    # those explicitly rather than assuming a link-free Tauri bundle.
    yield app
    for root, dirs, files in os.walk(app, followlinks=False):
        for name in sorted(dirs + files):
            yield Path(root) / name


def materialize_links(app):
    # Tauri/Apple frameworks can contain internal aliases. Resolve only targets
    # already inside this app; never import the builder's host paths.
    for path in list(entries(app)):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=True)
        if not target.is_relative_to(app.resolve()) or target == path or not (target.is_file() or target.is_dir()):
            raise ValueError(f"bundle link escapes app or is unsupported: {path}")
        path.unlink()
        if target.is_dir():
            shutil.copytree(target, path, symlinks=True)
        else:
            shutil.copy2(target, path)
    if any(p.is_symlink() for p in entries(app)):
        raise ValueError("bundle contains unresolved links")


def inspect_macho(path):
    return "Mach-O" in run("file", "-b", str(path))


def macho_loads(path):
    output = run("otool", "-L", str(path)).splitlines()
    dependencies = [line.strip().split(" (", 1)[0] for line in output[1:]]
    lines = run("otool", "-l", str(path)).splitlines()
    rpaths = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            # otool prints cmdsize and then path; fail if unexpected layout.
            match = re.fullmatch(r"\s*path (\S+) \(offset \d+\)", lines[index + 2])
            if not match:
                raise ValueError(f"unrecognized LC_RPATH in {path}")
            rpaths.append(match.group(1))
    return dependencies, rpaths


def validate_bundle(app, version, identifier="app.basehero.client"):
    if app.name != BUNDLE or not app.is_dir() or app.is_symlink():
        raise ValueError("expected BaseHero.app directory")
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != identifier or info.get("CFBundleVersion") != str(version):
        raise ValueError("bundle identifier or CFBundleVersion mismatch")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or Path(executable).name != executable or not (app / "Contents" / "MacOS" / executable).is_file():
        raise ValueError("missing or invalid bundle executable")
    for path in entries(app):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"unsupported bundle entry: {path}")
        if not path.is_file() or not inspect_macho(path):
            continue
        if run("lipo", "-archs", str(path)).strip() != "arm64":
            raise ValueError(f"non-arm64 Mach-O: {path}")
        deps, rpaths = macho_loads(path)
        for dependency in deps:
            if dependency.startswith(SYSTEM):
                continue
            prefix = "@executable_path/../Frameworks/"
            if dependency.startswith(prefix) and "/" not in dependency[len(prefix):] and (app / "Contents" / "Frameworks" / dependency[len(prefix):]).is_file():
                continue
            raise ValueError(f"external Mach-O dependency: {path}: {dependency}")
        if rpaths:
            raise ValueError(f"unexpected Mach-O rpath: {path}: {rpaths}")


def archive_bundle(app, output):
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped, tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path in entries(app):
                if path.is_symlink() or not (path.is_dir() or path.is_file()):
                    raise ValueError(f"unsupported archive entry: {path}")
                name = BUNDLE if path == app else BUNDLE + "/" + path.relative_to(app).as_posix()
                info = tar.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with path.open("rb") if path.is_file() else open(os.devnull, "rb") as stream:
                    tar.addfile(info, stream if path.is_file() else None)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def bundle_native_sodium(app):
    framework = app / "Contents" / "Frameworks"
    for path in list(entries(app)):
        if not path.is_file() or not inspect_macho(path):
            continue
        deps, _ = macho_loads(path)
        for dep in deps:
            if dep.startswith("/nix/store/") and Path(dep).name == SODIUM:
                # The pinned pkg-config library is the only acceptable source.
                libdir = Path(run("pkg-config", "--variable=libdir", "libsodium").strip()).resolve()
                if Path(dep).resolve() != (libdir / SODIUM).resolve():
                    raise ValueError(f"unexpected libsodium linkage: {dep}")
                framework.mkdir(exist_ok=True)
                dest = framework / SODIUM
                if not dest.exists():
                    shutil.copy2(dep, dest)
                    notices = app / "Contents" / "Resources" / "Licenses"
                    notices.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / "LICENSES" / "libsodium.txt", notices / "libsodium.txt")
                    run("install_name_tool", "-id", f"@executable_path/../Frameworks/{SODIUM}", str(dest))
                run("install_name_tool", "-change", dep, f"@executable_path/../Frameworks/{SODIUM}", str(path))
            elif dep.startswith("/nix/store/") and Path(dep).name == "libiconv.2.dylib":
                # macOS supplies libiconv; don't ship a separate LGPL copy.
                run("install_name_tool", "-change", dep, "/usr/lib/libiconv.2.dylib", str(path))


def bundle_notices(app):
    notices = app / "Contents" / "Resources" / "Licenses"
    notices.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "apps" / "client" / "src-tauri" / "src" / "eff_large_wordlist-LICENSE.md",
                 notices / "eff_large_wordlist-LICENSE.md")


def build(version, output, identifier="app.basehero.client", signing_root=None, *, sync_endpoint=None, local_only=False):
    bundle_identifier(identifier)
    root = certificate_root(signing_root)
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise ValueError("build requires an arm64 Mac")
    # A checkout can have its .git at ROOT (public repo) or above ROOT
    # (private repo's product subtree). An export nested below a checkout is
    # fine: Git does not track its own copy of this script.
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", "scripts/mac_package.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0
    if (ROOT / ".git").exists() or tracked:
        raise ValueError("build only from a source-only export, not a working checkout")
    if not (ROOT / "Cargo.lock").is_file():
        raise ValueError("missing product source")
    if (output / NAME).exists():
        raise ValueError(f"output already exists: {output / NAME}")
    # Own the Cargo location and target rather than inheriting a developer's
    # CARGO_TARGET_DIR / build.target. Keep the compiler cache across packages,
    # but remove only this bundle before building: a successful no-bundle run
    # must never stamp and archive an earlier app.
    triple = "aarch64-apple-darwin"
    target_dir = ROOT / "target" / "mac-package"
    app = target_dir / triple / "release" / "bundle" / "macos" / BUNDLE
    if app.is_symlink() or app.is_file():
        app.unlink()
    elif app.is_dir():
        shutil.rmtree(app)
    build_env, endpoint_proof = prepare_endpoint(sync_endpoint, local_only, output, os.environ)
    build_env.update({"CARGO_TARGET_DIR": str(target_dir), "CARGO_BUILD_TARGET": triple})
    # CLI overlay enables only the app bundle; the committed config remains
    # inactive for ordinary development builds. Tauri version stays semver.
    # Tauri's trailing arguments pass --locked to its Cargo runner.
    overlay = json.dumps({"bundle": {"active": True}, "identifier": identifier})
    run("cargo", "tauri", "build", "--target", triple, "--bundles", "app", "--config", overlay, "--", "--locked", cwd=ROOT / "apps" / "client" / "src-tauri", env=build_env)
    # Build under a fixed identity first: certificate rotation and separate
    # demo identifiers cannot change the pinned toolchain/source build input.
    verify_helper_pin(build_helper(PIN_IDENTIFIER, PIN_ROOT, triple).read_bytes())
    helper = app / "Contents" / "MacOS" / HELPER
    shutil.copyfile(build_helper(identifier, root, triple), helper)
    helper.chmod(0o755)
    materialize_links(app)
    info = app / "Contents" / "Info.plist"
    plist = plistlib.loads(info.read_bytes())
    plist["CFBundleVersion"] = str(version)
    info.write_bytes(plistlib.dumps(plist))
    bundle_native_sodium(app)
    bundle_notices(app)
    validate_bundle(app, version, identifier)
    helper_bytes = helper.read_bytes()
    # Check the actual executable selected from this bundle's validated plist,
    # not a cached Cargo binary or a source feature declaration.
    run("node", str(ROOT / "scripts" / "check-webdriver-markers.mjs"),
        str(app / "Contents" / "MacOS" / plist["CFBundleExecutable"]), "--expect", "absent")
    # Sign nested code first. The app's signature covers plist, resources and
    # framework code; verification is repeated after archive generation.
    for path in entries(app):
        if path.is_file() and path.parent.name == "Frameworks" and inspect_macho(path):
            run("codesign", "--force", "--sign", "-", str(path))
    # Hardened runtime: the helper ignores DYLD_* and refuses debuggers.
    run("codesign", "--force", "--sign", "-", "--options", "runtime", "--identifier", f"{identifier}.keychain-helper", str(helper))
    run("codesign", "--force", "--sign", "-", str(app))
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    validate_bundle(app, version, identifier)
    archive_bundle(app, output / NAME)
    record_endpoint(output, endpoint_proof, output / NAME)
    # A changed helper makes macOS ask once per Keychain item after the update.
    print(f"{app}\n{output / NAME}\nkeychain helper sha256 (before signing) {sha256(helper_bytes)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_number", help="canonical positive decimal signed-release u64")
    parser.add_argument("output", type=Path, help="output directory outside the exported source")
    parser.add_argument("--identifier", default="app.basehero.client", type=bundle_identifier,
                        help="bundle identity; a separate identity keeps separate app data and keys")
    parser.add_argument("--signing-root", required=True, type=certificate_root,
                        help="lowercase SHA-1 of the app-signing certificate the Keychain helper trusts")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--sync-endpoint', type=Path, help='reviewed public hardware endpoint JSON')
    mode.add_argument('--local-only', action='store_true', help='explicit development build without sync')
    args = parser.parse_args()
    number = release_number(args.release_number)
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error("output must be outside the source export")
    build(number, output, args.identifier, args.signing_root,
          sync_endpoint=args.sync_endpoint, local_only=args.local_only)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"mac packaging failed: {error}", file=sys.stderr)
        sys.exit(1)
