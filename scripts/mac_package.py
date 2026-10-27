#!/usr/bin/env python3
"""Build and package the unsigned arm64 Tauri app, with the pinned Keychain helper."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = "BaseHero.app"
HELPER = "bh-keychain-helper"
SYSTEM = ("/usr/lib/", "/System/Library/")
HELPER_DIR = ROOT / "apps/basehero/src-tauri/keychain-helper"


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True).stdout


def verify_helper(data, sums=HELPER_DIR / "SHA256SUMS"):
    """Verify the committed, pre-signing helper bytes (not its final cdhash)."""
    lines = sums.read_text().splitlines()
    matches = [line.split() for line in lines if line.split() and line.split()[-1].lstrip("*").removeprefix("./") == HELPER]
    if len(matches) != 1 or len(matches[0]) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", matches[0][0]):
        raise ValueError("SHA256SUMS must pin bh-keychain-helper exactly once")
    if hashlib.sha256(data).hexdigest() != matches[0][0].lower():
        raise ValueError("helper differs from SHA256SUMS")


def check_loads(dependencies, rpaths=(), frameworks=()):
    """Reject host-specific loads and search paths; permit bundled libraries only."""
    for dependency in dependencies:
        if dependency.startswith(SYSTEM):
            continue
        prefix = "@executable_path/../Frameworks/"
        if dependency.startswith(prefix) and dependency[len(prefix):] in frameworks:
            continue
        raise ValueError(f"external Mach-O dependency: {dependency}")
    if rpaths:
        raise ValueError(f"unexpected Mach-O rpath: {rpaths}")


def entries(app):
    yield app
    for root, dirs, files in os.walk(app, followlinks=False):
        for name in sorted(dirs + files):
            yield Path(root) / name


def materialize_links(app):
    for path in list(entries(app)):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=True)
        if not target.is_relative_to(app.resolve()) or not (target.is_file() or target.is_dir()):
            raise ValueError(f"bundle link escapes app: {path}")
        path.unlink()
        if target.is_dir():
            shutil.copytree(target, path, symlinks=True)
        else:
            shutil.copy2(target, path)
    if any(path.is_symlink() for path in entries(app)):
        raise ValueError("unresolved bundle link")


def macho(path):
    return "Mach-O" in run("file", "-b", str(path))


def macho_loads(path):
    dependencies = [line.strip().split(" (", 1)[0] for line in run("otool", "-L", str(path)).splitlines()[1:]]
    lines = run("otool", "-l", str(path)).splitlines()
    rpaths = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            match = re.fullmatch(r"\s*path (\S+) \(offset \d+\)", lines[index + 2])
            if not match:
                raise ValueError(f"unrecognized LC_RPATH: {path}")
            rpaths.append(match.group(1))
    return dependencies, rpaths


def bundle_native_libraries(app):
    frameworks = app / "Contents/Frameworks"
    for path in list(entries(app)):
        if not path.is_file() or not macho(path):
            continue
        deps, _ = macho_loads(path)
        for dep in deps:
            if dep.startswith("/nix/store/") and Path(dep).name == "libsodium.26.dylib":
                libdir = Path(run("pkg-config", "--variable=libdir", "libsodium").strip()).resolve()
                if Path(dep).resolve() != (libdir / "libsodium.26.dylib").resolve():
                    raise ValueError(f"unexpected libsodium linkage: {dep}")
                frameworks.mkdir(exist_ok=True)
                dest = frameworks / "libsodium.26.dylib"
                if not dest.exists():
                    shutil.copy2(dep, dest)
                    notices = app / "Contents/Resources/Licenses"
                    notices.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / "LICENSES/libsodium.txt", notices / "libsodium.txt")
                    run("install_name_tool", "-id", "@executable_path/../Frameworks/libsodium.26.dylib", str(dest))
                run("install_name_tool", "-change", dep, "@executable_path/../Frameworks/libsodium.26.dylib", str(path))
            elif dep.startswith("/nix/store/") and Path(dep).name == "libiconv.2.dylib":
                run("install_name_tool", "-change", dep, "/usr/lib/libiconv.2.dylib", str(path))


def validate_bundle(app, version):
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != "app.basehero" or info.get("CFBundleShortVersionString") != version:
        raise ValueError("bundle identifier or version mismatch")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or Path(executable).name != executable or not (app / "Contents/MacOS" / executable).is_file():
        raise ValueError("missing app executable")
    frameworks = {p.name for p in (app / "Contents/Frameworks").glob("*") if p.is_file()}
    for path in entries(app):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"unsupported bundle entry: {path}")
        if path.is_file() and macho(path):
            if run("lipo", "-archs", str(path)).strip() != "arm64":
                raise ValueError(f"non-arm64 Mach-O: {path}")
            dependencies, rpaths = macho_loads(path)
            check_loads(dependencies, rpaths, frameworks)


def archive_bundle(app, output):
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped, tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path in entries(app):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise ValueError(f"unsupported archive entry: {path}")
                name = BUNDLE if path == app else BUNDLE + "/" + path.relative_to(app).as_posix()
                info = tar.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                if path.is_file():
                    with path.open("rb") as stream:
                        tar.addfile(info, stream)
                else:
                    tar.addfile(info)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def build(version, out):
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise ValueError("requires an arm64 Mac")
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version, re.ASCII):
        raise ValueError("version must be X.Y.Z")
    triple = "aarch64-apple-darwin"
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    app = target / triple / "release/bundle/macos" / BUNDLE
    if app.is_symlink() or app.is_file():
        app.unlink()
    elif app.is_dir():
        shutil.rmtree(app)
    run("npm", "ci", "--no-audit", "--no-fund", cwd=ROOT / "apps/basehero")
    run("cargo", "tauri", "build", "--bundles", "app", "--target", triple, "--no-sign", "--ci", "--", "--locked", cwd=ROOT / "apps/basehero")
    if not app.is_dir():
        raise ValueError(f"missing Tauri app bundle: {app}")
    helper_bytes = (HELPER_DIR / HELPER).read_bytes()
    verify_helper(helper_bytes)
    helper = app / "Contents/MacOS" / HELPER
    helper.write_bytes(helper_bytes)
    helper.chmod(0o755)
    materialize_links(app)
    bundle_native_libraries(app)
    validate_bundle(app, version)
    archive_bundle(app, out / f"BaseHero-{version}-macos-arm64.app.tar.gz")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    build(args.version, args.out)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"mac packaging failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            # run() captures output, so show it here, or CI logs never name the cause.
            print(f"{error.stdout or ''}{error.stderr or ''}", file=sys.stderr)
        sys.exit(1)
