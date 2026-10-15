#!/usr/bin/env python3
"""Build a link-free, ad-hoc signed arm64 Tauri app from a source-only export.

Run inside `git archive HEAD:basehero` unpacked outside the repository. No
release signing key or production update endpoint is used by this tool.
"""
import argparse
import gzip
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
NAME = "BaseHero-macos-aarch64.app.tar.gz"
BUNDLE = "BaseHero.app"
SYSTEM = ("/usr/lib/", "/System/Library/")
SODIUM = "libsodium.26.dylib"


def run(*args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True, capture_output=True).stdout


def release_number(text):
    if not re.fullmatch(r"[1-9][0-9]*", text, flags=re.ASCII) or int(text) > 2**64 - 1:
        raise ValueError("release number must be a canonical positive decimal u64")
    return int(text)


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


def validate_bundle(app, version):
    if app.name != BUNDLE or not app.is_dir() or app.is_symlink():
        raise ValueError("expected BaseHero.app directory")
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != "app.basehero.client" or info.get("CFBundleVersion") != str(version):
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


def build(version, output):
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
    build_env = {**os.environ, "CARGO_TARGET_DIR": str(target_dir), "CARGO_BUILD_TARGET": triple}
    # CLI overlay enables only the app bundle; the committed config remains
    # inactive for ordinary development builds. Tauri version stays semver.
    # Tauri's trailing arguments pass --locked to its Cargo runner.
    run("cargo", "tauri", "build", "--target", triple, "--bundles", "app", "--config", '{"bundle":{"active":true}}', "--", "--locked", cwd=ROOT / "apps" / "client" / "src-tauri", env=build_env)
    materialize_links(app)
    info = app / "Contents" / "Info.plist"
    plist = plistlib.loads(info.read_bytes())
    plist["CFBundleVersion"] = str(version)
    info.write_bytes(plistlib.dumps(plist))
    bundle_native_sodium(app)
    validate_bundle(app, version)
    # Check the actual executable selected from this bundle's validated plist,
    # not a cached Cargo binary or a source feature declaration.
    run("node", str(ROOT / "scripts" / "check-webdriver-markers.mjs"),
        str(app / "Contents" / "MacOS" / plist["CFBundleExecutable"]), "--expect", "absent")
    # Sign nested code first. The app's signature covers plist, resources and
    # framework code; verification is repeated after archive generation.
    for path in entries(app):
        if path.is_file() and path.parent.name == "Frameworks" and inspect_macho(path):
            run("codesign", "--force", "--sign", "-", str(path))
    run("codesign", "--force", "--sign", "-", str(app))
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    validate_bundle(app, version)
    archive_bundle(app, output / NAME)
    print(f"{app}\n{output / NAME}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_number", help="canonical positive decimal signed-release u64")
    parser.add_argument("output", type=Path, help="output directory outside the exported source")
    args = parser.parse_args()
    number = release_number(args.release_number)
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error("output must be outside the source export")
    build(number, output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"mac packaging failed: {error}", file=sys.stderr)
        sys.exit(1)
