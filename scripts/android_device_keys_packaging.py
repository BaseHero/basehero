#!/usr/bin/env python3
"""Check the unsigned release APK, not just source declarations, for the JNI bridge."""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def check(apk: Path):
    with zipfile.ZipFile(apk) as archive:
        dex = b''.join(archive.read(name) for name in archive.namelist()
                       if name.startswith('classes') and name.endswith('.dex'))
        for marker in (b'Lapp/basehero/devicekeys/DeviceKeysBridge;',
                       b'attachActivity', b'detachActivity', b'currentActivity', b'nativeComplete'):
            if marker not in dex:
                raise ValueError(f'JNI class/method missing or renamed by R8: {marker!r}')
        libs = [name for name in archive.namelist()
                if name == 'lib/arm64-v8a/libbh_client_lib.so']
        if len(libs) != 1:
            raise ValueError(f'expected one arm64 client native library, got {libs}')
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp, 'libbh_client_lib.so')
            lib.write_bytes(archive.read(libs[0]))
            symbols = subprocess.check_output(['readelf', '--dyn-syms', '--wide', str(lib)], text=True)
            callback = 'Java_app_basehero_devicekeys_DeviceKeysBridge_nativeComplete'
            if callback not in symbols:
                raise ValueError(f'JNI callback missing from release dynamic symbols: {callback}')
    print('unsigned release APK: R8-retained device-key JNI class/methods and native callback export')


if __name__ == '__main__':
    try:
        check(Path(sys.argv[1]))
    except (IndexError, OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        sys.exit(f'Android device-key packaging failed: {exc}')
