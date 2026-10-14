#!/usr/bin/env python3
"""Check the exact emulator test APK's packaged manifest and transfer rules."""
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from android_storage_boundary import (ANDROID, RULES, aapt_output, check_manifest as check_storage_manifest,
                                      check_rules, parse_aapt_tree, require, resource_path)

PERMISSIONS = {'android.permission.INTERNET',
               'app.basehero.client.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'}
COMPONENTS = {
    'activity': {'app.basehero.client.MainActivity'},
    'provider': {'androidx.startup.InitializationProvider'},
    'receiver': {'androidx.profileinstaller.ProfileInstallReceiver'},
}


def check_manifest(root, packaged=False):
    check_storage_manifest(root, packaged=packaged)
    attribute = 'android:name' if packaged else ANDROID + 'name'
    permissions = [node.get(attribute) for node in root.findall('uses-permission')]
    require(not set(permissions) - PERMISSIONS and len(permissions) == len(set(permissions))
            and 'android.permission.INTERNET' in permissions,
            f'unexpected feature APK permissions: {permissions}')
    app = root.find('application')
    for tag in ('activity', 'provider', 'receiver', 'service', 'activity-alias'):
        found = [node.get(attribute) for node in app.findall(tag)]
        expected = COMPONENTS.get(tag, set())
        require(not set(found) - expected and len(found) == len(set(found))
                and (tag != 'activity' or set(found) == expected),
                f'unexpected feature APK {tag}: {found}')
    return {name: app.get(('android:' if packaged else ANDROID) + attr)
            for attr, (name, _, _) in RULES.items()}


def check_apk(apk, aapt):
    # Resolve both resources by the IDs in this APK, not by same-named source XML.
    refs = check_manifest(parse_aapt_tree(aapt_output(aapt, 'xmltree', str(apk), 'AndroidManifest.xml')),
                          packaged=True)
    resources = aapt_output(aapt, '--values', 'resources', str(apk))
    with zipfile.ZipFile(apk) as archive:
        for name, (resource_name, tag, sections) in RULES.items():
            path = resource_path(resources, refs[resource_name][1:].lower(), resource_name)
            require(path in archive.namelist(), f'{name}: missing packaged resource {path}')
            check_rules(parse_aapt_tree(aapt_output(aapt, 'xmltree', str(apk), path)), tag, sections)
            print(f'{name}: packaged exclusions verified at {path}')
    print('feature APK: INTERNET only; no extra components; packaged backups and transfers excluded')


if __name__ == '__main__':
    try:
        check_apk(Path(sys.argv[1]), Path(sys.argv[2]))
    except (IndexError, KeyError, ValueError, OSError, ET.ParseError,
            zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        sys.exit(f'WebDriver feature APK failed: {error}')
