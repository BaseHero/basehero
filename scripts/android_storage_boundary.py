#!/usr/bin/env python3
"""Check the Android release's merged and packaged app-data transfer boundary.

The binary manifest's resource IDs are resolved against this APK's resource table;
checking a same-named source XML alone would not establish what the APK ships.
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ANDROID = '{http://schemas.android.com/apk/res/android}'
DOMAINS = {'root', 'file', 'database', 'sharedpref', 'external',
           'device_root', 'device_file', 'device_database', 'device_sharedpref'}
RULES = {'dataExtractionRules': ('app_data_extraction_rules', 'data-extraction-rules',
                                 ('cloud-backup', 'device-transfer')),
         'fullBackupContent': ('app_full_backup_rules', 'full-backup-content', ())}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_rules(root, name, sections):
    require(root.tag == name, f'expected <{name}>, got <{root.tag}>')
    if sections:
        require([child.tag for child in root] == list(sections),
                f'{name}: expected sections {sections}, got {[child.tag for child in root]}')
    for section in list(root) if sections else [root]:
        require(not section.attrib, f'{section.tag}: unexpected attributes')
        require(not any(child.tag == 'include' for child in section),
                f'{section.tag}: include would enable copying')
        excludes = [(child.attrib.get('domain'), child.attrib.get('path')) for child in section]
        require(all(child.tag == 'exclude' and len(child.attrib) == 2 for child in section)
                and set(excludes) == {(domain, '.') for domain in DOMAINS}
                and len(excludes) == len(DOMAINS),
                f'{section.tag}: expected root-wide exclusions for {sorted(DOMAINS)}, got {excludes}')


def parse_aapt_tree(output):
    """Decode aapt's indented xmltree (not the source XML)."""
    nodes = []
    root = None
    for line in output.splitlines():
        element = re.match(r'^( *)E: ([\w.-]+)(?: \(line=\d+\))?', line)
        if element:
            depth = len(element[1])
            node = ET.Element(element[2])
            while nodes and nodes[-1][0] >= depth:
                nodes.pop()
            if nodes:
                nodes[-1][1].append(node)
            else:
                require(root is None, 'multiple XML roots in aapt output')
                root = node
            nodes.append((depth, node))
            continue
        attribute = re.match(r'^ *A: ([\w:.-]+)(?:\(0x[0-9a-f]+\))?=(.*)$', line)
        if attribute:
            require(nodes, 'attribute without element in aapt output')
            value = attribute[2].strip()
            raw = re.search(r'\(Raw: "([^"]*)"\)', value)
            if raw:
                value = raw[1]
            elif value.startswith('"'):
                value = value.split('"', 2)[1]
            elif re.match(r'^@0x[0-9a-fA-F]+$', value):
                pass
            elif value.startswith('(type 0x12)'):
                payload = value[len('(type 0x12)'):]
                require(bool(re.fullmatch(r'0x[0-9a-fA-F]+', payload)),
                        f'malformed aapt boolean: {value}')
                value = 'true' if int(payload, 16) != 0 else 'false'
            else:
                # Other manifest attributes (versionCode, flags, etc.) are not
                # part of this boundary. Required attributes must still parse.
                continue
            nodes[-1][1].set(attribute[1], value)
    require(root is not None, 'empty aapt XML tree')
    return root


def check_manifest(root, packaged):
    app = root.find('application')
    require(app is not None, 'missing application')
    providers = app.findall('provider')
    # AndroidX startup comes from the bundled shell's dependencies. It is not a
    # file-sharing provider and cannot grant URIs; fail on any other provider.
    require(len(providers) <= 1 and all(
        provider.get('android:name' if packaged else ANDROID + 'name')
        == 'androidx.startup.InitializationProvider'
        and provider.get('android:exported' if packaged else ANDROID + 'exported') == 'false'
        and provider.get('android:grantUriPermissions' if packaged else ANDROID + 'grantUriPermissions') is None
        and provider.get('android:authorities' if packaged else ANDROID + 'authorities')
        == 'app.basehero.client.androidx-startup'
        for provider in providers), 'unexpected provider in release manifest')
    backup = app.get('android:allowBackup' if packaged else ANDROID + 'allowBackup')
    require(backup == 'false', f'allowBackup must be false, got {backup}')
    refs = {}
    for attr, (name, _, _) in RULES.items():
        value = app.get('android:' + attr if packaged else ANDROID + attr)
        if packaged:
            require(bool(re.fullmatch(r'@0x[0-9a-fA-F]{8}', value or '')),
                    f'{attr} must refer to a packaged resource ID, got {value}')
        else:
            require(value == '@xml/' + name, f'{attr} merged reference: {value}')
        refs[name] = value
    return refs


def aapt_output(aapt, *args):
    return subprocess.check_output([str(aapt), 'dump', *args], text=True)


def resource_path(resources, ref, resource_name):
    # Reject every variant of this ID, even an alias overriding a safe default.
    definitions = re.findall(r'^\s*resource ' + re.escape(ref) + r'\s+([^\n]*)',
                             resources, re.M)
    match = re.search(r'^\s*resource ' + re.escape(ref) + r'\s+[^\n]*:xml/'
                      + re.escape(resource_name) +
                      r': t=0x03[^\n]*\n\s*\(string8\) "([^"]+)"', resources, re.M)
    require(len(definitions) == 1 and match is not None,
            f'{resource_name} {ref} must resolve to one packaged XML: {definitions}')
    return match[1]


def check(apk, aapt, merged):
    check_manifest(ET.parse(merged).getroot(), packaged=False)
    refs = check_manifest(parse_aapt_tree(aapt_output(aapt, 'xmltree', str(apk), 'AndroidManifest.xml')),
                          packaged=True)
    resources = aapt_output(aapt, '--values', 'resources', str(apk))
    with zipfile.ZipFile(apk) as archive:
        for name, (resource_name, tag, sections) in RULES.items():
            ref = refs[resource_name][1:].lower()
            # Require this *ID*, not merely a similarly named resource, to resolve
            # to the packaged file whose binary XML is decoded below.
            path = resource_path(resources, ref, resource_name)
            require(path in archive.namelist(), f'{name} missing APK entry {path}')
            check_rules(parse_aapt_tree(aapt_output(aapt, 'xmltree', str(apk), path)), tag, sections)
            print(f'{name}: {ref} -> {path}; {len(DOMAINS)} excluded domains in '
                  f'{len(sections) or 1} section(s)')
    print('merged and packaged manifests: backups disabled, only non-exported AndroidX startup provider')


if __name__ == '__main__':
    try:
        check(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except (IndexError, ValueError, OSError, ET.ParseError, subprocess.CalledProcessError) as exc:
        sys.exit(f'Android storage boundary failed: {exc}')
