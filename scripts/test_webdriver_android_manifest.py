import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest.mock import patch
from webdriver_android_manifest import check_manifest, check_apk
from android_storage_boundary import parse_aapt_tree

NS = 'http://schemas.android.com/apk/res/android'


def manifest(extra=''):
    return ET.fromstring(f'''<manifest xmlns:android="{NS}"><uses-permission android:name="android.permission.INTERNET"/>
      <uses-permission android:name="android.permission.CAMERA"/>
      <application android:allowBackup="false" android:dataExtractionRules="@xml/app_data_extraction_rules"
        android:fullBackupContent="@xml/app_full_backup_rules"><activity android:name="app.basehero.client.MainActivity"/>
        {extra}</application></manifest>''')


def packaged_xml(root):
    def emit(node, level=0):
        out = [' ' * level + 'E: ' + node.tag]
        out.extend(' ' * (level + 2) + f'A: android:{name.split("}", 1)[1]}="{value}" (Raw: "{value}")'
                   for name, value in node.attrib.items() if name.startswith('{' + NS + '}'))
        out.extend(line for child in node for line in emit(child, level + 2))
        return out
    return '\n'.join(emit(root))


class ManifestBoundary(unittest.TestCase):
    def test_only_expected_application_components(self):
        check_manifest(manifest())
        for extra in ['<provider android:name="BadProvider"/>', '<service android:name="BadService"/>',
                      '<receiver android:name="BadReceiver"/>']:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                check_manifest(manifest(extra))

    def test_packaged_device_key_permissions_are_allowed(self):
        root = manifest()
        for permission in ('android.permission.USE_BIOMETRIC',
                           'android.permission.USE_FINGERPRINT',
                           'app.basehero.client.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'):
            ET.SubElement(root, 'uses-permission', {f'{{{NS}}}name': permission})
        check_manifest(root)
        app = root.find('application')
        app.set(f'{{{NS}}}dataExtractionRules', '@0x7f120000')
        app.set(f'{{{NS}}}fullBackupContent', '@0x7f120001')
        check_manifest(parse_aapt_tree(packaged_xml(root)), packaged=True)
        # Expected device-key permissions must not admit unrelated capabilities.
        ET.SubElement(root, 'uses-permission', {f'{{{NS}}}name': 'android.permission.ACCESS_NETWORK_STATE'})
        with self.assertRaisesRegex(ValueError, 'permission'):
            check_manifest(parse_aapt_tree(packaged_xml(root)), packaged=True)

    def test_unexpected_permission_rejected(self):
        for permission in ('android.permission.VIBRATE', 'android.permission.ACCESS_NETWORK_STATE'):
            root = manifest()
            ET.SubElement(root, 'uses-permission', {f'{{{NS}}}name': permission})
            with self.subTest(permission=permission), self.assertRaises(ValueError):
                check_manifest(root)

    def test_camera_is_required_and_only_camerax_metadata_service_allowed(self):
        root = manifest()
        root.remove(root.findall('uses-permission')[1])
        with self.assertRaisesRegex(ValueError, 'permission'):
            check_manifest(root)
        root = manifest('<service android:name="androidx.camera.core.impl.MetadataHolderService" '
                        'android:exported="false"/>')
        check_manifest(root)
        root.find('application/service').set(f'{{{NS}}}exported', 'true')
        with self.assertRaisesRegex(ValueError, 'exported'):
            check_manifest(root)
        for name in ('com.google.mlkit.common.internal.MlKitComponentDiscoveryService',
                     'com.google.android.datatransport.runtime.backends.TransportBackendDiscovery'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'service'):
                check_manifest(manifest(f'<service android:name="{name}" android:exported="false"/>'))

    def test_supplied_apk_is_checked_even_when_unrelated_merged_xml_is_safe(self):
        # No Gradle path is passed. Each fake aapt response belongs to the
        # supplied archive, which is checked before runner AVD creation.
        with tempfile.TemporaryDirectory() as tmp:
            merged = Path(tmp) / 'unrelated-safe-merged.xml'
            ET.ElementTree(manifest()).write(merged)
            check_manifest(ET.parse(merged).getroot())
            apk = Path(tmp) / 'supplied.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('res/backup.xml', '')
                archive.writestr('res/transfer.xml', '')
            def rules(tag, sections, remove=False):
                root = ET.Element(tag)
                for section in sections or [None]:
                    parent = ET.SubElement(root, section) if section else root
                    for domain in sorted({'root', 'file', 'database', 'sharedpref', 'external', 'device_root', 'device_file', 'device_database', 'device_sharedpref'}):
                        if remove and domain == 'root':
                            continue
                        ET.SubElement(parent, 'exclude', domain=domain, path='.')
                return '\n'.join((' ' * (level * 2)) + 'E: ' + node.tag +
                                 (''.join('\n' + ' ' * (level * 2 + 2) + f'A: {k}="{v}" (Raw: "{v}")' for k, v in node.attrib.items()))
                                 for level, node in walk(root))
            resources = ('resource 0x7f120000 app:xml/app_data_extraction_rules: t=0x03 d=0x00000000\n'
                         '  (string8) "res/transfer.xml"\n'
                         'resource 0x7f120001 app:xml/app_full_backup_rules: t=0x03 d=0x00000000\n'
                         '  (string8) "res/backup.xml"\n')
            def verify(unsafe=False, missing=False):
                root = manifest()
                app = root.find('application')
                app.set(f'{{{NS}}}dataExtractionRules', '@0x7f120000')
                app.set(f'{{{NS}}}fullBackupContent', '@0x7f120001')
                if unsafe:
                    ET.SubElement(root, 'uses-permission', {f'{{{NS}}}name': 'android.permission.VIBRATE'})
                outputs = {
                    ('xmltree', str(apk), 'AndroidManifest.xml'): packaged_xml(root),
                    ('--values', 'resources', str(apk)): resources,
                    ('xmltree', str(apk), 'res/transfer.xml'): rules('data-extraction-rules', ('cloud-backup', 'device-transfer'), missing),
                    ('xmltree', str(apk), 'res/backup.xml'): rules('full-backup-content', (), missing),
                }
                with patch('webdriver_android_manifest.aapt_output', side_effect=lambda _, *args: outputs[args]):
                    check_apk(apk, Path('unused-aapt'))
            verify()
            with self.assertRaisesRegex(ValueError, 'permission'):
                verify(unsafe=True)
            with self.assertRaisesRegex(ValueError, 'exclusions'):
                verify(missing=True)


def walk(node, level=0):
    yield level, node
    for child in node:
        yield from walk(child, level + 1)


if __name__ == '__main__':
    unittest.main()
