import importlib.util
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

spec = importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('android_storage_boundary.py'))
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)
MAIN = Path(__file__).resolve().parents[1] / 'apps/client/src-tauri/gen/android/app/src/main'


class BoundaryTests(unittest.TestCase):
    def test_source_rules_and_manifest(self):
        manifest = ET.parse(MAIN / 'AndroidManifest.xml').getroot()
        boundary.check_manifest(manifest, packaged=False)
        for resource, tag, sections in boundary.RULES.values():
            root = ET.parse(MAIN / 'res/xml' / (resource + '.xml')).getroot()
            boundary.check_rules(root, tag, sections)

    def test_empty_or_omitted_device_transfer_rejected(self):
        exclusions = ''.join(f'<exclude domain="{d}" path="."/>' for d in sorted(boundary.DOMAINS))
        for device_section in ('', '<device-transfer/>'):
            with self.subTest(device_section=device_section):
                root = ET.fromstring('<data-extraction-rules><cloud-backup>' + exclusions
                                     + '</cloud-backup>' + device_section + '</data-extraction-rules>')
                with self.assertRaises(ValueError):
                    boundary.check_rules(root, 'data-extraction-rules', ('cloud-backup', 'device-transfer'))

    def test_provider_in_merged_or_binary_manifest_rejected(self):
        source = ET.parse(MAIN / 'AndroidManifest.xml').getroot()
        app = source.find('application')
        app.attrib[boundary.ANDROID + 'allowBackup'] = 'false'
        for attr, (name, _, _) in boundary.RULES.items():
            app.attrib[boundary.ANDROID + attr] = '@xml/' + name
        ET.SubElement(app, 'provider', {boundary.ANDROID + 'name': 'injected.Provider'})
        with self.assertRaisesRegex(ValueError, 'provider'):
            boundary.check_manifest(source, packaged=False)
        binary = boundary.parse_aapt_tree('''E: manifest (line=2)
  E: application (line=4)
    A: android:allowBackup(0x01010280)=(type 0x12)0x0
    A: android:dataExtractionRules(0x0101063e)=@0x7f100001
    A: android:fullBackupContent(0x010104eb)=@0x7f100002
    E: provider (line=7)
''')
        with self.assertRaisesRegex(ValueError, 'provider'):
            boundary.check_manifest(binary, packaged=True)

    def test_aapt_boolean_payloads(self):
        for payload, expected in (('0x0', 'false'), ('0x1', 'true'), ('0xffffffff', 'true')):
            with self.subTest(payload=payload):
                tree = boundary.parse_aapt_tree(f'''E: manifest (line=2)
  E: application (line=4)
    A: android:allowBackup(0x01010280)=(type 0x12){payload}
    A: android:dataExtractionRules(0x0101063e)=@0x7f100001
    A: android:fullBackupContent(0x010104eb)=@0x7f100002
''')
                self.assertEqual(tree.find('application').get('android:allowBackup'), expected)
                if expected == 'true':
                    with self.assertRaisesRegex(ValueError, 'allowBackup'):
                        boundary.check_manifest(tree, packaged=True)
                else:
                    boundary.check_manifest(tree, packaged=True)
        with self.assertRaisesRegex(ValueError, 'boolean'):
            boundary.parse_aapt_tree('''E: manifest (line=2)
  E: application (line=4)
    A: android:allowBackup(0x01010280)=(type 0x12)not-hex
''')

    def test_resource_variants_rejected(self):
        def definition(config, value):
            return (f'      config {config}:\n'
                    '        resource 0x7f010000 app.basehero.client:xml/app_data_extraction_rules: '
                    f'{value}\n')

        direct = ('t=0x03 d=0x00000000 (s=0x0008 r=0x00)\n'
                  '          (string8) "res/xml/app_data_extraction_rules.xml"')
        alias = ('t=0x01 d=0x7f010002 (s=0x0008 r=0x00)\n'
                 '          (reference) 0x7f010002')
        for definitions in (definition('(default)', direct) + definition('v31', alias),
                            definition('(default)', alias),
                            definition('(default)', direct) + definition('v31', direct)):
            with self.subTest(definitions=definitions):
                with self.assertRaisesRegex(ValueError, 'one packaged XML'):
                    boundary.resource_path(definitions, '0x7f010000', 'app_data_extraction_rules')
        self.assertEqual(boundary.resource_path(definition('(default)', direct), '0x7f010000',
                                                'app_data_extraction_rules'),
                         'res/xml/app_data_extraction_rules.xml')

    def test_aapt_binary_xml_exclusions(self):
        lines = ['E: data-extraction-rules (line=2)']
        for section in ('cloud-backup', 'device-transfer'):
            lines.append('  E: ' + section + ' (line=3)')
            for domain in sorted(boundary.DOMAINS):
                lines += ['    E: exclude (line=4)',
                          f'      A: domain="{domain}" (Raw: "{domain}")',
                          '      A: path="." (Raw: ".")']
        boundary.check_rules(boundary.parse_aapt_tree('\n'.join(lines)), 'data-extraction-rules',
                             ('cloud-backup', 'device-transfer'))
        lines = lines[:lines.index('  E: device-transfer (line=3)')] + ['  E: device-transfer (line=3)']
        with self.assertRaises(ValueError):
            boundary.check_rules(boundary.parse_aapt_tree('\n'.join(lines)), 'data-extraction-rules',
                                 ('cloud-backup', 'device-transfer'))


if __name__ == '__main__':
    unittest.main()
