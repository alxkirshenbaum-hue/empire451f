import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('w8_security', Path(__file__).resolve().parents[1] / 'pilot' / 'w8_security_check.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture():
    return dict(surfaces=[dict(kind=k, uid=981, allowed_uid=981, mode=0o600,
        regular=True, single_link=True, foreign_uid_denied=True,
        proc_root_denied=True, redacted=True) for k in sorted(checker.SURFACES)],
        off_vds_key=True, sentinel_decrypt=True, usable_restore=True,
        retention_verified=True, rotation_drill=True, disk_peak_bytes=500_000_000,
        aggregate_ram_peak_bytes=500_000_000, resource_scope_complete=True)


class SecurityFixtures(unittest.TestCase):
    def test_valid_synthetic_only(self):
        self.assertEqual(checker.check_fixture(fixture()), [])

    def test_negative_boundaries(self):
        for field, value, expected in [('uid', 982, 'OWNER_MODE'),
                ('mode', 0o644, 'OWNER_MODE'), ('mode', True, 'OWNER_MODE'),
                ('regular', False, 'LINK_BOUNDARY'),
                ('single_link', False, 'LINK_BOUNDARY'),
                ('foreign_uid_denied', False, 'FOREIGN_UID'),
                ('proc_root_denied', False, 'PROC_ROOT'),
                ('redacted', False, 'REDACTION')]:
            with self.subTest(field=field, value=value):
                data = fixture()
                data['surfaces'][0][field] = value
                self.assertIn(expected, checker.check_fixture(data))

    def test_missing_duplicate_and_malformed(self):
        for data in [None, {}, {'surfaces': [None]}, {'surfaces': [{'kind': []}]}]:
            self.assertTrue(checker.check_fixture(data))
        data = fixture()
        data['surfaces'].append(copy.deepcopy(data['surfaces'][0]))
        self.assertIn('SURFACE_SCHEMA', checker.check_fixture(data))

    def test_custody_restore_resource_gaps(self):
        for field in ['off_vds_key', 'sentinel_decrypt', 'usable_restore',
                      'retention_verified', 'rotation_drill', 'resource_scope_complete',
                      'disk_peak_bytes', 'aggregate_ram_peak_bytes']:
            data = fixture()
            del data[field]
            self.assertTrue(checker.check_fixture(data))
        for field in ['disk_peak_bytes', 'aggregate_ram_peak_bytes']:
            data = fixture()
            data[field] = 500_000_001
            self.assertTrue(checker.check_fixture(data))

    def test_output_does_not_echo_input(self):
        data = fixture()
        data['surfaces'][0]['kind'] = 'SYNTHETIC_PRIVATE_CANARY'
        self.assertNotIn('CANARY', repr(checker.check_fixture(data)))


if __name__ == '__main__':
    unittest.main()