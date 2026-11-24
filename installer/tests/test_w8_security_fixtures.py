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



import json
import os
import tempfile
from unittest.mock import patch


@unittest.skipUnless(os.name == 'posix', 'descriptor security requires POSIX')
class SafeInventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        for name in checker.SECRET_LAYOUT.values():
            path = self.root / name
            path.write_bytes(b'SYNTHETIC_SECRET_CANARY')
            path.chmod(0o600)

    def audit(self):
        return checker.audit_safe(str(self.root), os.getuid())

    def test_metadata_only_all_22_and_honest_gaps(self):
        # Reading content is prohibited, even for a hash or manifest parsing.
        with patch('builtins.open', side_effect=AssertionError('content read')), patch.object(Path, 'read_bytes', side_effect=AssertionError('content read')):
            evidence = self.audit()
        self.assertTrue(evidence['inventory_complete'])
        self.assertEqual(len(evidence['checks']), 22)
        self.assertFalse(any(c['status'] == 'pass' for c in evidence['checks']))
        self.assertEqual(evidence['checks'][8]['status'], 'unknown')
        self.assertEqual(evidence['checks'][5]['status'], 'skipped_destructive')
        self.assertEqual(evidence['checks'][21]['status'], 'skipped_destructive')
        encoded = checker.serialize_safe_evidence(evidence)
        self.assertNotIn(b'CANARY', encoded)
        self.assertNotIn(str(self.root).encode(), encoded)
        self.assertLess(len(encoded), checker.MAX_EVIDENCE_BYTES)

    def test_missing_unsafe_symlink_and_hardlink(self):
        p = self.root / 'auth.caddy'
        p.unlink()
        self.assertFalse(self.audit()['inventory_complete'])
        p.symlink_to(self.root / 'clients.json')
        self.assertEqual(self.audit()['checks'][8]['status'], 'fail')
        p.unlink()
        os.link(self.root / 'clients.json', p)
        self.assertEqual(self.audit()['checks'][8]['status'], 'fail')

    def test_uid_mode_root_and_traversal(self):
        (self.root / 'clients.json').chmod(0o644)
        self.assertEqual(self.audit()['checks'][8]['status'], 'fail')
        self.assertEqual(checker.audit_safe(str(self.root), os.getuid() + 1)['root_status'], 'unsafe')
        layout = dict(checker.SECRET_LAYOUT, auth='../CANARY')
        evidence = checker.audit_safe(str(self.root), os.getuid(), layout)
        self.assertEqual(evidence['checks'][8]['status'], 'fail')
        self.assertNotIn(b'CANARY', checker.serialize_safe_evidence(evidence))
        self.root.chmod(0o755)
        self.assertEqual(self.audit()['root_status'], 'unsafe')

    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            alias = Path(outside) / 'alias'
            alias.symlink_to(self.root, target_is_directory=True)
            self.assertEqual(checker.audit_safe(str(alias), os.getuid())['root_status'], 'unsafe')

    def test_oversize_entries_and_bytes(self):
        with patch.object(checker, 'MAX_INVENTORY_ENTRIES', 2):
            evidence = self.audit()
        self.assertFalse(evidence['inventory_complete'])
        self.assertIn('oversize', [r['state'] for r in evidence['inventory']])
        with patch.object(checker, 'MAX_INVENTORY_BYTES', 1):
            evidence = self.audit()
        self.assertEqual(evidence['checks'][8]['status'], 'fail')

    def test_unknown_inventory_never_complete(self):
        (self.root / 'unknown-private-canary').write_text('CANARY')
        evidence = self.audit()
        self.assertFalse(evidence['inventory_complete'])
        self.assertNotIn(b'CANARY', checker.serialize_safe_evidence(evidence))

    def test_serializer_rejects_unknown_fields_and_values(self):
        evidence = self.audit()
        evidence['logs'] = 'CANARY'
        with self.assertRaises(ValueError):
            checker.serialize_safe_evidence(evidence)
        evidence = self.audit()
        evidence['checks'][0]['code'] = 'CANARY'
        with self.assertRaises(ValueError):
            checker.serialize_safe_evidence(evidence)
        evidence = self.audit()
        evidence['inventory'][0]['bytes'] = True
        with self.assertRaises(ValueError):
            checker.serialize_safe_evidence(evidence)


if __name__ == '__main__':
    unittest.main()
