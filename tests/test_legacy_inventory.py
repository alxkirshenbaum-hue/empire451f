"""Offline migration checks for the v0.3.6 installer. Uses generated fixtures only."""
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INSTALLER))
from render import file
from inspect_legacy import inspect, inspect_snapshot


class MigrationFixtures(unittest.TestCase):
    def setUp(self):
        self.names = ['master_user', 'Case', 'case']
        self.users = [{'username': n, 'password': secrets.token_urlsafe(20) + '" \\'}
                      for n in self.names]
        self.export = {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': self.users}
        self.lines = ['basic_auth ' + json.dumps(u['username']) + ' ' + json.dumps(u['password'])
                      for u in self.users]
        self.auth = file('\n'.join(self.lines))['content'].encode()
        self.digest = hashlib.sha256(self.auth).hexdigest()

    def test_exact_identity_and_missing_profile(self):
        result = inspect(self.auth, self.export, self.digest, [])
        self.assertEqual(result, dict(manifest_matches=True, duplicate_auth_names=0,
            case_collision_groups=1, caddy_only=0, export_only=0, password_conflicts=0,
            master_in_both=True, unmatched_profiles=0))

    def test_drift_and_orphans(self):
        self.users.pop()
        self.users[1]['password'] = secrets.token_urlsafe()
        self.users.append({'username': 'export-only', 'password': secrets.token_urlsafe()})
        auth = self.auth + (self.lines[0] + '\n').encode()
        result = inspect(auth, self.export, self.digest, [('Case', self.users[1]['password'])])
        self.assertEqual(result, dict(manifest_matches=False, duplicate_auth_names=1,
            case_collision_groups=1, caddy_only=1, export_only=1, password_conflicts=1,
            master_in_both=True, unmatched_profiles=1))

    def test_unrecognized_auth_stops_inspection(self):
        with self.assertRaises(ValueError):
            inspect(b'import other-file', self.export, self.digest, [])

    def test_snapshot_command(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            def write(name, obj):
                (root / name).write_text(json.dumps(obj), encoding='utf-8')

            def run(code):
                result = subprocess.run([sys.executable, '-B', str(INSTALLER / 'inspect_legacy.py'),
                                         str(root)], capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                for user in self.users:
                    self.assertNotIn(user['password'], result.stdout + result.stderr)
                return json.loads(result.stdout) if code != 2 else result.stdout

            (root / 'auth.caddy').write_bytes(self.auth)
            write('manifest.json', {'files': {'/etc/empire-vpn/nh1/auth.caddy': self.digest},
                                    'config': {'id': 'nh1', 'domain': 'vpn.invalid'}})
            write('clients.json', self.export)
            profile = {'outbounds': [dict(type='naive', server='vpn.invalid', **self.users[0])]}
            write('master_user.sfa.json', profile)
            before = {p: p.read_bytes() for p in root.iterdir()}
            first = run(1)
            self.assertEqual(first['case_collision_groups'], 1)
            self.assertEqual(first, inspect_snapshot(root))
            self.assertEqual(before, {p: p.read_bytes() for p in root.iterdir()})

            self.users.pop()
            clean = ('\n'.join(self.lines[:2]) + '\n').encode()
            (root / 'auth.caddy').write_bytes(clean)
            write('manifest.json', {'files': {'/etc/empire-vpn/nh1/auth.caddy': hashlib.sha256(clean).hexdigest()},
                                    'config': {'id': 'nh1', 'domain': 'vpn.invalid'}})
            write('clients.json', self.export)
            second = run(0)
            self.assertNotEqual(first['snapshot_sha256'], second['snapshot_sha256'])
            write('vpn-Case.json', profile)
            self.assertEqual(run(1)['profile_binding_conflicts'], 1)
            write('pending.json', {})
            self.assertEqual(run(2), '')
            (root / 'pending.json').unlink()
            (root / 'clients.json').write_text('{"clients":[],"clients":[]}', encoding='utf-8')
            self.assertEqual(run(2), '')


if __name__ == '__main__':
    unittest.main()
