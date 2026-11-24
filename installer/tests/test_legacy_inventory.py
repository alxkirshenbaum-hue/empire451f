"""Offline migration checks for the v0.3.6 installer. Uses generated fixtures only."""
import hashlib
import json
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INSTALLER))
from render import file
from inspect_legacy import inspect, inspect_snapshot, record_snapshot


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

    def test_registry_plan_replay_drift_and_review(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            root.chmod(0o700)
            snap = root / 'snapshot'
            snap.mkdir()
            registry = root / 'state.db'
            sql = INSTALLER / 'controlpanel' / 'migrations'
            db = sqlite3.connect(registry)
            try:
                registry.chmod(0o600)
                for version, path in enumerate(sorted(sql.glob('*.sql')), 1):
                    db.executescript(path.read_text(encoding='utf-8'))
                    db.execute('INSERT INTO schema_migrations VALUES(?,?,CURRENT_TIMESTAMP)',
                               (version, hashlib.sha256(path.read_bytes()).hexdigest()))
                db.commit()
                users = [dict(self.users[0]), dict(self.users[1], username='Legacy.Name')]
                raw = ''.join('basic_auth ' + json.dumps(u['username']) + ' ' +
                              json.dumps(u['password']) + '\n' for u in users).encode()
                (snap / 'auth.caddy').write_bytes(raw)
                def put(name, value):
                    (snap / name).write_text(json.dumps(value), encoding='utf-8')
                put('manifest.json', {'config': {'id': 'nh1', 'domain': 'vpn.invalid'},
                    'files': {'/etc/empire-vpn/nh1/auth.caddy': hashlib.sha256(raw).hexdigest()}})
                put('clients.json', dict(self.export, clients=users))
                put('master_user.sfa.json', {'outbounds': [dict(type='naive', server='vpn.invalid', **users[0])]})

                report, code = record_snapshot(snap, registry, None)
                self.assertEqual(code, 0)
                run = report['run_id']
                with ThreadPoolExecutor(2) as pool:
                    results = list(pool.map(lambda _: record_snapshot(snap, registry, run), range(2)))
                self.assertEqual(results[0], results[1])
                plan, code = results[0]
                self.assertEqual(code, 0)
                self.assertEqual([u['login'] for u in plan['users']], ['Legacy.Name', 'master_user'])
                self.assertTrue(plan['users'][0]['legacy_accepted'])
                self.assertTrue(plan['users'][1]['protected'])
                self.assertEqual(plan['snapshot_sha256'], report['snapshot_sha256'])
                docs = db.execute('SELECT kind,body FROM legacy_migration_documents WHERE run_id=?', (run,)).fetchall()
                self.assertEqual(dict(docs).keys(), {'inspection', 'plan'})
                for _, body in docs:
                    for u in users:
                        self.assertNotIn(u['password'], json.dumps(json.loads(body), ensure_ascii=False))
                        self.assertNotIn(json.dumps(u['password'])[1:-1], body)
                (snap / 'auth.caddy').write_bytes(raw + b'\n')
                self.assertEqual(record_snapshot(snap, registry, run), ({'run_id': run, 'status': 'stale'}, 1))
                review, code = record_snapshot(snap, registry, None)
                self.assertEqual(code, 1)
                self.assertEqual(record_snapshot(snap, registry, review['run_id'])[0]['status'], 'review_required')
                (snap / 'auth.caddy').write_bytes(raw)
                self.assertEqual(record_snapshot(snap, registry, run)[1], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone(), (0,))
                self.assertEqual(db.execute("SELECT count(*) FROM legacy_migration_documents WHERE kind='plan'").fetchone(), (1,))
            finally:
                db.close()


if __name__ == '__main__':
    unittest.main()
