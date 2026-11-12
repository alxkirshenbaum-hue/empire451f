"""Offline migration checks for the v0.3.6 installer. Uses generated fixtures only."""
import hashlib
import json
import secrets
import sys
import unittest
from collections import Counter
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INSTALLER))
from render import credentials, file


def auth_lines(data):
    # Managed v0.3.6 format: the installer serializes each token as a JSON string.
    decoder = json.JSONDecoder()
    for line in data.decode().splitlines():
        if not line.strip():
            continue
        directive, sep, tokens = line.strip().partition(' ')
        if directive != 'basic_auth' or not sep:
            raise ValueError('Unknown authentication directive')
        name, end = decoder.raw_decode(tokens.lstrip())
        tail = tokens.lstrip()[end:]
        if not tail.startswith((' ', '\t')):
            raise ValueError('Missing token separator')
        password = json.loads(tail)
        if not isinstance(name, str) or not isinstance(password, str):
            raise ValueError('Invalid credential fields')
        yield name, password


def inspect(auth, export, digest, profiles):
    rows = list(auth_lines(auth))
    checked = credentials(export)['clients']
    active = dict(rows)
    saved = {u['username']: u['password'] for u in checked}
    names = set(active) | set(saved)
    collisions = Counter(name.lower() for name in names)
    return {
        'manifest_matches': hashlib.sha256(auth).hexdigest() == digest,
        'duplicate_auth_names': len(rows) - len(active),
        'case_collision_groups': sum(count > 1 for count in collisions.values()),
        'caddy_only': len(active.keys() - saved.keys()),
        'export_only': len(saved.keys() - active.keys()),
        'password_conflicts': sum(active[n] != saved[n] for n in active.keys() & saved.keys()),
        'master_in_both': 'master_user' in active and 'master_user' in saved,
        'unmatched_profiles': sum(n not in active or active[n] != p for n, p in profiles),
    }


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


if __name__ == '__main__':
    unittest.main()
