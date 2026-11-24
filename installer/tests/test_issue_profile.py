import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_installer import files, users


class ProfileIssuance(unittest.TestCase):
    def exercise(self, reject):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            command = state / 'vpn-add-user'
            command.write_text(files()['/usr/local/bin/vpn-add-user']['content'], encoding='utf8')
            with patch.dict(sys.modules, {'grp': Mock(), 'fcntl': Mock()}):
                issue = runpy.run_path(str(command))['issue']
            auth = state / 'auth.caddy'
            original = files()['/etc/empire-vpn/labtest/auth.caddy']['content'].encode()
            auth.write_bytes(original)
            export = state / 'clients.json'
            export.write_text(json.dumps(users()))
            manifest = state / 'manifest.json'
            manifest.write_text(json.dumps({'files': {str(auth): hashlib.sha256(original).hexdigest()},
                'config': {'domain': 'test.example', 'entry': {'ssh': 'entry'}}}))
            profile = {'outbounds': [{'type': 'naive', 'username': 'master_user'}], 'route': {'final': 'naive-out'}}
            (state / 'master_user.sfa.json').write_text(json.dumps(profile))
            def write(path, data):
                path.write_bytes(data)
            with patch.dict(issue.__globals__, STATE=state, AUTH=auth, write=write, restart=Mock()), patch('builtins.input', return_value='y'), patch('subprocess.run', side_effect=ValueError if reject else None):
                if reject:
                    with self.assertRaises(ValueError):
                        issue('alice')
                    self.assertEqual(auth.read_bytes(), original)
                    self.assertEqual(json.loads(export.read_bytes()), users())
                    self.assertFalse((state / 'vpn-alice.json').exists())
                else:
                    issue('alice')
                    result = json.loads((state / 'vpn-alice.json').read_bytes())
                    user = json.loads(export.read_bytes())['clients'][-1]
                    self.assertEqual(result['outbounds'][0]['password'], user['password'])
                    self.assertEqual(result['route'], profile['route'])
                    self.assertIn(user['password'].encode(), auth.read_bytes())
                    self.assertEqual(json.loads(manifest.read_bytes())['files'][str(auth)], hashlib.sha256(auth.read_bytes()).hexdigest())
                    with self.assertRaises(SystemExit):
                        issue('alice')
                self.assertFalse((state / 'user-rollback.json').exists())

    def test_issue(self):
        self.exercise(False)

    def test_rollback(self):
        self.exercise(True)
