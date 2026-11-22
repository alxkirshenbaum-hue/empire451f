import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client
import remote
import render

ROOT = Path(__file__).resolve().parents[1]


class PostPanelSecurityTests(unittest.TestCase):
    def setUp(self):
        self.c = render.validate(json.loads((ROOT / 'tests/fixture.json').read_text()))
        self.c['security'] = {'key_only': True}
        self.manifest = {'role': 'entry', 'config': copy.deepcopy(self.c),
                         'files': {'account-file': 'current'}, 'transaction': 'previous',
                         'panel_generation': 19, 'panel_extra': {'preserved': True}}
        self.facts = {'interface': 'ens99', 'ssh_port': 2222, 'legacy': False,
                      'owned': {}, 'saved_security': {}}
        self.keys = {'entry': 'A' * 43 + '=', 'exit': 'B' * 43 + '='}

    def test_security_render_ignores_accounts_and_other_templates(self):
        templates = {k: v for k, v in client.bundle().items() if k.startswith('host-')}
        out = render.render(self.c, 'entry', self.facts, self.keys, None, templates, security_only=True)
        self.assertEqual(set(out), remote.security_scope(self.c))
        with self.assertRaises(Exception):
            render.render(self.c, 'entry', self.facts, self.keys, None, templates)

    def test_panel_security_plan_allowed_ordinary_writer_stays_refused(self):
        with patch.object(remote, 'readjson', return_value=self.manifest), patch.object(remote.os.path, 'lexists', return_value=False), patch.object(remote, 'digest', return_value=None):
            out, changes = remote.plan(self.c, 'entry', self.facts, self.keys, None, client.bundle(), True)
            self.assertEqual(set(out), remote.security_scope(self.c))
            with self.assertRaisesRegex(render.Invalid, 'managed by the panel'):
                remote.plan(self.c, 'entry', self.facts, self.keys, None, client.bundle())
            self.manifest['config']['domain'] = 'changed.example'
            with self.assertRaisesRegex(render.Invalid, 'differs'):
                remote.plan(self.c, 'entry', self.facts, self.keys, None, client.bundle(), True)

    def journal(self):
        path = next(p for p in remote.security_scope(self.c) if '/etc/ssh/' in p)
        return {'role': 'entry', 'config': self.c, 'facts': self.facts, 'phase': 'applied',
                'files': {path: None}, 'new_hashes': {path: 'new'}, 'security_paths': [path]}

    def test_security_commit_merges_current_manifest(self):
        journal = self.journal()
        writes = {}
        def read(path, default=None):
            if str(path).endswith('pending.json'):
                return {'transaction': 'tx', 'dir': '/private/tx'}
            if str(path).endswith('journal.json'):
                return journal
            return copy.deepcopy(self.manifest)
        with patch.object(remote, 'readjson', side_effect=read), patch.object(remote.os.path, 'lexists', return_value=False), patch.object(remote, 'digest', return_value='new'), patch.object(remote, 'atomic', side_effect=lambda p, d: writes.update({str(p): json.loads(d)})), patch.object(remote, 'cancel_timer'), patch.object(Path, 'unlink'):
            remote.commit(self.c, 'tx')
        manifest = writes[remote.names(self.c)['state'] + '/manifest.json']
        self.assertEqual(manifest['panel_generation'], 19)
        self.assertEqual(manifest['panel_extra'], self.manifest['panel_extra'])
        self.assertEqual(manifest['files']['account-file'], 'current')
        self.assertEqual(manifest['transaction'], 'tx')

    def test_uncommitted_security_rollback_keeps_newer_panel_manifest(self):
        journal = self.journal()
        journal['files'] = {}
        journal['new_hashes'] = {}
        journal['security_paths'] = []
        def read(path, default=None):
            if str(path).endswith('journal.json'):
                return journal
            if str(path).endswith('pending.json'):
                return {'dir': '/private/tx'}
            return copy.deepcopy(self.manifest)
        writes = []
        with patch.object(remote, 'readjson', side_effect=read), patch.object(remote.os.path, 'lexists', return_value=False), patch.object(remote, 'atomic', side_effect=lambda p, d: writes.append(str(p))), patch.object(remote, 'cancel_timer'), patch.object(Path, 'unlink'):
            remote.rollback_local('/private/tx')
        self.assertFalse(any(p.endswith('manifest.json') for p in writes))

    def test_committed_security_rollback_merges_only_security(self):
        journal = self.journal()
        path = journal['security_paths'][0]
        before = copy.deepcopy(self.manifest)
        before['config'].pop('security')
        before['panel_generation'] = 1
        import base64
        journal['manifest'] = {'data': base64.b64encode(json.dumps(before).encode()).decode()}
        current = copy.deepcopy(self.manifest)
        current['transaction'] = 'tx'
        current['files'][path] = 'new'
        writes = {}
        def read(p, default=None):
            if str(p).endswith('journal.json'):
                return journal
            if str(p).endswith('pending.json'):
                return None
            return copy.deepcopy(current)
        with patch.object(remote, 'readjson', side_effect=read), patch.object(remote.os.path, 'lexists', return_value=False), patch.object(remote, 'digest', return_value='new'), patch.object(remote, 'run'), patch.object(remote, 'atomic', side_effect=lambda p, d: writes.update({str(p): json.loads(d)})), patch.object(remote, 'cancel_timer'), patch.object(Path, 'unlink'):
            remote.rollback_local('/private/tx')
        manifest = writes[remote.names(self.c)['state'] + '/manifest.json']
        self.assertEqual(manifest['panel_generation'], 19)
        self.assertEqual(manifest['files'], before['files'])
        self.assertNotIn('security', manifest['config'])
        self.assertEqual(manifest['panel_extra'], current['panel_extra'])
    def test_both_preflights_before_any_apply(self):
        import controller
        from unittest.mock import Mock
        node = Mock()
        facts = dict(self.facts, owned={'file': 'hash'}, pending=None, public_key=self.keys['entry'], admin_ip='direct')
        def call(role, action, config, **kwargs):
            if action == 'probe':
                return facts
            if action == 'secure-plan' and role == 'exit':
                raise render.Invalid('second preflight refused')
        node.call.side_effect = call
        with patch.object(controller.remote, 'readjson', return_value={'committed': True, 'config': self.c}), patch('builtins.input', side_effect=['y', 'y']):
            with self.assertRaisesRegex(render.Invalid, 'second preflight'):
                controller.finish(node, 'a' * 32, 'secure')
        actions = [c.args[1] for c in node.call.call_args_list]
        self.assertEqual(actions, ['probe', 'probe', 'secure-plan', 'secure-plan'])
    def test_journal_scope_and_return_intent_denied(self):
        journal = self.journal()
        journal['security_paths'].append('/etc/passwd')
        with self.assertRaisesRegex(render.Invalid, 'journal paths'):
            remote.security_journal(journal)
        with patch.object(remote.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(render.Invalid, 'returning writer'):
                remote.security_manifest(self.c, 'entry')


if __name__ == '__main__':
    unittest.main()