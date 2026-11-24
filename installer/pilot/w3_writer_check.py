"""Run W3 writer-ownership checks on synthetic files from an installer checkout."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

import fcntl


class WriterChecks(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.auth = self.root / 'auth.caddy'
        self.export = self.root / 'clients.json'
        self.manifest = self.root / 'manifest.json'
        self.lock = self.root / 'empire-vpn.lock'
        self.lock.touch()
        self.auth.write_text('basic_auth "master_user" "synthetic"\n')
        self.users = {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [
            {'username': 'master_user', 'password': 'synthetic'},
            {'username': 'retired', 'password': 'synthetic-retired'}]}
        self.export.write_text(json.dumps(self.users))
        self.meta = {'transaction': 'old', 'files': {str(self.auth): remote.digest(self.auth)}}
        self.manifest.write_text(json.dumps(self.meta))
        self.config = json.loads((SOURCE / 'tests/fixture.json').read_bytes())
        self.paths = {'state': str(self.root), 'base': str(self.root)}
        self.enterContext(patch.object(controller, 'names', return_value=self.paths))
        self.enterContext(patch.object(remote, 'names', return_value=self.paths))
        self.enterContext(patch.object(remote, 'run', side_effect=AssertionError('Unexpected system command')))
        original_open = open
        def fixture_open(path, *args, **kwargs):
            if str(path) == '/run/lock/empire-vpn.lock':
                path = self.lock
            return original_open(path, *args, **kwargs)
        self.enterContext(patch('builtins.open', side_effect=fixture_open))

    def handoff(self):
        with self.lock.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertFalse(any((self.root / p).exists() for p in ('pending.json','user-rollback.json')))
            meta = dict(self.meta)
            meta['files'] = dict(meta['files'])
            meta['panel_auth_hash'] = meta['files'].pop(str(self.auth))
            meta['panel_generation'] = 1
            meta['panel_previous_transaction'] = meta.pop('transaction')
            remote.atomic(self.manifest, json.dumps(meta))
            return meta

    def test_preloaded_cli(self):
        issue = runpy.run_path(str(SOURCE / 'templates/vpn-add-user'))['issue']
        self.handoff()
        before = [p.read_bytes() for p in (self.auth,self.export,self.manifest)]
        with patch.dict(issue.__globals__, STATE=self.root, AUTH=self.auth), self.assertRaisesRegex(
                SystemExit, 'differs from the installer manifest' if LEGACY else 'managed by the panel'):
            issue('later')
        self.assertEqual(before, [p.read_bytes() for p in (self.auth,self.export,self.manifest)])

    def test_plan_and_previously_previewed_apply(self):
        facts = {'legacy': False, 'default_route': [], 'machine_id': 'fixture', 'pending': None,
                 'owned': self.meta['files']}
        spec = {str(self.auth): {'content': self.auth.read_text()}}
        with patch.object(remote, 'desired', return_value=spec), patch.object(remote, 'probe', return_value=facts):
            _, changes = remote.plan(self.config,'entry',facts,{},self.users,{})
            self.assertEqual(changes[0]['action'],'unchanged')
            request = {'facts':dict(facts),'keys':{},'clients':self.users,'templates':{}}
            facts['owned'] = self.handoff()['files']
            msg = 'Unknown or externally modified' if LEGACY else 'managed by the panel'
            with self.assertRaisesRegex(render.Invalid,msg):
                remote.plan(self.config,'entry',facts,{},self.users,{})
            with self.assertRaisesRegex(render.Invalid,msg):
                remote.apply(self.config,'entry',request)
            self.assertFalse((self.root/'transactions').exists())

    def test_cached_rollback_journal(self):
        tx = self.root / 'transactions' / 'old'
        tx.mkdir(parents=True)
        (tx/'journal.json').write_text(json.dumps({'phase':'committed','config':self.config,'facts':{},'role':'entry'}))
        self.handoff()
        with self.assertRaisesRegex(render.Invalid,'not the latest transaction'):
            remote.rollback_local(tx)

    def test_updated_resume_paths(self):
        if LEGACY:
            self.skipTest('Updated installer guards only')
        self.handoff()
        tx = self.root / 'transactions' / 'old'
        tx.mkdir(parents=True)
        (tx/'journal.json').write_text(json.dumps({'phase':'applied','config':self.config,'role':'entry','facts':{}}))
        (self.root/'pending.json').write_text(json.dumps({'dir':str(tx),'transaction':'old'}))
        for operation in (lambda: remote.prepare(self.config,'entry',{}),
                          lambda: remote.rollback_local(tx),
                          lambda: remote.commit(self.config,'old')):
            with self.assertRaisesRegex(render.Invalid,'managed by the panel'):
                operation()
        (self.root/'pending.json').unlink()
        (self.root/'user-rollback.json').write_text('unreadable fixture')
        issue = runpy.run_path(str(SOURCE / 'templates/vpn-add-user'))['issue']
        with patch.dict(issue.__globals__, STATE=self.root, AUTH=self.auth), self.assertRaisesRegex(
                SystemExit, 'managed by the panel'):
            issue('later')
        with patch.object(controller,'BUNDLE',{'templates/sfa-profile.json':'fixture'}), patch.object(
                controller.delivery,'profile',return_value={}), self.assertRaisesRegex(render.Invalid,'managed by the panel'):
            controller.handoff_profile(self.config,self.users,'old')
        self.assertFalse((self.root/'master_user.sfa.json').exists())

    def test_export_writer_at_handoff(self):
        original = remote.atomic
        newer = dict(self.users, clients=self.users['clients'][:1])
        def delayed_write(path,data):
            if LEGACY:
                # Legacy wizard read both rows before cutover. Pause just before rename.
                with patch.object(remote,'atomic',original):
                    self.handoff()
                original(self.export,json.dumps(newer))
            else:
                with self.lock.open('a') as competitor, self.assertRaises(BlockingIOError):
                    fcntl.flock(competitor,fcntl.LOCK_EX | fcntl.LOCK_NB)
            original(path,data)
        with patch.object(remote,'atomic',side_effect=delayed_write), contextlib.redirect_stdout(io.StringIO()):
            controller.clients(self.config,None,create=True)
        if LEGACY:
            self.assertEqual(json.loads(self.export.read_bytes()),self.users,
                             'Expected historical wizard to overwrite the newer export')
        else:
            self.handoff()
            original(self.export,json.dumps(newer))
            with self.assertRaisesRegex(render.Invalid,'managed by the panel'):
                controller.clients(self.config,None,create=True)
            self.assertEqual(json.loads(self.export.read_bytes()),newer)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path)
    parser.add_argument('--v036',action='store_true',help='Assert historical v0.3.6 behavior')
    args = parser.parse_args()
    SOURCE, LEGACY = args.source.resolve(), args.v036
    sys.path.insert(0,str(SOURCE))
    import controller
    import remote
    import render
    unittest.main(argv=[sys.argv[0]],verbosity=2)
