"""File half of the Caddy saga; all paths and credentials are synthetic."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import owned_auth as owned


@unittest.skipUnless(sys.platform == 'linux', 'Linux ownership and fsync semantics')
class OwnedAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root/'var/lib/nh1'
        self.config = self.root/'etc/nh1'
        self.prepared = self.root/'panel/op'
        for path in (self.state,self.config,self.prepared):
            path.mkdir(parents=True,mode=0o700)
        self.auth = self.config/'auth.caddy'
        self.caddy = self.config/'Caddyfile'
        self.manifest = self.state/'manifest.json'
        self.auth.write_bytes(b'basic_auth "canary" "unchanged"\n')
        self.caddy.write_bytes(b'unchanged TLS/site/upstream configuration')
        meta = dict(config=dict(id='nh1'),files={str(self.caddy):owned.digest(self.caddy.read_bytes())},
                    panel_run_id='run',panel_generation=7,panel_auth_hash=owned.digest(self.auth.read_bytes()),
                    future=dict(keep=['all','fields']))
        self.manifest.write_text(json.dumps(meta))
        os.chmod(self.auth,0o640)
        try: os.setxattr(self.auth,'user.synthetic',b'preserved')
        except OSError: pass
        os.chmod(self.caddy,0o640)
        os.chmod(self.manifest,0o600)
        old = owned.encoded_auth([dict(username='canary',password='unchanged')])
        new = owned.encoded_auth([dict(username='new',password='synthetic secret')])
        self.before_config = dict(routes=[dict(handler='forward_proxy',auth_credentials=old,upstream='kept')],site='kept')
        candidate = copy.deepcopy(self.before_config)
        candidate['routes'][0]['auth_credentials'] += new
        self.prepared_file = self.prepared/'prepared.json'
        self.prepared_file.write_text(json.dumps(dict(operation='op',generation=7,before=self.before_config,candidate=candidate)))
        os.chmod(self.prepared_file,0o600)
        self.before = (self.auth.read_bytes(),self.manifest.read_bytes())
        self.intent = owned.prepare(self.state,self.auth,self.caddy,self.prepared,'op','run',7,'new','synthetic secret')

    def publish(self, rollback=False):
        owned.publish_files(self.state,'op','run',7,rollback=rollback)

    def test_commit_replay_and_return_snapshot(self):
        self.publish()
        after = (self.auth.read_bytes(),self.manifest.read_bytes())
        meta = json.loads(after[1])
        self.assertEqual(meta['panel_generation'],8)
        self.assertEqual(meta['panel_auth_hash'],owned.digest(after[0]))
        self.assertEqual(meta['future'],dict(keep=['all','fields']))
        self.assertEqual(list(owned.auth_lines(after[0])),[('canary','unchanged'),('new','synthetic secret')])
        self.assertEqual(self.auth.stat().st_mode & 0o777,0o640)
        self.assertEqual(self.manifest.stat().st_mode & 0o777,0o600)
        self.publish()
        self.assertEqual(after,(self.auth.read_bytes(),self.manifest.read_bytes()))
        self.publish(rollback=True)
        self.publish(rollback=True)
        self.assertEqual(self.before,(self.auth.read_bytes(),self.manifest.read_bytes()))

    def test_process_crash_between_replacements(self):
        for rollback in (False,True):
            for cut in (1,2):
                with self.subTest(rollback=rollback,cut=cut):
                    # Begin from the opposite complete state, preserving journal.
                    self.publish(rollback=not rollback)
                    child = '''import os,sys
from pathlib import Path
import owned_auth as o
publish=o.publish
count=0
def interrupted(path,data,**kwargs):
    global count
    publish(path,data,**kwargs)
    count+=1
    if count==int(sys.argv[3]): os._exit(86)
o.publish=interrupted
o.publish_files(Path(sys.argv[1]),'op','run',7,rollback=sys.argv[2]=='True')
'''
                    result = subprocess.run([sys.executable,'-B','-c',child,str(self.state),str(rollback),str(cut)],
                                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    self.assertEqual(result.returncode,86)
                    owned.inspect(self.state,'op','run',7)
                    self.publish(rollback=rollback)
                    expected = self.before if rollback else tuple(base64.b64decode(t['after']) for t in self.intent['targets'])
                    self.assertEqual(expected,(self.auth.read_bytes(),self.manifest.read_bytes()))

    def test_drift_and_conflicts_refused(self):
        with self.assertRaises(ValueError): owned.inspect(self.state,'other','run',7)
        with self.assertRaises(ValueError): owned.inspect(self.state,'op','run',8)
        self.auth.write_bytes(b'external change')
        for rollback in (False,True):
            with self.assertRaises(ValueError): self.publish(rollback=rollback)
        self.assertEqual(self.auth.read_bytes(),b'external change')

    def test_changed_prepared_and_unmanaged_file_refused(self):
        self.caddy.write_bytes(b'external site update')
        with self.assertRaises(ValueError): self.publish()
        self.caddy.write_bytes(b'unchanged TLS/site/upstream configuration')
        self.prepared_file.write_text('{}')
        with self.assertRaises(ValueError): self.publish()

    def test_copy_and_permissions_refused(self):
        clone = self.root/'clone'
        shutil.copytree(self.state,clone)
        with self.assertRaises(ValueError): owned.inspect(clone,'op','run',7)
        os.chmod(self.auth,0o644)
        with self.assertRaises(ValueError): self.publish()

    def test_xattr_preserved(self):
        if not hasattr(os,'setxattr'): self.skipTest('xattrs unavailable')
        try: os.getxattr(self.auth,'user.synthetic')
        except OSError: self.skipTest('filesystem does not support xattrs')
        self.publish()
        self.assertEqual(os.getxattr(self.auth,'user.synthetic'),b'preserved')
        os.setxattr(self.auth,'user.synthetic',b'external metadata change')
        with self.assertRaises(ValueError): self.publish(rollback=True)

    def test_finish_requires_committed_database(self):
        registry = self.root/'state.db'
        with sqlite3.connect(registry) as db:
            db.executescript("CREATE TABLE users(id,status); CREATE TABLE operations(id,target_id,kind,target_type,status);")
            db.execute("INSERT INTO users VALUES('u','provisioning')")
            db.execute("INSERT INTO operations VALUES('op','u','user.create','user','verifying')")
        os.chmod(registry,0o600)
        self.publish()
        with self.assertRaises(ValueError): owned.finish(self.state,'op','run',7,registry)
        self.assertTrue((self.state/'panel-auth-pending.json').exists())
        with sqlite3.connect(registry) as db:
            db.execute("UPDATE users SET status='active'")
            db.execute("UPDATE operations SET status='succeeded'")
        owned.finish(self.state,'op','run',7,registry)
        self.assertFalse((self.state/'panel-auth-pending.json').exists())

    def test_internal_helper_does_not_print_secrets(self):
        req = dict(action='inspect',state=str(self.state),operation='op',run='run',generation=7)
        helper = Path(owned.__file__)
        result = subprocess.run([sys.executable,'-B',str(helper)],input=json.dumps(req).encode(),capture_output=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout),dict(status='ok'))
        self.assertNotIn(b'synthetic secret',result.stdout+result.stderr)
        req['generation'] = 8
        result = subprocess.run([sys.executable,'-B',str(helper)],input=json.dumps(req).encode(),capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'synthetic secret',result.stdout+result.stderr)

    def test_pending_file_journal_cannot_be_replaced(self):
        original = (self.state/'panel-auth-pending.json').read_bytes()
        with self.assertRaises(ValueError):
            owned.prepare(self.state,self.auth,self.caddy,self.prepared,'other','run',7,'other','new secret')
        self.assertEqual(original,(self.state/'panel-auth-pending.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
