"""Linux-only W1 design rehearsal. All state is synthetic and temporary."""
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest

if os.name == 'posix':
    import fcntl
import runpy


def write_json(path, value):
    stage = path.with_suffix('.tmp')
    stage.write_text(json.dumps(value))
    stage.replace(path)


def sources(root):
    return [root / name for name in ('auth.caddy', 'clients.json', 'master.sfa.json')]


def signature(root):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources(root)}


def checkpoint(channel, point, pause):
    if point == pause:
        channel.send(point)
        channel.recv()


def worker(root, action, expected, pause, channel, issuer):
    # Loading the old command before flock emulates an already started CLI.
    if action == 'obsolete':
        issue = runpy.run_path(str(issuer))['issue']
        issue.__globals__.update(STATE=root, AUTH=root/'auth.caddy')
    with (root/'empire-vpn.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            channel.send('waiting')
            fcntl.flock(lock, fcntl.LOCK_EX)
        if action == 'obsolete':
            try:
                issue('late-user')
            except SystemExit as exc:
                channel.send(str(exc))
                return
            raise AssertionError('obsolete writer passed its ownership check')
        manifest = root/'manifest.json'
        meta = json.loads(manifest.read_bytes())
        auth_key = str(root/'auth.caddy')
        if action == 'import':
            if meta.get('panel_generation') is not None:
                channel.send('already switched')
                return
            assert signature(root) == expected
            records = json.loads((root/'clients.json').read_bytes())['clients']
            # No credentials are needed for the W1 owner/lock proof.
            with sqlite3.connect(root/'stage.db') as db:
                db.execute('CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY COLLATE BINARY, active INTEGER)')
                db.execute('DELETE FROM users')
                db.executemany('INSERT INTO users VALUES (?,1)', [(row['username'],) for row in records])
                checkpoint(channel, 'before-stage-commit', pause)
            checkpoint(channel, 'after-stage-commit', pause)
            assert meta['files'].pop(auth_key) == expected['auth.caddy']
            meta['panel_auth_hash'] = expected['auth.caddy']
            meta['panel_generation'] = 1
            # Single atomic ownership switch gates both new and obsolete writers.
            write_json(manifest, meta)
            checkpoint(channel, 'after-owner-switch', pause)
            channel.send('switched')
            return
        if not meta.get('panel_generation'):
            channel.send('legacy owner')
            return
        with sqlite3.connect(root/'stage.db') as db:
            db.execute('CREATE TABLE IF NOT EXISTS revision (generation INTEGER NOT NULL)')
            current = db.execute('SELECT generation FROM revision').fetchone()
            generation = current[0] if current else meta['panel_generation']
            if expected != generation:
                channel.send('stale generation')
                return
            checkpoint(channel, 'locked', pause)
            db.execute('UPDATE users SET active=? WHERE login=?',
                       (0 if action == 'disable' else 1, 'Test.User'))
            db.execute('DELETE FROM revision')
            db.execute('INSERT INTO revision VALUES (?)', (generation + 1,))
            checkpoint(channel, 'during-mutation', pause)
        channel.send('committed')


@unittest.skipUnless(os.name == 'posix', 'Requires Linux flock and process signals')
class MigrationRehearsal(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.issuer = Path(__file__).resolve().parents[1]/'templates'/'vpn-add-user'
        users = [dict(username=n, password=secrets.token_urlsafe()) for n in ('master_user','Test.User','test.user')]
        auth, export, profile = sources(self.root)
        auth.write_text(''.join('basic_auth '+json.dumps(u['username'])+' '+json.dumps(u['password'])+'\n' for u in users))
        write_json(export, dict(clients=users))
        write_json(profile, dict(outbounds=[dict(type='naive', **users[0])]))
        self.before = signature(self.root)
        write_json(self.root/'manifest.json', {'files': {str(auth): self.before['auth.caddy']}})
        self.processes = []
        self.addCleanup(self.cleanup_workers)

    def cleanup_workers(self):
        for p, pipe in self.processes:
            if p.is_alive():
                p.kill()
            p.join(5)
            pipe.close()

    def start(self, action, expected=None, pause=None):
        ctx = multiprocessing.get_context('spawn')
        parent, child = ctx.Pipe()
        p = ctx.Process(target=worker, args=(self.root, action, expected, pause, child, self.issuer))
        p.start()
        child.close()
        self.processes.append((p, parent))
        return p, parent

    def recv(self, pair):
        self.assertTrue(pair[1].poll(8), 'Timed out waiting for worker')
        return pair[1].recv()

    def finish(self, pair, msg):
        self.assertEqual(self.recv(pair),msg)
        pair[0].join(5)
        self.assertEqual(pair[0].exitcode,0)

    def crash(self, action, point, expected):
        proc = self.start(action,expected,point)
        self.assertEqual(self.recv(proc),point)
        proc[0].kill()
        proc[0].join(5)
        self.assertLess(proc[0].exitcode,0)

    def check_users(self, active):
        with sqlite3.connect(self.root/'stage.db') as db:
            self.assertEqual(dict(db.execute('SELECT login,active FROM users')),
                             {'master_user':1,'test.user':1,'Test.User':active})
        self.assertEqual(signature(self.root),self.before)

    def interrupted_import(self, point, switched):
        self.crash('import',point,self.before)
        if not switched:
            self.finish(self.start('disable',1),'legacy owner')
        self.finish(self.start('import',self.before),'already switched' if switched else 'switched')
        self.check_users(1)

    def test_crash_before_stage_commit(self):
        self.interrupted_import('before-stage-commit',False)

    def test_crash_after_stage_commit(self):
        self.interrupted_import('after-stage-commit',False)

    def test_crash_after_switch(self):
        self.interrupted_import('after-owner-switch',True)

    def test_obsolete_cli_waiting_during_switch(self):
        panel = self.start('import',self.before,'after-stage-commit')
        self.assertEqual(self.recv(panel),'after-stage-commit')
        stale = self.start('obsolete')
        self.assertEqual(self.recv(stale),'waiting')
        panel[1].send('continue')
        self.finish(panel,'switched')
        self.finish(stale,'VPN accounts are managed by the panel; legacy issue refused.')
        self.check_users(1)

    def test_concurrent_revoke_and_enable(self):
        self.finish(self.start('import',self.before),'switched')
        panel = self.start('disable',1,'locked')
        self.assertEqual(self.recv(panel),'locked')
        cli = self.start('enable',1)
        self.assertEqual(self.recv(cli),'waiting')
        panel[1].send('continue')
        self.finish(panel,'committed')
        self.finish(cli,'stale generation')
        self.finish(self.start('import',self.before),'already switched')
        self.check_users(0)

    def test_crash_during_revoke(self):
        self.finish(self.start('import',self.before),'switched')
        self.crash('disable','during-mutation',1)
        self.check_users(1)
        self.finish(self.start('disable',1),'committed')
        self.check_users(0)


if __name__=='__main__':
    unittest.main(verbosity=2)
