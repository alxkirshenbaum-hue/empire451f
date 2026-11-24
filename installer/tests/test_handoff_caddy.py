"""Strict legacy/fresh admin before-image contract; no live paths or services."""
import json, os
from pathlib import Path
import subprocess, sys, unittest
from handoff_legacy import checked_caddy_cutover, checked_caddy_restore

class HandoffCaddyTests(unittest.TestCase):
    socket = '/run/evpn-labtest-caddy-admin/admin.sock'
    old = b'{\n admin off\n}\nhttps://vpn.example.com {\n respond "site"\n}\n'
    def fresh(self):
        return self.old.replace(b'admin off', ('admin unix/'+self.socket).encode())
    def test_legacy_off_transition(self):
        self.assertEqual(checked_caddy_cutover(self.old,self.fresh(),self.socket),self.fresh())
    def test_already_expected_unix_is_unchanged(self):
        self.assertEqual(checked_caddy_cutover(self.fresh(),self.fresh(),self.socket),self.fresh())
    def test_wrong_tcp_duplicate_block_extra_token_missing_rejected(self):
        for directive in (b'admin unix//run/wrong.sock',b'admin localhost:2019',
                          b'admin off\n admin unix/'+self.socket.encode(),
                          b'admin unix/'+self.socket.encode()+b'\n admin unix/'+self.socket.encode(),
                          b'admin unix/'+self.socket.encode()+b' {',
                          b'admin unix/'+self.socket.encode()+b' extra',b'# no admin'):
            with self.subTest(directive=directive):
                source=self.old.replace(b'admin off',directive)
                with self.assertRaises(ValueError):checked_caddy_cutover(source,source,self.socket)
                with self.assertRaises(ValueError):checked_caddy_restore(source,source,self.socket)
    def test_full_file_drift_rejected(self):
        for source,current in ((self.old,self.fresh()+b'\n# drift'),(self.fresh(),self.fresh()+b'\n# drift')):
            with self.assertRaises(ValueError):checked_caddy_cutover(source,current,self.socket)
            with self.assertRaises(ValueError):checked_caddy_restore(source,current,self.socket)
    def test_restore_legacy_transition_and_already_restored_replay(self):
        self.assertEqual(checked_caddy_restore(self.old,self.fresh(),self.socket),self.fresh())
        self.assertEqual(checked_caddy_restore(self.old,self.old,self.socket),self.fresh())
    def test_restore_fresh_beforeimage_and_drift(self):
        self.assertEqual(checked_caddy_restore(self.fresh(),self.fresh(),self.socket),self.fresh())
        with self.assertRaises(ValueError):checked_caddy_restore(self.fresh(),self.fresh()+b'\n# drift',self.socket)
        with self.assertRaises(ValueError):checked_caddy_restore(self.fresh().replace(b'admin unix/',b'admin tcp/'),self.fresh(),self.socket)
    @unittest.skipUnless(os.environ.get('VPN_INSTALLER_SOURCE'),'Set to pinned actual fresh installer source')
    def test_actual_fresh_renderer(self):
        root=Path(os.environ['VPN_INSTALLER_SOURCE']).resolve()
        code="import client,render,json; from pathlib import Path; c=json.loads(Path('tests/fixture.json').read_text()); c.update(panel_enabled=True,tls='ready',panel_path='/'+('a'*32)+'/'); files=render.render(c,'entry',dict(interface='ens99',ssh_port=2222),dict(entry='A'*43+'=',exit='B'*43+'='),dict(format='empire-vpn-clients',schema_version=1,clients=[dict(username='master_user',password='synthetic')]),client.bundle()); print(json.dumps(files['/etc/empire-vpn/'+c['id']+'/Caddyfile']['content']))"
        source=json.loads(subprocess.check_output([sys.executable,'-B','-c',code],cwd=root,text=True)).encode()
        self.assertIn(('admin unix/'+self.socket).encode(),source)
        self.assertEqual(checked_caddy_cutover(source,source,self.socket),source)
        self.assertEqual(checked_caddy_restore(source,source,self.socket),source)

if __name__=='__main__':unittest.main()
