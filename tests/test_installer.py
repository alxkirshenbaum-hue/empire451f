import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import client
import remote
import render


def config():
    return render.validate(json.loads((ROOT / 'tests/fixture.json').read_text()))


def users():
    # Synthetic fixture assembled in memory, never a real credential export.
    return {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': 'fixture', 'password': 'synthetic test "pass" \\ value'}]}


def files(role='entry'):
    return render.render(config(), role, {'interface': 'ens99', 'ssh_port': 2222}, {'entry': 'A' * 43 + '=', 'exit': 'B' * 43 + '='}, users(), client.bundle())


class RenderingTests(unittest.TestCase):
    def test_both_roles_and_dynamic_addresses(self):
        entry, exitfiles = files(), files('exit')
        self.assertEqual(len(entry), 17)
        self.assertEqual(len(exitfiles), 5)
        e = '\n'.join(v['content'] for v in entry.values())
        x = '\n'.join(v['content'] for v in exitfiles.values())
        self.assertIn('203.0.113.20:51830', e)
        self.assertIn('ens99', x)
        self.assertIn('tcp dport 2222', x)
        self.assertNotIn('193.233.', e + x)
        self.assertNotIn('85.155.', e + x)
        self.assertNotIn('flush ruleset', x)

    def test_chain_is_http_uot_and_failclosed(self):
        out = files()
        sb = json.loads(out['/etc/empire-vpn/labtest/sing-box.json']['content'])
        self.assertEqual(sb['inbounds'][0]['type'], 'http')
        self.assertEqual(sb['outbounds'][0]['bind_interface'], 'wg0')
        self.assertEqual(sb['dns']['servers'][0]['detour'], 'wg-only')
        self.assertIn('upstream http://127.0.0.1:1081', out['/etc/empire-vpn/labtest/Caddyfile']['content'])
        ns = out['/etc/empire-vpn/labtest/namespace.nft']['content']
        self.assertIn('meta nfproto ipv6 drop', ns)
        self.assertIn('policy drop', ns)
        self.assertLess(ns.index('ip daddr {'), ns.index('oifname "wg0" accept'))

    def test_units_no_socket_cycle_or_network_admin(self):
        out = files()
        for path, spec in out.items():
            if path.endswith('.socket'):
                self.assertIn('DefaultDependencies=no', spec['content'])
                self.assertIn('After=sysinit.target', spec['content'])
            if path.endswith(('-caddy.service', '-singbox.service')):
                self.assertIn('User=evpn', spec['content'])
                self.assertIn('NetworkNamespacePath=/run/netns/naive', spec['content'])
                self.assertNotIn('CAP_NET_ADMIN', spec['content'])

    def test_credentials_import_preserved_and_escaped(self):
        value = users()
        self.assertEqual(render.credentials(value), value)
        auth = files()['/etc/empire-vpn/labtest/auth.caddy']
        self.assertEqual(auth['mode'], 0o640)
        self.assertIn(json.dumps(value['clients'][0]['password']), auth['content'])

    def test_invalid_credential_formats(self):
        for mutate in [lambda v: v.update(schema_version=2), lambda v: v['clients'].append(v['clients'][0]), lambda v: v['clients'][0].update(password='bad\nvalue')]:
            v = users()
            mutate(v)
            with self.assertRaises(render.Invalid):
                render.credentials(v)

    def test_input_injection_and_subnet_errors(self):
        for field, value in [('domain', 'x;touch /tmp/bad'), ('id', '../../root'), ('tunnel', '10.1.2.3/30'), ('relay', '10.203.71.0/30'), ('wg_port', 22)]:
            c = config()
            c[field] = value
            with self.subTest(field=field), self.assertRaises(render.Invalid):
                render.validate(c)

    def test_protected_target_refused(self):
        c = config()
        c['protected_addresses'] = [c['exit']['address']]
        with self.assertRaises(render.Invalid):
            render.validate(c)

    def test_rerun_unchanged_and_external_drift_refused(self):
        out = files()
        hashes = {p: hashlib.sha256(v['content'].encode()).hexdigest() for p, v in out.items()}
        self.assertTrue(all(x['action'] == 'unchanged' for x in render.change_plan(out, hashes, hashes)))
        drift = dict(hashes)
        drift[next(iter(drift))] = 'changed-externally'
        with self.assertRaises(render.Invalid):
            render.change_plan(out, drift, hashes)
        with self.assertRaises(render.Invalid):
            render.change_plan(out, hashes, {})


class ClientTests(unittest.TestCase):
    def test_offline_preview_no_writes_no_processes_no_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            before = list(Path(folder).rglob('*'))
            output = io.StringIO()
            with patch.object(client, 'private_root', return_value=Path(folder)), patch.object(client.subprocess, 'run', side_effect=AssertionError('process')), patch.object(client.secrets, 'token_urlsafe', side_effect=AssertionError('generated secret')), patch.object(client, 'save_private', side_effect=AssertionError('write')), contextlib.redirect_stdout(output):
                c = config()
                client.offline_preview(c, client.clients_for(c, False))
            self.assertEqual(before, list(Path(folder).rglob('*')))
            self.assertNotIn('synthetic test', output.getvalue())

    def test_ssh_errors_are_distinct(self):
        self.assertEqual(client.ssh_error('Host key verification failed.'), 'identity')
        self.assertEqual(client.ssh_error('Permission denied (publickey).'), 'authentication')
        self.assertEqual(client.ssh_error('Connection timed out'), 'network')

    def test_saved_credentials_never_regenerated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'clients.json'
            path.write_text(json.dumps(users()))
            with patch.object(client, 'private_root', return_value=Path(folder)), patch.object(client.secrets, 'token_urlsafe', side_effect=AssertionError('rotation')), patch.object(client, 'save_private'):
                self.assertEqual(client.clients_for(config(), True), users())

    def test_windows_and_macos_paths_roundtrip(self):
        for value in ['C:\\Users\\Example User\\.ssh\\ключ', '/Users/Example User/.ssh/ключ']:
            self.assertEqual(json.loads(json.dumps({'identity': value}))['identity'], value)

    def test_wizard_corrects_invalid_answer(self):
        answers = ['fresh', 'labtest', 'root@198.51.100.10', '198.51.100.10', 'root@203.0.113.20', '203.0.113.20', 'bad;domain', 'legacy', 'new', '10.203.71.0/30', '10.203.72.0/30', '51830', '', 'owner', '', 'defer', 'Q07', 'vpn.example.com', 'continue']
        with patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            c = client.wizard()
        self.assertEqual(c['domain'], 'vpn.example.com')

    def test_no_proxyjump_for_authentication_failure(self):
        ssh = client.SSH(config())
        with patch.object(ssh, 'ping', side_effect=['authentication', None]), patch.object(client, 'ask', side_effect=AssertionError('must not propose jump')):
            with self.assertRaises(render.Invalid):
                ssh.establish(False)


class RemoteSafetyTests(unittest.TestCase):
    def test_stale_session_cannot_commit_newer_transaction(self):
        with patch.object(remote, 'readjson', return_value={'transaction': 'newer', 'dir': '/state/newer'}), patch.object(remote, 'atomic', side_effect=AssertionError('write')):
            with self.assertRaisesRegex(render.Invalid, 'different transaction'):
                remote.commit(config(), expected='older')
    def test_apply_failure_restores_exact_files_and_clears_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old = root / 'etc/existing.txt'
            old.parent.mkdir()
            old.write_text('before\n')
            created = root / 'etc/new.txt'
            forward = root / 'forward'
            forward.write_text('0')
            n = render.names(config()) | {'state': str(root / 'state'), 'base': str(root / 'etc')}
            f = {'pending': None, 'machine_id': 'fixture', 'default_route': [], 'legacy': False, 'owned': {}}
            desired = {str(old): render.file('after'), str(created): render.file('created')}
            calls = []
            def runner(args, **kwargs):
                calls.append(args)
                if args[:2] == ['systemctl', 'restart']:
                    raise render.Invalid('injected activation failure')
                code = 1 if args[:2] in (['systemctl', 'is-active'], ['systemctl', 'is-enabled'], ['nft', 'list']) else 0
                return subprocess.CompletedProcess(args, code, b'', b'')
            def atomic(path, data, mode=0o600, group=None):
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data if isinstance(data, bytes) else data.encode())
            def paths(value):
                return forward if str(value) == '/proc/sys/net/ipv4/ip_forward' else (root / 'global-etc' if str(value) == '/etc/empire-vpn' else Path(value))
            request = {'facts': f, 'keys': {'exit': 'B' * 43 + '='}, 'templates': {}, 'clients': users(), 'transaction': 'testtransaction', 'sources': {'remote.py': '#fixture', 'render.py': '#fixture'}}
            with patch.object(remote, 'names', return_value=n), patch.object(remote, 'probe', return_value=f), patch.object(remote, 'plan', return_value=(desired, [{'action': 'update'}])), patch.object(remote, 'run', side_effect=runner), patch.object(remote, 'atomic', side_effect=atomic), patch.object(remote, 'Path', side_effect=paths), patch.object(remote, 'arm_timer'), patch.object(remote, 'cancel_timer'), patch.object(remote.os, 'chmod'), patch.object(remote.os, 'chown', create=True):
                with self.assertRaisesRegex(render.Invalid, 'activation failure'):
                    remote.apply(config(), 'exit', request)
            self.assertEqual(old.read_text(), 'before\n')
            self.assertFalse(created.exists())
            self.assertFalse((root / 'state/pending.json').exists())
            journal = json.loads((root / 'state/transactions/testtransaction/journal.json').read_text())
            self.assertEqual(journal['phase'], 'rolled-back')
            self.assertNotIn('data', journal['files'][str(old)])
            self.assertIn('backup', journal['files'][str(old)])
            self.assertFalse(any('flush' in ' '.join(call) for call in calls))

    def test_noop_apply_does_not_arm_timer_or_write(self):
        f = {'pending': None, 'machine_id': 'same', 'default_route': []}
        request = {'facts': f, 'keys': {}, 'templates': {}}
        with patch.object(remote, 'probe', return_value=f), patch.object(remote, 'plan', return_value=({}, [{'action': 'unchanged'}])), patch.object(remote, 'atomic', side_effect=AssertionError('write')), patch.object(remote, 'arm_timer', side_effect=AssertionError('timer')):
            self.assertEqual(remote.apply(config(), 'exit', request)['status'], 'unchanged')

    def test_legacy_exit_preserves_existing_rules_and_key_path(self):
        c = config()
        c['mode'] = 'replace-entry'
        c['exit']['kind'] = 'legacy'
        source = 'flush ruleset\ntable inet personal_host {\n chain input {\n  type filter hook input priority filter; policy drop;\n  tcp dport 22 accept\n }\n chain forward {\n  type filter hook forward priority filter; policy drop;\n  iifname "wg0" accept\n }\n}\n'
        f = {'interface': 'eth9', 'ssh_port': 22, 'legacy': True, 'key_path': '/etc/wireguard/personal.key'}
        templates = client.bundle()
        with patch.object(remote.Path, 'read_text', return_value=source):
            result = remote.desired(c, 'exit', f, {'entry': 'A' * 43 + '=', 'exit': 'B' * 43 + '='}, users(), templates)
        nft = result['/etc/nftables.conf']['content']
        self.assertIn('iifname "wg0" accept', nft)
        self.assertIn('evpn:labtest:input', nft)
        self.assertLess(nft.index('policy drop;'), nft.index('evpn:labtest:input'))
        self.assertIn('/etc/wireguard/personal.key', result['/etc/empire-vpn/labtest/network.sh']['content'])

    def test_download_rejects_wrong_checksum_without_write(self):
        response = Mock()
        response.__enter__ = Mock(return_value=io.BytesIO(b'wrong-binary'))
        response.__exit__ = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as folder, patch.object(remote.urllib.request, 'urlopen', return_value=response), patch.object(remote, 'atomic', side_effect=AssertionError('write')):
            with self.assertRaises(render.Invalid):
                remote.download('https://example.com/file', '0' * 64, Path(folder) / 'asset')

    def test_subprocess_error_does_not_disclose_output(self):
        p = subprocess.CompletedProcess(['validator'], 1, b'private-secret', b'private-secret')
        with patch.object(remote.subprocess, 'run', return_value=p):
            with self.assertRaises(render.Invalid) as cm:
                remote.run(['validator'])
        self.assertNotIn('private-secret', str(cm.exception))

    def test_existing_wireguard_key_is_only_read_for_public_part(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / 'key'
            key.write_bytes(b'synthetic-key')
            with patch.object(remote, 'text', return_value='PUBLIC') as called:
                self.assertEqual(remote.public_key(key), 'PUBLIC')
                self.assertEqual(called.call_args.args[0], ['wg', 'pubkey'])
            self.assertEqual(key.read_bytes(), b'synthetic-key')

    def test_rollback_rejects_stale_journal(self):
        c = config()
        j = {'phase': 'committed', 'config': c, 'role': 'entry', 'facts': {}}
        def read(path, default=None):
            if str(path).endswith('journal.json'):
                return j
            if str(path).endswith('manifest.json'):
                return {'transaction': 'newer'}
            return None
        with patch.object(remote, 'readjson', side_effect=read), patch.object(remote, 'run', side_effect=AssertionError('mutation')):
            with self.assertRaises(render.Invalid):
                remote.rollback_local('/var/lib/empire-vpn/labtest/transactions/older')

    def test_pending_transaction_stops_prepare_before_packages(self):
        with patch.object(remote, 'probe', return_value={'pending': {'transaction': 'old'}}), patch.object(remote, 'run', side_effect=AssertionError('mutation')):
            with self.assertRaises(render.Invalid):
                remote.prepare(config(), 'entry', {})


if __name__ == '__main__':
    unittest.main()
