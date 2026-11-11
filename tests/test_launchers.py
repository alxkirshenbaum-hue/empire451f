import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import controller
from test_installer import config, users


class ServerControllerTests(unittest.TestCase):
    def test_missing_saved_clients_cannot_rotate_passwords(self):
        def read(path):
            return {'installed': True} if str(path).endswith('manifest.json') else None
        with patch.object(controller.remote, 'readjson', side_effect=read):
            with self.assertRaisesRegex(controller.Invalid, 'import existing credentials'):
                controller.clients(config(), None, create=True)
    def test_first_preview_has_no_saved_state_and_no_mutations(self):
        calls = []
        class Nodes:
            def call(self, role, action, cfg, **extra):
                calls.append(action)
                if action == 'probe':
                    return {'machine_id': role, 'pending': None}
                if action == 'plan':
                    return {'changes': [], 'facts': {}}
                raise AssertionError('Unexpected mutation: ' + action)
        for answer in ('', '1', 'preview', '\x1b[200~PREVIEW\x1b[201~'):
            calls.clear()
            with self.subTest(answer=answer), patch('builtins.input', side_effect=['typo', answer]), patch.object(controller, 'ask', return_value='labtest'), patch.object(controller, 'configure', return_value=config()), patch.object(controller, 'clients', return_value=users()), patch.object(controller.remote, 'readjson', return_value=None), patch.object(controller.remote, 'atomic', side_effect=AssertionError('write')), patch.object(controller, 'store_session', side_effect=AssertionError('write')), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(controller.start(Nodes(), 'a' * 32, None), 0)
                self.assertIn('Choose a listed number', output.getvalue())
            self.assertEqual(calls, ['probe', 'probe', 'plan', 'plan'])
    def test_apply_waits_for_fresh_local_ssh_before_commit(self):
        c = config()
        captured = {}
        calls = []
        class Nodes:
            def call(self, role, action, cfg, **extra):
                calls.append((role, action))
                if action == 'probe':
                    return {'machine_id': role, 'pending': None}
                if action == 'plan':
                    return {'facts': {'machine_id': role}, 'changes': [{'action': 'create', 'path': '/etc/test'}]}
                if action == 'prepare':
                    return {'public_key': ('A' if role == 'entry' else 'B') * 43 + '='}
                return {'status': 'applied' if action == 'apply' else 'committed'}
        def store(session, state):
            captured.update(json.loads(json.dumps(state)))
        with patch('builtins.input', return_value='new'), patch.object(controller, 'configure', return_value=c), patch.object(controller, 'clients', return_value=users()), patch.object(controller, 'ask', return_value='APPLY'), patch.object(controller.remote, 'atomic'), patch.object(controller, 'store_session', side_effect=store), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.start(Nodes(), 'a' * 32, None), 42)
        self.assertNotIn(('entry', 'commit'), calls)
        self.assertNotIn(('exit', 'commit'), calls)
        with patch.object(controller.remote, 'readjson', return_value=captured), patch.object(controller, 'clients', return_value=users()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.finish(Nodes(), 'a' * 32, 'finish'), 0)
        self.assertIn(('entry', 'commit'), calls)
        self.assertIn(('exit', 'commit'), calls)

    def test_rpc_rejects_missing_auth_and_stops_cleanly(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        token = 'a' * 64
        with patch.object(controller.signal, 'signal'), patch.object(controller.signal, 'SIGHUP', 1, create=True):
            worker = threading.Thread(target=controller.rpc, args=(port, token), daemon=True)
            worker.start()
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1', port), .1):
                        break
                except OSError:
                    time.sleep(.02)
            url = 'http://127.0.0.1:' + str(port) + '/'
            req = urllib.request.Request(url, data=b'{"action":"shutdown"}')
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=3)
            self.assertEqual(cm.exception.code, 403)
            req.add_header('Authorization', 'Bearer ' + token)
            with urllib.request.urlopen(req, timeout=3) as response:
                self.assertTrue(json.load(response)['ok'])
            worker.join(3)
            self.assertFalse(worker.is_alive())

    def test_client_credentials_not_sent_to_exit(self):
        captured = {}
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        def open_request(req, **kwargs):
            captured.update(json.loads(req.data))
            return Response(b'{"ok":true,"result":{}}')
        with patch.object(controller.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = open_request
            controller.Nodes('a' * 64, 12345).call('exit', 'plan', config(), clients=users(), keys={})
        self.assertNotIn('clients', captured)


@unittest.skipUnless(os.name == 'nt', 'Windows shells unavailable')
class NativeWindowsTests(unittest.TestCase):
    def test_native_flow_with_process_level_ssh_stub(self):
        compiler = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if not compiler.exists():
            self.skipTest('C# compiler unavailable for SSH process stub')
        with tempfile.TemporaryDirectory(prefix='native launch ') as folder:
            root = Path(folder).resolve()
            code = root / 'Stub.cs'
            code.write_text(r'''
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
class Stub {
 static int Main(string[] args) {
  string exe=Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName);
  if(exe.Contains("keygen")) return 1;
  if(exe.Contains("ssh-add")) {
   if(args.Contains("-l")) return 0;
   string marker=Environment.GetEnvironmentVariable("EVPN_TEST_TRACE")+".unlock";
   if(!File.Exists(marker)){ File.WriteAllText(marker,"attempt"); return 1; }
   return 0;
  }
  string all=String.Join(" ",args), last=args.Length>0?args[args.Length-1]:"";
  string trace=Environment.GetEnvironmentVariable("EVPN_TEST_TRACE");
  if(args.Contains("-G")) {
   Console.WriteLine("hostname "+(last.Contains("198.51")?"198.51.100.10":"203.0.113.20"));
   if(last=="existing-exit") Console.WriteLine("identityfile "+Environment.GetEnvironmentVariable("EVPN_TEST_KEY")+".exit");
   Console.WriteLine("user root\nport 22\nproxyjump "+(last=="existing-exit"?"saved-hop":"none")); return 0;
  }
  if(last=="true") {
   if(args.Contains("exit") && !File.ReadAllText(args[Array.IndexOf(args,"-F")+1]).Contains("ProxyJump transit")) return 7;
   if(args.Contains("exit") && !File.ReadAllText(args[Array.IndexOf(args,"-F")+1]).Split(new[]{"Host exit\n"},StringSplitOptions.None)[1].Split(new[]{"\nHost "},StringSplitOptions.None)[0].Contains(".exit\"")) return 6;
   File.AppendAllText(trace,"ssh-check\n"); return 0;
  }
  if(all.Contains("MISSING_PYTHON")) { Console.WriteLine("READY"); return 0; }
  if(all.Contains(" rpc ")) {
   if(!last.Contains("exec\\(") || !last.Contains("\\'base64\\'")) return 10;
   if(String.IsNullOrEmpty(Environment.GetEnvironmentVariable("LC_EVPN_TOKEN"))) return 9;
   File.AppendAllText(trace,"rpc-start\n");Console.WriteLine("EVPN_RPC_READY");Console.Out.Flush();Thread.Sleep(120000);return 0;
  }
  if(all.Contains(" wizard ")) {
   if(!args.Contains("-tt")) return 8;
   if(last.EndsWith(" start")) {File.AppendAllText(trace,"apply-pending\n");Console.WriteLine("REMOTE_DIALOG_STUB");return 42;}
   if(last.EndsWith(" finish")) {File.AppendAllText(trace,"commit\n");Console.WriteLine("COMMIT_STUB");return 0;}
  }
  return 7;
 }
}
''')
            result = subprocess.run([str(compiler), '/nologo', '/out:' + str(root / 'ssh.exe'), str(code)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout)
            shutil.copy2(root / 'ssh.exe', root / 'ssh-keygen.exe')
            shutil.copy2(root / 'ssh.exe', root / 'ssh-add.exe')
            key = root / 'existing key'
            key.write_text('non-secret process-stub fixture')
            Path(str(key)+'.exit').touch()
            launcher = root / 'launcher.ps1'
            # Exercise the real encoded remote command through Windows argv parsing.
            launcher.write_text((ROOT / 'bootstrap/windows.ps1').read_text())
            harness = root / 'harness.ps1'
            harness.write_text(r'''
$ErrorActionPreference='Stop'
$global:EVPNTestAnswers=New-Object 'System.Collections.Generic.Queue[string]'
$global:EVPNTestAnswers.Enqueue('root@198.51.100.10')
$global:EVPNTestAnswers.Enqueue('existing-exit')
$global:EVPNTestAnswers.Enqueue($env:EVPN_TEST_KEY + '.pub')
$global:EVPNTestAnswers.Enqueue($env:EVPN_TEST_KEY + '.missing')
$global:EVPNTestAnswers.Enqueue($env:EVPN_TEST_KEY)
$global:EVPNTestAnswers.Enqueue('')
$global:EVPNTestAnswers.Enqueue('wrong')
$global:EVPNTestAnswers.Enqueue('2')
$global:EVPNTestAnswers.Enqueue('')
$global:EVPNTestAnswers.Enqueue('')
function Read-Host {param([string]$Prompt); if(!$global:EVPNTestAnswers.Count){throw ('Unexpected prompt: '+$Prompt)};return $global:EVPNTestAnswers.Dequeue()}
& $env:EVPN_TEST_LAUNCHER
''')
            for name in ('powershell.exe', 'pwsh.exe'):
                shell = shutil.which(name)
                if not shell:
                    continue
                trace = root / (name + '.trace')
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], EVPN_TEST_TRACE=str(trace), EVPN_TEST_KEY=str(key), EVPN_TEST_LAUNCHER=str(launcher), TEMP=str(root))
                result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(harness)], capture_output=True, timeout=30, env=env)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
                events = trace.read_text().splitlines()
                start, finish = events.index('apply-pending'), events.index('commit')
                self.assertEqual(events[start + 1:finish], ['ssh-check', 'ssh-check'])
                self.assertIn(b'REMOTE_DIALOG_STUB', result.stdout)
                self.assertIn(b'COMMIT_STUB', result.stdout)
                self.assertIn(b'Key was not unlocked', result.stdout)
                self.assertIn(b'Route 2 did not reach exit', result.stdout)

    def test_real_shells_parse_and_generate_ssh_config(self):
        source = (ROOT / 'bootstrap/native-windows.ps1.in').read_text()
        definitions = source.split("foreach($tool in @('ssh.exe'")[0].replace('__BOOT_PS__', "'fixture'")
        for name in ('powershell.exe', 'pwsh.exe'):
            shell = shutil.which(name)
            if not shell:
                continue
            with self.subTest(shell=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                target = root / 'functions.ps1'
                script = definitions + r'''
$Nodes=@{entry=@{hostname='198.51.100.10';user='root';port='22'};exit=@{hostname='203.0.113.20';user='root';port='2222'}}
$Jumps=@{exit='entry'}
$Identity='C:\Users\Example User\.ssh\key'
$Config=$env:EVPN_TEST_CONFIG
Write-Config
Write-Output 'NATIVE_FUNCTIONS_OK'
'''
                target.write_text(script, encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(target)], capture_output=True, timeout=20, env=dict(os.environ, EVPN_TEST_CONFIG=str(root / 'ssh-config')))
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertIn(b'NATIVE_FUNCTIONS_OK', result.stdout)
                value = (root / 'ssh-config').read_text()
                self.assertIn('Host entry\n HostName 198.51.100.10', value)
                self.assertIn('ProxyJump entry', value)
                self.assertIn('ForwardAgent no', value)
                self.assertNotIn('StrictHostKeyChecking no', value)

    def test_whole_native_script_parses_in_51_and_7(self):
        source = (ROOT / 'bootstrap/native-windows.ps1.in').read_text().replace('__BOOT_PS__', "'fixture'")
        for name in ('powershell.exe', 'pwsh.exe'):
            shell = shutil.which(name)
            if not shell:
                continue
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder).resolve() / 'bootstrap.ps1'
                path.write_text(source)
                command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:EVPN_SCRIPT,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Output;exit 1}'
                result = subprocess.run([shell, '-NoProfile', '-Command', command], capture_output=True, env=dict(os.environ, EVPN_SCRIPT=str(path)))
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


class NativeContractTests(unittest.TestCase):
    def test_no_local_python_package_or_agent_forwarding(self):
        for name in ('native-windows.ps1.in', 'native-macos.sh.in'):
            text = (ROOT / 'bootstrap' / name).read_text()
            self.assertNotIn('Expand-Archive', text)
            self.assertNotIn('installer.zip', text)
            self.assertNotIn('python.exe', text)
            self.assertNotIn('python.org', text)
            self.assertIn('ForwardAgent no', text)
            self.assertIn('LC_EVPN_TOKEN', text)
        loader = (ROOT / 'server_boot.py.in').read_text()
        self.assertIn('hashlib.sha256(data)', loader)
        self.assertIn('installer.zip', loader)

    @unittest.skipUnless(sys.platform == 'darwin', 'Actual macOS unavailable')
    def test_macOS_real_shell_syntax(self):
        for shell in ('/bin/bash', '/bin/zsh'):
            result = subprocess.run([shell, '-n', str(ROOT / 'bootstrap/native-macos.sh.in')], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
