import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Real Windows shell required')
class WindowsLaunchTests(unittest.TestCase):
    def shells(self):
        result = []
        for name in ('powershell.exe', 'pwsh.exe'):
            if shutil.which(name):
                result.append(shutil.which(name))
        return result

    def test_entrypoint_offline_in_supported_shells(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'Install-Vpn.ps1'), '-Action', 'preview', '-Offline', '-Config', str(ROOT / 'tests/fixture.json'), '-PythonPath', sys.executable], capture_output=True, timeout=40, env=dict(os.environ, PYTHONUTF8='1'))
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertIn(b'OFFLINE PREVIEW', result.stdout)

    def test_bootstrap_extract_verify_start_and_refuse_tampering(self):
        for shell in self.shells():
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='empire launcher ') as folder:
                root = Path(folder).resolve()
                (root / 'tmp').mkdir()
                (root / 'app').mkdir()
                package = root / 'fixture.zip'
                with zipfile.ZipFile(package, 'w') as z:
                    z.writestr('client.py', 'import sys\nprint("BOOTSTRAP_STUB",sys.argv[1])\n')
                sha = hashlib.sha256(package.read_bytes()).hexdigest()
                bootstrap = (ROOT / 'bootstrap/windows.ps1.in').read_text().replace('__BUNDLE_SHA256__', sha)
                target = root / 'bootstrap.ps1'
                target.write_text(bootstrap, encoding='utf-8')
                wrapper = root / 'harness.ps1'
                wrapper.write_text(r'''
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Archive
function Get-Command {
 param([string]$Name,[object]$ErrorAction)
 if($Name -eq 'python.exe' -or $Name -eq 'python3.exe'){[pscustomobject]@{Source=$env:EMPIRE_TEST_PYTHON}}
 else{Microsoft.PowerShell.Core\Get-Command $Name -ErrorAction SilentlyContinue}
}
function Invoke-WebRequest {
 param([switch]$UseBasicParsing,[string]$Uri,[string]$OutFile)
 Copy-Item -LiteralPath $env:EMPIRE_TEST_ZIP -Destination $OutFile
}
function Read-Host {throw 'Unexpected environment-install prompt in test'}
& $env:EMPIRE_TEST_BOOTSTRAP
''', encoding='utf-8')
                env = dict(os.environ, LOCALAPPDATA=str(root / 'app'), TEMP=str(root / 'tmp'), EMPIRE_TEST_PYTHON=sys.executable, EMPIRE_TEST_ZIP=str(package), EMPIRE_TEST_BOOTSTRAP=str(target), PYTHONUTF8='1')
                command = [shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(wrapper)]
                first = subprocess.run(command, capture_output=True, env=env, timeout=40)
                self.assertEqual(first.returncode, 0, first.stderr.decode(errors='replace'))
                self.assertIn(b'BOOTSTRAP_STUB wizard', first.stdout)
                second = subprocess.run(command, capture_output=True, env=env, timeout=40)
                self.assertEqual(second.returncode, 0, second.stderr.decode(errors='replace'))
                installed = next((root / 'app').rglob('client.py'))
                installed.write_text('changed by another process')
                tampered = subprocess.run(command, capture_output=True, env=env, timeout=40)
                self.assertNotEqual(tampered.returncode, 0)
                self.assertIn(b'changed', tampered.stderr)
                self.assertEqual(installed.read_text(), 'changed by another process')

    def test_bootstrap_bad_hash_fails_before_execution(self):
        # Same real hashing implementation as the bootstrap, across both supported shells.
        for shell in self.shells():
            with tempfile.TemporaryDirectory() as folder:
                p = Path(folder) / 'bad.zip'
                p.write_bytes(b'not the trusted bundle')
                script = (ROOT / 'bootstrap/windows.ps1.in').read_text().split('foreach($tool')[0] + "\n$h=Get-EmpireHash $env:TEST_ASSET; if($h -ne ('0'*64)){exit 7}; exit 0"
                result = subprocess.run([shell, '-NoProfile', '-Command', script], env=dict(os.environ, TEST_ASSET=str(p)), capture_output=True)
                self.assertEqual(result.returncode, 7)


class MacOSContractTests(unittest.TestCase):
    def test_launcher_uses_shared_engine_and_no_powershell(self):
        script = (ROOT / 'Install-Vpn.sh').read_text()
        boot = (ROOT / 'bootstrap/macos.sh.in').read_text()
        self.assertIn('client.py', script)
        self.assertNotIn('powershell', script.lower() + boot.lower())
        self.assertIn('shasum -a 256', boot)
        self.assertIn('"$DEST/Install-Vpn.sh"', boot)
        self.assertNotIn('latest', boot)

    @unittest.skipUnless(sys.platform == 'darwin', 'Actual macOS unavailable; not simulated as a PASS')
    def test_real_macOS_bash_and_zsh_offline(self):
        for shell in ('/bin/bash', '/bin/zsh'):
            command = '/bin/bash "$LAUNCHER" preview --offline --config "$FIXTURE"'
            result = subprocess.run([shell, '-c', command], capture_output=True, timeout=30, env=dict(os.environ, EMPIRE_PYTHON=sys.executable, LAUNCHER=str(ROOT / 'Install-Vpn.sh'), FIXTURE=str(ROOT / 'tests/fixture.json')))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'OFFLINE PREVIEW', result.stdout)
