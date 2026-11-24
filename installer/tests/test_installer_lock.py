"""Shared installer lock regression on real files; no live paths or services."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import remote
from render import Invalid


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'Requires isolated Linux root filesystem fixture')
class InstallerLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'lock'

    def test_new_lock_is_private_under_umask022(self):
        previous = os.umask(0o022)
        try:
            with remote.open_installer_lock(self.path):
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        finally:
            os.umask(previous)

    def test_existing_0644_is_normalized_without_replacing_inode(self):
        self.path.write_text('')
        self.path.chmod(0o644)
        inode = self.path.stat().st_ino
        with remote.open_installer_lock(self.path) as lock:
            self.assertEqual(os.fstat(lock.fileno()).st_ino, inode)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_existing_flock_is_not_bypassed(self):
        import fcntl
        with remote.open_installer_lock(self.path) as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with remote.open_installer_lock(self.path) as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(held, fcntl.LOCK_UN)
        with remote.open_installer_lock(self.path) as contender:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_symlink_does_not_chmod_target(self):
        target = self.path.with_name('target')
        target.write_text('preserved')
        target.chmod(0o644)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            remote.open_installer_lock(self.path)
        self.assertEqual(target.read_text(), 'preserved')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_nonregular_file_refused_without_blocking(self):
        os.mkfifo(self.path, 0o644)
        with self.assertRaises(Invalid):
            remote.open_installer_lock(self.path)
        self.assertTrue(stat.S_ISFIFO(self.path.stat().st_mode))

    def test_nonroot_file_refused_before_chmod(self):
        self.path.write_text('preserved')
        self.path.chmod(0o644)
        os.chown(self.path, 65534, 65534)
        with self.assertRaises(Invalid):
            remote.open_installer_lock(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    def test_hardlinked_file_refused_before_chmod(self):
        self.path.write_text('preserved')
        self.path.chmod(0o644)
        os.link(self.path, self.path.with_name('other'))
        with self.assertRaises(Invalid):
            remote.open_installer_lock(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)


class PanelStageTests(unittest.TestCase):
    def test_stage_and_exit_visible_but_output_and_args_hidden(self):
        result = subprocess.CompletedProcess(['secret-argument'], 5, b'secret-out', b'secret-err')
        with patch.object(remote, 'run', return_value=result):
            with self.assertRaisesRegex(Invalid, r'registry initialization \(exit 5\)') as error:
                remote.panel_command('registry initialization', ['secret-argument'], {})
        self.assertNotIn('secret', str(error.exception))

    def test_timeout_does_not_echo_output_or_args(self):
        with patch.object(remote, 'run', side_effect=Invalid('secret-output')):
            with self.assertRaisesRegex(Invalid, 'owner initialization; command timed out') as error:
                remote.panel_command('owner initialization', ['secret-argument'], {})
        self.assertNotIn('secret', str(error.exception))

    def test_unchecked_service_probe_stays_unchecked(self):
        result = subprocess.CompletedProcess(['systemctl'], 3)
        with patch.object(remote, 'run', return_value=result):
            self.assertIs(remote.panel_command('service startup', ['systemctl'], {}, check=False), result)


class PanelReadinessTests(unittest.TestCase):
    def attempt(self,exit_code,status):
        result=subprocess.CompletedProcess(['curl'],exit_code,status,b'secret diagnostics')
        with patch.object(remote.shutil,'which',return_value='/usr/bin/curl'),patch.object(remote,'panel_command',return_value=result),patch.object(remote.time,'monotonic',side_effect=[0,31]):
            return remote.wait_panel_https([],Path('/public-ca.crt'),{'PATH':'/usr/bin'})

    def test_success_requires_http200(self):
        self.attempt(0,b'200')

    def test_non200_never_counts_as_ready(self):
        for code in (b'302',b'404',b'503'):
            with self.subTest(code=code),self.assertRaises(Invalid):self.attempt(0,code)

    def test_transport_or_tls_error_never_counts_as_ready(self):
        for code in (7,60):
            with self.subTest(code=code),self.assertRaises(Invalid):self.attempt(code,b'000')

    def test_unknown_status_does_not_leak_output(self):
        with self.assertRaises(Invalid) as error:self.attempt(22,b'secret output')
        self.assertNotIn('secret',str(error.exception))


if __name__ == '__main__':
    unittest.main()
