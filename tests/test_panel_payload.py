"""Pinned panel release packaging; uses only supplied public compiled artifacts."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('panel_release',ROOT/'build_release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

class PanelPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        source=Path(os.environ['PANEL_TEST_STAGING'])
        self.sha=os.environ['PANEL_TEST_SOURCE_SHA']
        for name in release.PANEL_PATHS:
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source/name,target)
    def test_deterministic_explicit_allowlist_and_hashes(self):
        (self.root/'private.pem').write_text('must not package')
        a=release.panel_payload(self.root,self.sha)
        self.assertEqual(a,release.panel_payload(self.root,self.sha))
        payload=json.loads(a);self.assertEqual(payload['source_sha'],self.sha)
        self.assertEqual({x['path'] for x in payload['files']},{release.panel_destination(x) for x in release.PANEL_PATHS})
        for entry in payload['files']:
            data=base64.b64decode(entry['data'],validate=True)
            self.assertEqual(hashlib.sha256(data).hexdigest(),entry['sha256'])
            self.assertEqual(entry['mode'],0o755 if entry['path'].startswith('bin/') else 0o644)
    def test_unverified_source_rejected(self):
        with self.assertRaises(ValueError):release.panel_payload(self.root,'0'*40)
    def test_core_helper_modification_rejected(self):
        with (self.root/'owned_auth.py').open('ab') as out:out.write(b'\n# unreviewed\n')
        with self.assertRaises(ValueError):release.panel_payload(self.root,self.sha)
    def test_missing_required_unit_rejected(self):
        (self.root/'controlpanel/systemd/vpn-control-api.service').unlink()
        with self.assertRaises(ValueError):release.panel_payload(self.root,self.sha)
    def test_symlink_binary_rejected(self):
        path=self.root/'bin/vpnctl';path.unlink();path.symlink_to(self.root/'bin/vpn-control')
        with self.assertRaises(ValueError):release.panel_payload(self.root,self.sha)
    def test_non_elf_rejected(self):
        (self.root/'bin/vpnctl').write_bytes(b'private material'*200)
        with self.assertRaises(ValueError):release.panel_payload(self.root,self.sha)



class BootstrapBundleTests(unittest.TestCase):
    def exercise(self,names,*,mutate=None):
        import io
        import zipfile
        from unittest import mock
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            for name in names:
                archive.writestr(name,'def main(args): return 0\n' if name=='controller.py' else '')
        data=output.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'installer.zip';path.write_bytes(data);path.chmod(0o600)
            if mutate:mutate(path)
            source=(ROOT/'server_boot.py.in').read_text().replace('__BUNDLE_SHA256__',hashlib.sha256(data).hexdigest()).replace('__BUNDLE_URL__',repr('https://example.invalid/never-fetch'))
            source=source.replace('/run/empire-vpn-local-installer/installer.zip',str(path))
            with mock.patch.dict(os.environ,LC_EVPN_BUNDLE_FILE=str(path)),mock.patch('urllib.request.urlopen',side_effect=AssertionError('local path fetched network')),mock.patch.dict('sys.modules',{}),mock.patch('sys.stderr',io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(source,'server_boot.py','exec'),{'__name__':'__main__'})
                return stopped.exception.code
    def test_valid_local_bundle_never_fetches_network(self):
        self.assertEqual(self.exercise(['render.py','remote.py','client.py','delivery.py','controller.py']),0)
    def test_local_bundle_hash_mismatch_refused(self):
        self.assertEqual(self.exercise(['controller.py'],mutate=lambda p:p.write_bytes(b'changed')),1)
    def test_unsafe_member_refused(self):
        self.assertEqual(self.exercise(['../outside.py']),1)
    def test_duplicate_members_refused(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(self.exercise(['controller.py','controller.py']),1)
    def test_world_readable_local_bundle_refused(self):
        self.assertEqual(self.exercise(['controller.py'],mutate=lambda p:p.chmod(0o644)),1)

class InstallerAllowlistTests(unittest.TestCase):
    def test_unlisted_template_is_not_packaged(self):
        import zipfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('client.py','controller.py','remote.py','render.py','verify.py','versions.json','README.md','GUIDE.md','CLIENT_EXPORT_V1.md','TEST_RESULTS.md','MIGRATION_TEST.md','delivery.py','server_boot.py.in'):
                shutil.copyfile(ROOT/name,root/name)
            shutil.copytree(ROOT/'templates',root/'templates')
            shutil.copytree(ROOT/'bootstrap',root/'bootstrap')
            (root/'examples/site-handoff').mkdir(parents=True)
            (root/'templates/private.pem').write_text('not a release component')
            with mock.patch.object(release,'ROOT',root):release.build()
            with zipfile.ZipFile(root/'dist/installer.zip') as archive:
                self.assertNotIn('templates/private.pem',archive.namelist())
                self.assertIn('templates/vpn-add-user',archive.namelist())
if __name__=='__main__':unittest.main()
