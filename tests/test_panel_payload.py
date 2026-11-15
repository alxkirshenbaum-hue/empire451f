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

if __name__=='__main__':unittest.main()
