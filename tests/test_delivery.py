import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import tarfile
import os

import controller
import delivery
from render import Invalid
from test_installer import config, users


class DeliveryTests(unittest.TestCase):
    def test_master_stable_when_original_export_is_reimported(self):
        saved = {}
        with tempfile.TemporaryDirectory() as tmp, patch.object(controller,'names',return_value={'state':tmp}), patch.object(controller.remote,'readjson',side_effect=lambda path: saved.get(str(path))), patch.object(controller.remote,'atomic',side_effect=lambda path,data: saved.update({str(path):json.loads(data)})), contextlib.redirect_stdout(io.StringIO()) as transcript:
            original = users()
            with patch.object(controller, 'installer_lock', contextlib.nullcontext):
                first = controller.clients(config(), original, True)
                second = controller.clients(config(), original, True)
            self.assertEqual(first, second)
            self.assertEqual(first['clients'][:-1], original['clients'])
            master = first['clients'][-1]
            self.assertEqual(master['username'],'master_user')
            self.assertGreaterEqual(len(master['password']),32)
            self.assertNotIn(master['password'],transcript.getvalue())

    def test_profile_matches_generated_login_and_target(self):
        text = (Path(__file__).resolve().parents[1]/'templates/sfa-profile.json').read_text()
        result = delivery.profile(text,config(),'synthetic-password')
        proxy = result['outbounds'][0]
        self.assertEqual(proxy['server'],config()['domain'])
        self.assertTrue(proxy['tls']['enabled'])
        self.assertNotIn('server_name',proxy['tls'])
        self.assertNotIn(config()['entry']['address'],json.dumps(result))
        resolvers = {item['tag']:item for item in result['dns']['servers']}
        self.assertNotIn('detour', resolvers[proxy['domain_resolver']['server']])
        self.assertEqual(proxy['domain_resolver']['strategy'], 'ipv4_only')
        self.assertEqual(resolvers[result['dns']['final']]['detour'],proxy['tag'])
        self.assertEqual((proxy['username'],proxy['password']),('master_user','synthetic-password'))
        self.assertEqual(proxy['udp_over_tcp']['version'],2)
        self.assertEqual(result['route']['rules'][1]['domain'],['panel.home.arpa'])

    def test_invalid_zip_cannot_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            for bad in ('../escape','site/.env','site/secret.json','site/a/../../outside'):
                with zipfile.ZipFile(base/'site.zip','w') as z:
                    z.writestr('site/index.html','ok')
                    z.writestr(bad,'reject')
                with self.assertRaises(Invalid):
                    delivery.publish_site(base/'site.zip',base/'releases',base/'current')
                self.assertFalse((base/'current').exists())
                self.assertEqual(list((base/'releases').iterdir()),[])

    def test_tar_metadata_rejects_links_and_traversal(self):
        for name, kind in [('index.html',tarfile.REGTYPE),('../index.html',tarfile.REGTYPE),('index.html',tarfile.SYMTYPE),('index.html',tarfile.LNKTYPE)]:
            with tempfile.TemporaryDirectory() as tmp:
                archive=Path(tmp)/'site.tar'
                with tarfile.open(archive,'w') as t:
                    i=tarfile.TarInfo(name); i.type=kind; i.size=2 if kind==tarfile.REGTYPE else 0; i.linkname='outside' if kind!=tarfile.REGTYPE else ''
                    t.addfile(i,io.BytesIO(b'ok') if i.size else None)
                if kind==tarfile.REGTYPE:
                    with delivery.site_archive(archive) as (entries, opener):
                        self.assertEqual(entries[0][0],name)
                else:
                    with self.assertRaises(Invalid), delivery.site_archive(archive): pass

    @unittest.skipIf(os.name == 'nt', 'Publication requires Linux symlink semantics')
    def test_tar_root_publish_and_failed_replacement_preserves_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); archive=base/'site.tar'
            with tarfile.open(archive,'w') as t:
                item=tarfile.TarInfo('./index.html');item.size=2;t.addfile(item,io.BytesIO(b'ok'))
            delivery.publish_site(archive,base/'releases',base/'current')
            self.assertEqual((base/'current/index.html').read_bytes(),b'ok')
            old=(base/'current').resolve()
            with tarfile.open(archive,'w') as t:
                item=tarfile.TarInfo('../index.html');item.size=2;t.addfile(item,io.BytesIO(b'no'))
            with self.assertRaises(Invalid): delivery.publish_site(archive,base/'releases',base/'current')
            self.assertEqual((base/'current').resolve(),old)
