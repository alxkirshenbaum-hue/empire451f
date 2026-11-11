import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import controller
import delivery
from render import Invalid
from test_installer import config, users


class DeliveryTests(unittest.TestCase):
    def test_master_stable_when_original_export_is_reimported(self):
        saved = {}
        with tempfile.TemporaryDirectory() as tmp, patch.object(controller,'names',return_value={'state':tmp}), patch.object(controller.remote,'readjson',side_effect=lambda path: saved.get(str(path))), patch.object(controller.remote,'atomic',side_effect=lambda path,data: saved.update({str(path):json.loads(data)})), contextlib.redirect_stdout(io.StringIO()) as transcript:
            original = users()
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
