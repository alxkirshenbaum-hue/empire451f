"""Fresh controller integration; no SSH, network or service mutations."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import controller
from render import Invalid

class FreshControllerTests(unittest.TestCase):
    def test_owner_secret_stays_out_of_session_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);ca=root/'ca.crt';ca.write_bytes(b'public certificate')
            state={'config':{'mode':'fresh','panel_enabled':True},'committed':True}
            result={'ca_path':str(ca),'panel_url':'https://panel.home.arpa/','ca_sha256':'f'*64}
            output=io.StringIO();secret='Independent owner secret'
            with patch.dict(controller.BUNDLE,{'panel/payload.json':'{}'}),patch('builtins.input',return_value='owner'),patch.object(controller.getpass,'getpass',return_value=secret),patch.object(controller.remote,'install_panel',return_value=result) as install,patch.object(controller,'session_path',return_value=root/'session.json'),patch.object(controller,'store_session') as store,contextlib.redirect_stdout(output):
                controller.setup_fresh_panel(state['config'],'session',state)
            self.assertEqual(install.call_args.args[2:],('owner',secret))
            self.assertTrue(state['panel_ready']);self.assertNotIn(secret,json.dumps(state));self.assertNotIn(secret,output.getvalue())
            self.assertEqual((root/'session.panel-ca.crt').read_bytes(),ca.read_bytes());store.assert_called_once()
    def test_panel_failure_does_not_abort_committed_vpn(self):
        state={'config':{'mode':'fresh','panel_enabled':True,'tls':'ready'},'changed':['entry','exit'],'transaction':'fixture-transaction'}
        nodes=Mock();nodes.call.return_value={'status':'committed'}
        with patch.object(controller.remote,'readjson',return_value=state),patch.object(controller,'session_path',return_value=Path('/unused')),patch.object(controller,'clients',return_value={}),patch.object(controller,'verify'),patch.object(controller,'store_session'),patch.object(controller,'handoff_profile'),patch.object(controller,'setup_fresh_panel',side_effect=Invalid('panel startup incomplete')),patch.object(controller,'abort') as abort,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(Invalid):controller.finish(nodes,'session','finish')
        self.assertTrue(state['committed']);abort.assert_not_called()
        self.assertEqual([c.args[1] for c in nodes.call.call_args_list],['health','commit','commit'])
    def test_replace_does_not_enter_fresh_panel(self):
        state={'config':{'mode':'replace-entry','tls':'ready'},'changed':[]}
        with patch.object(controller.remote,'readjson',return_value=state),patch.object(controller,'session_path',return_value=Path('/unused')),patch.object(controller,'clients',return_value={}),patch.object(controller,'verify'),patch.object(controller,'store_session'),patch.object(controller,'handoff_profile'),patch.object(controller,'setup_fresh_panel') as panel,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.finish(Mock(),'session','finish'),0)
        panel.assert_not_called()

if __name__=='__main__':unittest.main()
