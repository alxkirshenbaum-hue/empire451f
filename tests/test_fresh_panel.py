"""Fresh panel route and rejection tests; never installs services."""
import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
import client,delivery,remote,render
from test_installer import config,users

class FreshPanelTests(unittest.TestCase):
    def test_exact_namespace_panel_route_and_separate_socket_identity(self):
        c=config();c['panel_enabled']=True
        files=render.render(c,'entry',dict(interface='ens99',ssh_port=2222),dict(entry='A'*43+'=',exit='B'*43+'='),users(),client.bundle())
        base='/etc/empire-vpn/'+c['id'];sb=json.loads(files[base+'/sing-box.json']['content'])
        self.assertEqual(sb['route']['final'],'wg-only')
        for rule in sb['route']['rules'][:2]:
            self.assertEqual((rule['network'],rule['port'],rule['override_address'],rule['override_port']),('tcp',443,'127.0.0.1',18650))
        self.assertEqual(sb['route']['rules'][1]['ip_cidr'],['192.0.2.119/32'])
        self.assertEqual(sb['outbounds'][-1],dict(type='direct',tag='panel-only',bind_interface='lo'))
        unit=files['/etc/systemd/system/evpn-'+c['id']+'-caddy.service']['content']
        self.assertIn('User=evpn-caddy\nGroup=evpn-caddy',unit);self.assertIn('RuntimeDirectoryMode=0700',unit)
        self.assertNotIn('CAP_NET_ADMIN',unit)
        self.assertEqual(files[base+'/auth.caddy']['group'],'evpn-caddy')
        self.assertIn('admin unix//run/evpn-'+c['id']+'-caddy-admin/admin.sock',files[base+'/Caddyfile']['content'])
    def test_profile_private_dns_is_opt_in_and_does_not_rewrite_original(self):
        template=(Path(__file__).resolve().parents[1]/'templates/sfa-profile.json').read_text();c=config()
        old=delivery.profile(template,c,'synthetic');c['panel_enabled']=True;new=delivery.profile(template,c,'synthetic')
        self.assertFalse(any(s.get('tag')=='panel-dns' for s in old['dns']['servers']))
        self.assertEqual(new['dns']['servers'][0],dict(type='hosts',tag='panel-dns',predefined={'panel.home.arpa':'192.0.2.119'}))
        self.assertEqual(new['route']['rules'][0]['outbound'],'naive-out')
        self.assertEqual(new['outbounds'],old['outbounds'])
    def test_existing_tls_is_rejected_before_any_mutating_command(self):
        c=config();c.update(panel_enabled=True,tls='ready')
        manifest=dict(role='entry',config=dict(id=c['id']))
        with patch.object(remote,'readjson',return_value=manifest),patch.object(remote.os.path,'lexists',side_effect=lambda p:str(p)=='/etc/vpn-control/private-panel'),patch.object(Path,'exists',lambda p:str(p)=='/etc/vpn-control/private-panel'),patch.object(remote,'run') as command,patch.object(remote,'atomic') as write:
            with self.assertRaisesRegex(render.Invalid,'Existing private panel TLS'):
                remote.install_panel(c,{},'owner','Synthetic owner password')
            command.assert_not_called();write.assert_not_called()
    def test_nonfresh_and_invalid_owner_fail_before_any_command(self):
        c=config();c.update(panel_enabled=True,tls='ready',mode='replace-entry')
        with patch.object(remote,'run') as command:
            with self.assertRaises(render.Invalid):remote.install_panel(c,{},'owner','Synthetic owner password')
            command.assert_not_called()

if __name__=='__main__':unittest.main()
