import unittest
import client,render
from test_installer import config,users
class AcmeEmailTests(unittest.TestCase):
 def test_contact_enables_caddy_global_email(self):
  c=config();c['acme_email']='operator@example.invalid'
  out=render.render(c,'entry',dict(interface='ens99',ssh_port=2222),dict(entry='A'*43+'=',exit='B'*43+'='),users(),client.bundle())
  body=out['/etc/empire-vpn/'+c['id']+'/Caddyfile']['content']
  self.assertIn('\n email operator@example.invalid\n',body)
  self.assertNotIn('acme_ca ',body)
 def test_unsafe_contact_refused(self):
  for address in ('a@example.org\nadmin off','a@example.org\r','x y@example.org','{$KEY}@example.org','x"@example.org','a\\b@example.org','x@пример.рф','x'*255+'@example.org'):
   with self.subTest(address=address):
    c=config();c['acme_email']=address
    with self.assertRaises(render.Invalid):render.validate(c)
if __name__=='__main__':unittest.main()
