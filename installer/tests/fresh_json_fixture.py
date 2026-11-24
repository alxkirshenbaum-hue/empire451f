"""Private fixture bridge for existing Q13 JSON import → legacy panel stage."""
import contextlib,hashlib,io,json,sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import client,controller,delivery,render

def main():
    directory=Path(sys.argv[1]);snap=directory/'snapshot';snap.mkdir(mode=0o700)
    raw=b'{"format":"empire-vpn-clients","schema_version":1,"clients":[{"username":"Alice","password":"Synthetic Alice exact Case"},{"username":"master_user","password":"Synthetic master imported unchanged"}]}'
    imported=directory/'input.json';imported.write_bytes(raw);imported.chmod(0o600)
    c=render.validate(json.loads((ROOT/'tests/fixture.json').read_bytes()));c['panel_enabled']=True;c['panel_path']='/'+('a'*32)+'/'
    with patch.object(controller,'names',return_value={'state':str(snap)}),patch.object(controller.secrets,'token_urlsafe',side_effect=AssertionError('Imported master password must not regenerate')),patch.object(controller.getpass,'getpass',side_effect=AssertionError('Imported JSON must not prompt')),contextlib.redirect_stdout(io.StringIO()):
        result=controller._clients(c,json.loads(imported.read_bytes()),True)
    assert result==json.loads(raw)
    files=render.render(c,'entry',dict(interface='ens99',ssh_port=2222),dict(entry='A'*43+'=',exit='B'*43+'='),result,client.bundle());base='/etc/empire-vpn/'+c['id']
    for name in ('auth.caddy','Caddyfile'):(snap/name).write_text(files[base+'/'+name]['content']);(snap/name).chmod(0o600)
    manifest=dict(transaction='fresh-json-compatibility',config=dict(id=c['id'],domain=c['domain']),files={base+'/'+name:hashlib.sha256((snap/name).read_bytes()).hexdigest() for name in ('auth.caddy','Caddyfile')})
    (snap/'manifest.json').write_text(json.dumps(manifest));(snap/'manifest.json').chmod(0o600)
    template=(ROOT/'templates/sfa-profile.json').read_text()
    for user in result['clients']:
        profile=delivery.profile(template,c,user['password'])
        next(o for o in profile['outbounds'] if o['type']=='naive')['username']=user['username']
        name='master_user.sfa.json' if user['username']=='master_user' else 'vpn-'+user['username']+'.json'
        (snap/name).write_text(json.dumps(profile));(snap/name).chmod(0o600)
    assert imported.read_bytes()==raw
    print(json.dumps(dict(snapshot=str(snap),source_sha256=hashlib.sha256(raw).hexdigest())))

if __name__=='__main__':main()
