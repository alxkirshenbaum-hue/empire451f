"""Operation-specific shipped Naive probes; requires PrivateNetwork=yes."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from recovery_probe import BIN, perform

def main():
    for action in ('disable','enable','rotate','delete'):
        old,new,control = (secrets.token_hex(24) for _ in range(3))
        active = action in ('enable','rotate')
        password = new if action == 'rotate' else old
        auth = 'basic_auth "canary" '+json.dumps(control)+'\n'
        if active:
            auth += 'basic_auth "target" '+json.dumps(password)+'\n'
        def check(client,run,admin):
            scratch = Path('scratch').resolve()
            scratch.mkdir(mode=0o700)
            policy = dict(address='127.0.0.1',port=18443,domain='lab.example',ca_file=str(Path('cert').resolve()),
                site_sha256=hashlib.sha256(b'site').hexdigest(),binary=str(BIN/'sing-box'),
                auth_file=str(Path('auth.caddy').resolve()),canary_login='canary',scratch_dir=str(scratch),
                tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,
                udp_mode='echo',udp_host='192.0.2.119',udp_port=19877)
            path = Path('probe.json').resolve()
            path.write_text(json.dumps(policy));path.chmod(0o600)
            request = dict(login='target',password=password,previous=old,active=active)
            result = subprocess.run([sys.executable,'-B',str(ROOT/'create_probe.py'),'--policy',str(path)],
                input=json.dumps(request).encode(),capture_output=True,timeout=180)
            if result.returncode != 0 or result.stdout.strip() != b'{"verified":true}':
                raise RuntimeError('operation-specific probe failed: '+action)
            if any(secret.encode() in result.stdout+result.stderr for secret in (old,new,control)):
                raise RuntimeError('probe disclosed a credential')
            return dict(outbounds=[dict(type='naive',server='lab.example',server_port=18443,
                username='canary',password=control,tls=dict(enabled=True))])
        perform(dict(auth=auth,udp_echo=True,revoked_login='target',revoked=old if action!='enable' else new),check)
        print(action+': fresh candidate/revocation/control TCP/UoT/TLS/site PASS')

if __name__=='__main__':
    main()
