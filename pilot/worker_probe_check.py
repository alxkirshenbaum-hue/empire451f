"""Run the shipped worker probe against loopback Caddy/sing-box, never live WG."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from create_probe import probe
from recovery_probe import BIN, perform


def main():
    login,password,canary = 'new',secrets.token_hex(24),secrets.token_hex(24)
    auth = 'basic_auth "canary" '+json.dumps(canary)+'\nbasic_auth "new" '+json.dumps(password)+'\n'
    def check(client,run,admin):
        scratch = Path('scratch').resolve();scratch.mkdir(mode=0o700)
        policy = dict(address='127.0.0.1',port=18443,domain='lab.example',ca_file=str(Path('cert').resolve()),
                      site_sha256=hashlib.sha256(b'site').hexdigest(),binary=str(BIN/'sing-box'),
                      auth_file=str(Path('auth.caddy').resolve()),canary_login='canary',scratch_dir=str(scratch),
                      tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,
                      udp_mode='echo',udp_host='192.0.2.119',udp_port=19877)
        path = Path('probe.json').resolve();path.write_text(json.dumps(policy));path.chmod(0o600)
        result = subprocess.run([sys.executable,'-B',str(ROOT/'create_probe.py'),'--policy',str(path)],
                                input=json.dumps([login,password]).encode(),capture_output=True,timeout=90)
        if result.returncode != 0 or result.stdout.strip() != b'{"verified":true}':
            raise RuntimeError('shipped worker probe command failed')
        if password.encode() in result.stdout+result.stderr or canary.encode() in result.stdout+result.stderr:
            raise RuntimeError('probe command exposed credentials')
        # The same real probe must refuse an unrelated website baseline.
        policy['site_sha256'] = '0'*64
        path.write_text(json.dumps(policy))
        try: probe(path,login,password)
        except RuntimeError: pass
        else: raise RuntimeError('ignored website drift')
        return dict(outbounds=[dict(type='naive',server='lab.example',server_port=18443,
                                   username=login,password=password,tls=dict(enabled=True))])
    perform(dict(auth=auth,udp_echo=True,revoked_login=login,revoked=secrets.token_hex(24)),check)
    print('worker-probe: TLS/site/new/canary/TCP/UoT/wrong-password PASS')


if __name__ == '__main__':
    main()
