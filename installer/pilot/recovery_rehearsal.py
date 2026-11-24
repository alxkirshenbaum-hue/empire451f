"""W1 recovery rehearsal. Only synthetic nh1-shaped records; no live file inputs on VPS."""
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(text):
    return base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)


def packed(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def seal(public_pem, payload):
    recipient = serialization.load_pem_public_key(public_pem)
    header = b64(packed({'alg': 'RSA-OAEP-256', 'enc': 'A256GCM'}))
    key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, payload, header.encode())
    return '.'.join((header, b64(recipient.encrypt(key, oaep())), b64(iv),
                     b64(ciphertext[:-16]), b64(ciphertext[-16:]))).encode()


def decrypt(private, envelope):
    header, wrapped, iv, body, tag = envelope.decode().split('.')
    if json.loads(unb64(header)) != {'alg': 'RSA-OAEP-256', 'enc': 'A256GCM'}:
        raise ValueError('unexpected envelope format')
    key = private.decrypt(unb64(wrapped), oaep())
    return AESGCM(key).decrypt(unb64(iv), unb64(body) + unb64(tag), header.encode())


def cred_aad(login):
    return packed([login, 1])


def fixture(public_pem, template, generation, vault, passwords):
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE users(login TEXT PRIMARY KEY COLLATE BINARY, active INTEGER, nonce BLOB, secret BLOB)')
        for login, password in passwords.items():
            nonce = os.urandom(12)
            active = generation == 1 or login != 'revoked'
            cipher = AESGCM(vault).encrypt(nonce, password.encode(), cred_aad(login))
            db.execute('INSERT INTO users VALUES (?,?,?,?)', (login, active, nonce, cipher))
        db.commit()
        db_bytes = db.serialize()
    auth = ''.join('basic_auth '+json.dumps(n)+' '+json.dumps(p)+'\n'
                   for n,p in passwords.items() if n != 'revoked' or generation == 1)
    profile = copy.deepcopy(template)
    naive, = [o for o in profile['outbounds'] if o['type']=='naive']
    naive.update(username='Test.User', password=passwords['Test.User'])
    files = {'state.db': db_bytes, 'vault.key': vault, 'auth.caddy': auth.encode(),
             'user.sfa.json': packed(profile)}
    manifest = {'format':'vpn-control-rehearsal','version':1,'generation':generation,
                'files':{name:sha(data) for name,data in files.items()}}
    payload = packed({'manifest':manifest,'contents':{k:b64(v) for k,v in files.items()}})
    envelope = seal(public_pem,payload)
    # Reference digest delivered via the authenticated SSH channel.
    return dict(envelope=envelope.decode(), sha256=sha(envelope), manifest_sha256=sha(packed(manifest)))


def recover(private, record, expected_generation, destination):
    envelope = record['envelope'].encode()
    if not hmac.compare_digest(sha(envelope), record['sha256']):
        raise ValueError('container checksum mismatch')
    package = json.loads(decrypt(private, envelope))
    manifest = package['manifest']
    if sha(packed(manifest)) != record['manifest_sha256']:
        raise ValueError('manifest reference mismatch')
    if (manifest['format'],manifest['version'],manifest['generation']) != ('vpn-control-rehearsal',1,expected_generation):
        raise ValueError('unexpected format or generation')
    names = {'state.db','vault.key','auth.caddy','user.sfa.json'}
    if set(package['contents']) != names or set(manifest['files']) != names:
        raise ValueError('unexpected files')
    files = {n:unb64(package['contents'][n]) for n in names}
    if any(sha(data)!=manifest['files'][n] for n,data in files.items()):
        raise ValueError('payload checksum mismatch')
    with sqlite3.connect(':memory:') as db:
        db.deserialize(files['state.db'])
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
            raise ValueError('database integrity check failed')
        rows=db.execute('SELECT login,active,nonce,secret FROM users').fetchall()
    passwords={n:AESGCM(files['vault.key']).decrypt(iv,secret,cred_aad(n)).decode()
               for n,active,iv,secret in rows}
    allowed={n for n,active,iv,secret in rows if active}
    if allowed != {'master_user','Test.User'} or set(passwords)!=allowed|{'revoked'}:
        raise ValueError('unexpected restored access state')
    auth=''.join('basic_auth '+json.dumps(n)+' '+json.dumps(passwords[n])+'\n'
                 for n,active,iv,secret in rows if active)
    profile=json.loads(files['user.sfa.json'])
    naive, = [o for o in profile['outbounds'] if o['type']=='naive']
    if files['auth.caddy']!=auth.encode() or naive['username']!='Test.User' or naive['password']!=passwords['Test.User']:
        raise ValueError('inconsistent restored auth or profile')
    if destination.exists():
        raise ValueError('restore destination occupied')
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        stage=Path(tmp)/'snapshot'
        stage.mkdir(mode=0o700)
        for n,data in files.items():
            (stage/n).write_bytes(data)
        stage.rename(destination)
    return {'auth':auth,'profile':profile,'revoked':passwords['revoked']}


def remote(program, args):
    # Pipe source and fixture material only via stdin; the owner's private key never enters this function.
    command = ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','hh-entry',
               'systemd-run --quiet --collect --wait --pipe -p DynamicUser=yes -p PrivateNetwork=yes '
               '-p PrivateTmp=yes -p ProtectHome=yes -p ProtectSystem=strict -p NoNewPrivileges=yes '
               '-p InaccessiblePaths="/etc/empire-vpn /var/lib/empire-vpn /run/nh1-panel-pilot" '
               '-p MemoryMax=256M -p RuntimeMaxSec=90 /usr/bin/python3 -I -']
    src = program+'\nrequest=json.loads('+repr(packed(args).decode())+')\n'
    result=subprocess.run(command,input=(src+'print(json.dumps(perform(request)))\n').encode(),capture_output=True,timeout=120)
    if result.returncode:
        # Remote exceptions may contain synthetic credentials. Report only the final exception type.
        lines=result.stderr.decode(errors='replace').splitlines()
        kind=next((line.split(':')[0] for line in reversed(lines) if line.split(':')[0].isidentifier()),'remote failure')
        raise RuntimeError(f'Isolated worker failed: {kind}')
    return json.loads(result.stdout)


def perform(request):
    vault = AESGCM.generate_key(bit_length=256)
    passwords = {n:secrets.token_urlsafe(32) for n in ('master_user','Test.User','revoked')}
    return [fixture(request['public'].encode(),request['template'],g,vault,passwords) for g in (1,2)]


def main():
    from cryptography.exceptions import InvalidTag
    os.umask(0o077)
    repo=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(repo))
    from delivery import profile
    template=profile((repo/'templates/sfa-profile.json').read_text(),{'domain':'lab.example'},'FIXTURE')
    owner=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    public=owner.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    src=Path(__file__).read_text().rsplit("\nif __name__ ==",1)[0]
    old, current=remote(src,dict(public=public.decode(),template=template))
    wrong=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        restored=root/'restored'
        material=recover(owner,current,2,restored)
        before={p.name:sha(p.read_bytes()) for p in restored.iterdir()}
        def rejected(label, private, record, error, destination=None):
            dest=destination or root/'rejected'
            try:
                recover(private,record,2,dest)
            except error:
                assert (destination is not None or not dest.exists())
                assert before=={p.name:sha(p.read_bytes()) for p in restored.iterdir()}
                print(label, 'PASS')
                return
            raise AssertionError('unexpected restore: '+label)
        rejected('wrong recipient key',wrong,current,ValueError)
        parts=current['envelope'].split('.')
        tag=bytearray(unb64(parts[-1]))
        tag[0]^=1
        parts[-1]=b64(tag)
        corrupt=dict(current,envelope='.'.join(parts))
        rejected('changed container',owner,corrupt,ValueError)
        corrupt['sha256']=sha(corrupt['envelope'].encode())
        rejected('changed tag with recomputed checksum',owner,corrupt,InvalidTag)
        rejected('valid stale backup predating revocation',owner,old,ValueError)
        rejected('occupied destination',owner,current,ValueError,restored)
        print('verified SQLite, vault, profile, revocation and atomic restore: PASS')
        probe=(repo/'pilot/recovery_probe.py').read_text()
        print('live synthetic probe:',remote(probe,material))


if __name__ == '__main__':
    main()
