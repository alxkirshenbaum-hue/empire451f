"""Synthetic backup proof; entry requires the isolated rehearsal root marker."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import urllib.parse
from full_worker_rehearsal import ROOT, BIN, require, run, put, request, profile_client, service_identity
from recovery_probe import Echo, EchoServer, EchoDatagram, EchoDatagramServer, start


def capture(cli, migration, worker, api_socket, cookie, old_profile, revoked_secret):
    require(Path('/.vpn-control-rehearsal').is_file(), 'isolated root required')
    public=Path('/etc/vpn-control/backup-recipient.pem')
    require(public.is_file(), 'host supplied public recipient required')
    directory=Path('/var/lib/vpn-control-backups');directory.mkdir(mode=0o750,exist_ok=True);os.chown(directory,0,981)
    Path('/root').mkdir(mode=0o700,exist_ok=True)
    work=Path('/root/backup-work');work.mkdir(mode=0o700,exist_ok=True)
    worker.update(backup_helper=str(ROOT/'backup_artifact.py'),backup_recipient=str(public),backup_directory=str(directory),backup_work=str(work))
    put('/etc/vpn-control/worker-lab.json',json.dumps(worker))
    run([cli,'backup','configure','--installation','lab','--owner-run',migration])
    put('/root/backup-session',cookie.split('=',1)[1]+'\n')
    env=dict(os.environ,VPNCTL_SESSION_FILE='/root/backup-session',VPNCTL_SOCKET=str(api_socket))
    result=subprocess.run([str(cli),'backup','create','--label','isolated restore rehearsal','--idempotency-key','00000000-0000-4000-8000-000000008501'],env=env,capture_output=True,timeout=30)
    if result.returncode:
        put('/root/backup-cli-diagnostic.stderr',result.stderr[:4096])
        raise RuntimeError('owner backup CLI failed; private bounded stderr preserved')
    run([cli,'worker','once','--installation','lab','--owner-run',migration])
    with sqlite3.connect('/var/lib/vpn-control/state.db') as db:
        row=db.execute('SELECT b.id,b.encrypted_path,b.sha256,d.manifest_sha256,d.operation_id FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE b.status="created"').fetchone()
    require(row is not None,'encrypted backup not created')
    bid,path,digest,manifest,operation=row
    require(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest,'ciphertext digest mismatch')
    require(not list(work.iterdir()),'plaintext staging leaked')
    proof=Path('/root/backup-proof');proof.mkdir(mode=0o700)
    put(proof/'old-profile.json',old_profile)
    put(proof/'context.json',json.dumps(dict(owner_run=migration,backup_id=bid,own_operation=operation,encrypted_path=path,sha256=digest,manifest_sha256=manifest,revoked_secret=revoked_secret)))
    put(proof/'ready','synthetic encrypted source complete\n')


def verify():
    require(Path('/.vpn-control-rehearsal').is_file() and set(os.listdir('/sys/class/net'))=={'lo'},'isolated root required')
    os.umask(0o077)
    proof=Path('/root/backup-proof');context=json.loads((proof/'context.json').read_bytes())
    base=Path('/etc/empire-vpn/lab');panel=Path('/var/lib/vpn-control');cert=Path('/etc/vpn-control/lab-ca.pem')
    cli=ROOT/'rehearsal-bin/vpnctl';api=ROOT/'rehearsal-bin/vpn-control'
    def unpriv(uid):return ['/usr/bin/setpriv','--reuid='+str(uid),'--regid='+str(986 if uid==999 else uid),'--clear-groups','--bounding-set=-all']
    os.environ.update(XDG_DATA_HOME='/var/lib/empire-vpn-acme',XDG_CONFIG_HOME='/var/lib/empire-vpn-acme')
    for path in (Path('/run/caddy-admin'),Path('/run/caddy-data')):path.mkdir(mode=0o700,exist_ok=True);os.chown(path,982,982)
    # Existing synthetic certificate is separately trusted fixture material,
    # explicitly excluded from the managed backup.
    run(unpriv(982)+[BIN/'caddy','validate','--config',base/'Caddyfile','--adapter','caddyfile'])
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay=start(stack,unpriv(999)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081)
        caddy=start(stack,unpriv(982)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        service_identity(relay,999);service_identity(caddy,982)
        Path('/run/vpn-control').mkdir(mode=0o755,exist_ok=True)
        socket_dir=Path('/run/vpn-control/restore-api');socket_dir.mkdir(mode=0o700);os.chown(socket_dir,981,981)
        for p in (panel,panel/'state.db',panel/'vault.key'):os.chown(p,981,981)
        process=subprocess.Popen([str(x) for x in unpriv(981)]+[str(api),'--socket',str(socket_dir/'api.sock'),'--profile-domain','lab.example','--vault-key-file',str(panel/'vault.key'),'--owner-run',context['owner_run']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stack.callback(lambda:(process.terminate(),process.wait(timeout=5)))
        import time
        for _ in range(100):
            if (socket_dir/'api.sock').exists():break
            require(process.poll() is None,'restored owner API exited');time.sleep(.05)
        service_identity(process,981)
        status,_,_=request(socket_dir/'api.sock','POST','/login',urllib.parse.urlencode(dict(username='owner',password='Synthetic W7 owner password')),{'Origin':'https://panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
        require(status==303,'captured owner password failed')
        profile=json.loads((proof/'old-profile.json').read_bytes())
        require(Path('/var/lib/empire-vpn/lab/vpn-Old-User.json').read_bytes()==(proof/'old-profile.json').read_bytes(),'old profile bytes changed')
        profile_client(stack,profile,19088,cert)
        from create_probe import probe
        probe('/etc/vpn-control/probe-lab.json','New-User',context['revoked_secret'],active=False)
        print('backup-restore: owner login / unchanged old profile fresh TCP-UoT / revoked negative / Caddy validate PASS',flush=True)



def resume_capture():
    require(Path('/.vpn-control-rehearsal').is_file(),'isolated source required')
    import time
    migration=json.loads(Path('/var/lib/empire-vpn/lab/manifest.json').read_bytes())['panel_run_id']
    socket=Path('/run/vpn-control/capture-api.sock')
    api=ROOT/'rehearsal-bin/vpn-control'
    process=subprocess.Popen(['/usr/bin/setpriv','--reuid=981','--regid=981','--clear-groups','--bounding-set=-all',str(api),'--socket',str(socket),'--profile-domain','lab.example','--vault-key-file','/var/lib/vpn-control/vault.key','--owner-run',migration],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if socket.exists():break
            require(process.poll() is None,'capture API exited');time.sleep(.05)
        status,headers,_=request(socket,'POST','/login',urllib.parse.urlencode(dict(username='owner',password='Synthetic W7 owner password')),{'Origin':'https://panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
        require(status==303,'fresh source owner login failed')
        profile=json.loads(Path('/run/profile-19081.json').read_bytes())
        secret=next(o['password'] for o in profile['outbounds'] if o['type']=='naive')
        capture(ROOT/'rehearsal-bin/vpnctl',migration,json.loads(Path('/etc/vpn-control/worker-lab.json').read_bytes()),socket,headers['Set-Cookie'].split(';',1)[0],Path('/var/lib/empire-vpn/lab/vpn-Old-User.json').read_bytes(),secret)
    finally:
        process.terminate();process.wait(timeout=5)

if __name__=='__main__':
    import sys
    if '--resume-capture' in sys.argv:resume_capture()
    else:verify()
