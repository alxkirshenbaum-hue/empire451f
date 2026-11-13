"""Rehearse real CLI paths only inside the dedicated RootDirectory/loopback unit."""
import contextlib
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import sqlite3
import subprocess
import sys
import threading
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from recovery_probe import BIN, Echo, EchoServer, EchoDatagram, EchoDatagramServer, start, attempt
from inspect_legacy import record_snapshot
from return_legacy import restore


def require(value,label):
    if not value: raise RuntimeError(label)


def run(args, input=None, env=None):
    result = subprocess.run([str(a) for a in args],input=input,capture_output=True,timeout=120,env=env)
    require(result.returncode == 0,'rehearsal subprocess failed: '+Path(str(args[0])).name)
    return result.stdout


def put(path,data,mode=0o600,gid=None):
    path = Path(path)
    path.write_bytes(data if isinstance(data,bytes) else data.encode())
    path.chmod(mode)
    if gid is not None: os.chown(path,0,gid)


def request(path,method,route,body=None,headers=None):
    conn = http.client.HTTPConnection('localhost',timeout=10)
    conn.sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    conn.sock.connect(str(path))
    try:
        conn.request(method,route,body,headers or {})
        response = conn.getresponse()
        return response.status,dict(response.getheaders()),response.read()
    finally: conn.close()


def profile_client(stack,profile,port,cert):
    original=Path('/run/profile-'+str(port)+'.json')
    put(original,json.dumps(profile));run([BIN/'sing-box','check','-c',original])
    copied=copy.deepcopy(profile)
    outbound=next(o for o in copied['outbounds'] if o['type']=='naive')
    outbound.update(server='127.0.0.1',server_port=18443);outbound.pop('domain_resolver',None)
    outbound['tls'].update(server_name='lab.example',certificate_path=str(cert))
    client=dict(log=dict(disabled=True),inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=port)],outbounds=[outbound])
    path=Path('/run/client-'+str(port)+'.json');put(path,json.dumps(client))
    start(stack,[BIN/'sing-box','run','-c',path],port)
    require(attempt(port),'profile failed fresh TCP')
    from verify import udp
    nonce=secrets.token_bytes(24)
    require(udp(port,'192.0.2.119',19877,nonce)==nonce,'profile failed UoT')
    return outbound


def service_identity(process,uid):
    status=dict(line.split(':',1) for line in Path('/proc/'+str(process.pid)+'/status').read_text().splitlines() if ':' in line)
    require(int(status['Uid'].split()[1])==uid and int(status['CapEff'].strip(),16)==0,'service identity/capability mismatch')
    require(os.stat('/proc/'+str(process.pid)+'/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino,'wrong staging network namespace')


def main():
    require(Path('/.vpn-control-rehearsal').is_file() and set(os.listdir('/sys/class/net')) == {'lo'},'dedicated isolated root required')
    os.umask(0o077)
    base,state,panel = Path('/etc/empire-vpn/lab'),Path('/var/lib/empire-vpn/lab'),Path('/var/lib/vpn-control')
    for p in (base,state,panel,Path('/etc/vpn-control'),Path('/run/lock'),Path('/run/vpn-control/probes'),Path('/run/caddy-admin'),Path('/run/caddy-data'),Path('/run/relay')):
        p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
    base.parent.chmod(0o755)
    base.chmod(0o750);os.chown(base,0,65534)
    for p in (Path('/run/caddy-admin'),Path('/run/caddy-data')):os.chown(p,65534,65534)
    os.chown('/run/relay',65533,65533)
    Path('/run/vpn-control').chmod(0o755)
    put('/run/lock/empire-vpn.lock',b'')
    canary,owner_password = secrets.token_hex(24),secrets.token_hex(24)
    put('/run/fixture.json',json.dumps(dict(OwnerPassword=owner_password)))
    env=dict(os.environ,VPN_REHEARSAL_FIXTURE='init')
    tests=ROOT/'rehearsal-bin/vpnctl-tests';cli=ROOT/'rehearsal-bin/vpnctl';api=ROOT/'rehearsal-bin/vpn-control'
    run([tests,'-test.run=^TestRehearsalFixture$'],env=env)
    auth=b'basic_auth "master_user" '+json.dumps(canary).encode()+b'\n'
    put(base/'auth.caddy',auth,0o640,65534)
    run(['openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1','-subj','/CN=lab.example',
         '-addext','subjectAltName=DNS:lab.example','-keyout',base/'key','-out',base/'cert'])
    for name in ('key','cert'):os.chown(base/name,0,65534);(base/name).chmod(0o640)
    caddyfile=('{'+'\n admin unix//run/caddy-admin/admin.sock\n persist_config off\n auto_https off\n order forward_proxy before file_server\n}\n'
               'https://:18443 {\n bind 127.0.0.1\n tls '+str(base/'cert')+' '+str(base/'key')+'\n route {\n forward_proxy {\n import '+str(base/'auth.caddy')+
               '\n hide_ip\n hide_via\n probe_resistance\n upstream http://127.0.0.1:1081\n }\n respond "site" 200\n }\n}\n')
    put(base/'Caddyfile',caddyfile,0o640,65534)
    # Canonical inspection/import retains the exact old credential and profile.
    snapshot=Path('/run/snapshot');snapshot.mkdir(mode=0o700)
    template=json.loads((ROOT/'templates/sfa-profile.json').read_bytes())
    for outbound in template['outbounds']:
        if outbound['type']=='naive':outbound.update(server='lab.example',username='master_user',password=canary)
    old_profile=json.dumps(template).encode();put(snapshot/'master_user.sfa.json',old_profile)
    put(snapshot/'auth.caddy',auth)
    put(snapshot/'clients.json',json.dumps(dict(format='empire-vpn-clients',schema_version=1,clients=[dict(username='master_user',password=canary)])))
    manifest=dict(transaction='synthetic-baseline',config=dict(id='lab',domain='lab.example'),files={str(base/'auth.caddy'):hashlib.sha256(auth).hexdigest(),str(base/'Caddyfile'):hashlib.sha256(caddyfile.encode()).hexdigest()})
    put(snapshot/'manifest.json',json.dumps(manifest))
    db=panel/'state.db';key=panel/'vault.key'
    report,code=record_snapshot(snapshot,db,None);require(code==0,'snapshot not clean');migration=report['run_id']
    _,code=record_snapshot(snapshot,db,migration);require(code==0,'plan refused')
    run([cli,'migration','execute','--approved-plan',migration,'--staging-db',db,'--snapshot',snapshot,'--vault-key-file',key])
    # Fixture initialization is test-only, not MIG-05 or working-pair acceptance.
    put('/run/fixture.json',json.dumps(dict(OwnerPassword=owner_password,Run=migration)))
    run([tests,'-test.run=^TestRehearsalFixture$'],env=dict(os.environ,VPN_REHEARSAL_FIXTURE='baseline'))
    manifest['panel_run_id']=migration;manifest['panel_generation']=1;manifest['panel_auth_hash']=manifest['files'].pop(str(base/'auth.caddy'))
    manifest['panel_previous_transaction']=manifest.pop('transaction')
    put(state/'manifest.json',json.dumps(manifest))
    put(state/'master_user.sfa.json',old_profile);put(state/'clients.json',(snapshot/'clients.json').read_bytes())
    # Dedicated Caddy, relay and API identities; all binaries remain unchanged.
    setpriv=Path('/usr/bin/setpriv');python=Path(sys.executable).resolve()
    def unpriv(uid):return [setpriv,'--reuid='+str(uid),'--regid='+str(uid),'--clear-groups','--bounding-set=-all']
    relay=dict(log=dict(disabled=True),inbounds=[dict(type='http',listen='127.0.0.1',listen_port=1081)],outbounds=[dict(type='direct',tag='echo')],
               route=dict(rules=[dict(ip_cidr=['192.0.2.119/32'],port=p,action='route',outbound='echo',override_address='127.0.0.1') for p in (19876,19877)]))
    put('/run/relay/config.json',json.dumps(relay),0o640,65533)
    policy=dict(address='127.0.0.1',port=18443,domain='lab.example',ca_file=str(base/'cert'),site_sha256=hashlib.sha256(b'site').hexdigest(),
                binary=str(BIN/'sing-box'),auth_file=str(base/'auth.caddy'),canary_login='master_user',scratch_dir='/run/vpn-control/probes',
                tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,udp_mode='echo',udp_host='192.0.2.119',udp_port=19877)
    put('/etc/vpn-control/probe-lab.json',json.dumps(policy))
    worker=dict(installation='lab',owner_run=migration,socket='/run/caddy-admin/admin.sock',helper=str(ROOT/'owned_auth.py'),
                validate_command=[str(x) for x in unpriv(65534)]+[str(BIN/'caddy'),'validate','--config','-'],
                probe_command=[str(python),'-B',str(ROOT/'create_probe.py'),'--policy','/etc/vpn-control/probe-lab.json'])
    put('/etc/vpn-control/worker-lab.json',json.dumps(worker))
    os.environ.update(XDG_DATA_HOME='/run/caddy-data',XDG_CONFIG_HOME='/run/caddy-data')
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay_process=start(stack,unpriv(65533)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081)
        caddy_process=start(stack,unpriv(65534)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        for process,uid in ((relay_process,65533),(caddy_process,65534)):
            service_identity(process,uid)
        admin=Path('/run/caddy-admin/admin.sock')
        mode=admin.stat().st_mode&0o777
        require(admin.stat().st_uid==65534 and mode&0o077==0 and mode&0o200!=0
                and admin.parent.stat().st_uid==65534 and admin.parent.stat().st_mode&0o777==0o700,'socket ownership/mode mismatch')
        print('staging admin socket: uid=65534 mode='+format(mode,'04o')+' parent=0700',flush=True)
        # No socket access for the actual API/relay UIDs.
        denial='import socket;s=socket.socket(socket.AF_UNIX);s.connect("/run/caddy-admin/admin.sock")'
        for uid in (65532,65533):
            result=subprocess.run([str(x) for x in unpriv(uid)]+[str(python),'-c',denial],capture_output=True)
            require(result.returncode!=0,'admin socket exposed to isolated service')
        api_dir=Path('/run/vpn-control/api');api_dir.mkdir(mode=0o700);os.chown(api_dir,65532,65532)
        for p in (panel,db,key):os.chown(p,65532,65532)
        api_process=subprocess.Popen([str(x) for x in unpriv(65532)]+[str(api),'--socket',str(api_dir/'api.sock'),'--profile-domain','lab.example','--vault-key-file',str(key)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stack.callback(lambda: (api_process.terminate(),api_process.wait(timeout=5)))
        import time
        for _ in range(100):
            if (api_dir/'api.sock').exists():break
            require(api_process.poll() is None,'owner API exited');time.sleep(.05)
        service_identity(api_process,65532)
        status,headers,_=request(api_dir/'api.sock','POST','/login',urllib.parse.urlencode(dict(username='owner',password=owner_password)),
                                 {'Origin':'https://panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
        require(status==303,'owner login failed');cookie=headers['Set-Cookie'].split(';',1)[0]
        profile_client(stack,template,19082,base/'cert')
        from verify import connect
        try:
            # SOCKS acknowledgement may precede the upstream connect failure.
            # Check actual response data instead of treating ACK as admin access.
            with connect(19082,'127.0.0.1',2019) as stream:
                stream.sendall(b'GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                exposed=bool(stream.recv(128))
        except (OSError,RuntimeError): pass
        else: require(not exposed,'admin TCP endpoint exposed through proxy')
        with socket.create_connection(('127.0.0.1',18443),3) as raw:
            with ssl.create_default_context(cafile=str(base/'cert')).wrap_socket(raw,server_hostname='lab.example') as secured:
                secured.sendall(b'GET /config/ HTTP/1.1\r\nHost: lab.example\r\nConnection: close\r\n\r\n')
                response=http.client.HTTPResponse(secured);response.begin()
                require(response.status==200 and response.read()==b'site','admin route exposed over HTTPS')
        # The original wrapper runs unmodified apart from its installation token.
        wrapper=(ROOT/'templates/vpn-add-user').read_text().replace('@STATE@',str(state)).replace('@BASE@',str(base)).replace('@PREFIX@','evpn-lab')
        put('/run/vpn-add-user',wrapper,0o700)
        def return_installer():
            arguments=[python,'-B',ROOT/'return_legacy.py','--installation','lab','--staging-db',db,
                       '--approved-plan',migration,'--vault-key-file',key,'--vpnctl','/usr/local/bin/vpnctl']
            require(json.loads(run(arguments))['status']=='installer_returned','working-layout return failed')
            require(json.loads(run(arguments))['status']=='installer_returned','working-layout return replay failed')
            returned=json.loads((state/'manifest.json').read_bytes())
            require('panel_generation' not in returned and returned['returned_run_id']==migration,'writer not returned')
            require((base/'auth.caddy').stat().st_mode&0o777==0o640,'return changed auth access mode')
            require((base/'auth.caddy').stat().st_gid==65534,'return changed auth reader identity')
            require((state/'master_user.sfa.json').read_bytes()==old_profile,'return changed original profile')
            with sqlite3.connect(db) as connection:
                require(connection.execute('SELECT phase,status FROM legacy_migration_runs WHERE id=?',(migration,)).fetchone()==('rolled_back','installer_returned'),'return registry state incorrect')
            # The installer branch is reachable and can decline a new issuance
            # without changing users; no restart is requested or performed.
            run([python,'-B','/run/vpn-add-user'],input=b'Return-Probe\nn\n')
        if os.environ.get('VPN_REHEARSAL_RETURN_BEFORE')=='1':
            return_installer()
            require(attempt(19082),'old profile lost access before-change return')
            print('full-worker: working-layout installer return before user changes PASS')
            return
        run([python,'-B','/run/vpn-add-user'],input=b'New-User\n')
        with sqlite3.connect(db) as connection:
            user,op=connection.execute("SELECT u.id,o.id FROM users u JOIN operations o ON o.target_id=u.id WHERE u.login='New-User'").fetchone()
        route='/api/v1/users/'+user+'/profiles/download?client=sfa-1.14.4'
        require(request(api_dir/'api.sock','GET',route,headers={'Cookie':cookie})[0]==404,'profile issued before activation')
        worker_args=[cli,'worker','once','--installation','lab','--owner-run',migration]
        failure=os.environ.get('VPN_REHEARSAL_FAILURE','none')
        require(failure in ('none','sqlite','lost_response'),'unknown rehearsal failure')
        if failure=='sqlite':
            with sqlite3.connect(db) as connection:
                connection.execute("CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON operations WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END")
            result=subprocess.run([str(a) for a in worker_args],capture_output=True,timeout=120)
            require(result.returncode!=0,'SQLite fault was not reached')
            require(request(api_dir/'api.sock','GET',route,headers={'Cookie':cookie})[0]==404,'profile issued after failed commit')
            with sqlite3.connect(db) as connection:connection.execute('DROP TRIGGER reject_finish')
        result=json.loads(run(worker_args))
        require(result==dict(state='completed',operation_id=op),'worker did not complete queued operation')
        if failure=='lost_response':
            # Discard the completed response, then repeat the original SSH request.
            # No separate recovery state is needed: observed SQLite/files agree.
            with sqlite3.connect(db) as connection:
                before=connection.execute('SELECT nonce,ciphertext FROM credentials WHERE user_id=?',(user,)).fetchone()
            run([python,'-B','/run/vpn-add-user'],input=b'New-User\n')
            with sqlite3.connect(db) as connection:
                after=connection.execute('SELECT nonce,ciphertext FROM credentials WHERE user_id=?',(user,)).fetchone()
                require(before==after and connection.execute("SELECT count(*) FROM users WHERE login='New-User'").fetchone()[0]==1,'response replay changed identity or secret')
        require(json.loads(run([cli,'worker','once','--installation','lab','--owner-run',migration]))==dict(state='idle'),'worker replay changed state')
        require(request(api_dir/'api.sock','GET',route)[0]==401,'profile leaked without session')
        status,headers,body=request(api_dir/'api.sock','GET',route,headers={'Cookie':cookie})
        require(status==200 and headers.get('Cache-Control')=='no-store','owner download failed')
        profile=json.loads(body)
        outbound=profile_client(stack,profile,19081,base/'cert')
        require((state/'master_user.sfa.json').read_bytes()==old_profile,'original profile changed')
        export=Path('/run/export');export.mkdir(mode=0o700)
        run([cli,'migration','reverse-export','--approved-plan',migration,'--staging-db',db,'--vault-key-file',key,'--output-dir',export])
        exported=json.loads((export/'clients.json').read_bytes())['clients']
        require({u['username'] for u in exported}=={'master_user','New-User'},'reverse export lost active users')
        require(next(u['password'] for u in exported if u['username']=='master_user')==canary,'old password changed')
        with sqlite3.connect(db) as connection:
            require(connection.execute('SELECT count(*) FROM profile_issuance').fetchone()[0]==1,'profile issuance not audited')
        return_installer()
        from create_probe import probe
        probe('/etc/vpn-control/probe-lab.json','New-User',outbound['password'])
        require(attempt(19081),'downloaded profile lost access after return')
        require(attempt(19082),'original profile lost access after return')
        print('full-worker: real paths/CLI/unprivileged validate/TLS/TCP/UoT/socket denial/owner download/installer return PASS')


if __name__=='__main__':
    main()
