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
import uuid

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
    require(int(status['Gid'].split()[1])==(986 if uid==999 else uid),'service group mismatch')
    require(os.stat('/proc/'+str(process.pid)+'/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino,'wrong staging network namespace')


def main():
    require(Path('/.vpn-control-rehearsal').is_file() and set(os.listdir('/sys/class/net')) == {'lo'},'dedicated isolated root required')
    os.umask(0o077)
    base,state,panel = Path('/etc/empire-vpn/lab'),Path('/var/lib/empire-vpn/lab'),Path('/var/lib/vpn-control')
    data_dir=Path('/var/lib/empire-vpn-acme');ca_file=Path('/etc/vpn-control/lab-ca.pem')
    for p in (base,state,panel,Path('/etc/vpn-control'),Path('/run/lock'),Path('/run/vpn-control/probes'),Path('/run/caddy-admin'),Path('/run/caddy-data'),Path('/run/relay')):
        p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
    base.parent.chmod(0o755)
    base.chmod(0o755)
    data_dir.mkdir(mode=0o700);os.chown(data_dir,999,986)
    for p in (Path('/run/caddy-admin'),Path('/run/caddy-data')):os.chown(p,982,982)
    os.chown('/run/relay',999,986)
    Path('/run/vpn-control').chmod(0o755)
    put('/run/lock/empire-vpn.lock',b'')
    canary,old_password,owner_password = secrets.token_hex(24),secrets.token_hex(24),secrets.token_hex(24)
    cli=ROOT/'rehearsal-bin/vpnctl';api=ROOT/'rehearsal-bin/vpn-control';python=Path(sys.executable).resolve()
    auth=b'basic_auth "master_user" '+json.dumps(canary).encode()+b'\nbasic_auth "Old-User" '+json.dumps(old_password).encode()+b'\n'
    put(base/'auth.caddy',auth,0o640,986)
    run(['openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1','-subj','/CN=lab.example',
         '-addext','subjectAltName=DNS:lab.example','-keyout',data_dir/'key','-out',data_dir/'cert'])
    for name in ('key','cert'):os.chown(data_dir/name,999,986);(data_dir/name).chmod(0o600)
    put(ca_file,(data_dir/'cert').read_bytes())
    caddyfile=('{'+'\n admin unix//run/caddy-admin/admin.sock\n persist_config off\n auto_https off\n order forward_proxy before file_server\n}\n'
               'https://:18443 {\n bind 127.0.0.1\n tls '+str(data_dir/'cert')+' '+str(data_dir/'key')+'\n route {\n forward_proxy {\n import '+str(base/'auth.caddy')+
               '\n hide_ip\n hide_via\n probe_resistance\n upstream http://127.0.0.1:1081\n }\n respond "site" 200\n }\n}\n')
    put(base/'Caddyfile',caddyfile.replace('admin unix//run/caddy-admin/admin.sock','admin off'),0o640,986)
    # Canonical inspection/import retains the exact old credential and profile.
    snapshot=Path('/run/snapshot');snapshot.mkdir(mode=0o700)
    template=json.loads((ROOT/'templates/sfa-profile.json').read_bytes())
    for outbound in template['outbounds']:
        if outbound['type']=='naive':outbound.update(server='lab.example',username='master_user',password=canary)
    old_profile=json.dumps(template).encode();put(snapshot/'master_user.sfa.json',old_profile)
    put(snapshot/'auth.caddy',auth)
    old_regular=copy.deepcopy(template)
    for outbound in old_regular['outbounds']:
        if outbound['type']=='naive':outbound.update(username='Old-User',password=old_password)
    old_regular_bytes=json.dumps(old_regular).encode();put(snapshot/'vpn-Old-User.json',old_regular_bytes)
    put(snapshot/'clients.json',json.dumps(dict(format='empire-vpn-clients',schema_version=1,clients=[dict(username='master_user',password=canary),dict(username='Old-User',password=old_password)])))
    source_caddy=caddyfile.replace('admin unix//run/caddy-admin/admin.sock','admin off')
    put(snapshot/'Caddyfile',source_caddy)
    manifest=dict(transaction='synthetic-baseline',config=dict(id='lab',domain='lab.example'),files={str(base/'auth.caddy'):hashlib.sha256(auth).hexdigest(),str(base/'Caddyfile'):hashlib.sha256(source_caddy.encode()).hexdigest()})
    put(snapshot/'manifest.json',json.dumps(manifest))
    put(state/'manifest.json',json.dumps(manifest))
    put(state/'master_user.sfa.json',old_profile);put(state/'vpn-Old-User.json',old_regular_bytes);put(state/'clients.json',(snapshot/'clients.json').read_bytes())
    window=str(uuid.uuid4())
    snapshot_args=[python,'-B',ROOT/'g3_snapshot.py','lab',window,'pre']
    protected=json.loads(run(snapshot_args));require(protected==json.loads(run(snapshot_args)),'snapshot replay changed before-image')
    snapshot=Path(protected['import_snapshot'])
    db=panel/'state.db';key=panel/'vault.key'
    template_file=ROOT/'templates/sfa-profile.json'
    init=[cli,'registry','init','--installation','lab','--sfa-template',template_file,'--approve-sha256',hashlib.sha256(template_file.read_bytes()).hexdigest()]
    initialized=run(init);original_key=key.read_bytes()
    require(initialized==run(init) and key.read_bytes()==original_key,'registry init replay changed revision or key')
    run([api,'--bootstrap-owner','owner','--owner-password-stdin'],input=(owner_password+'\n').encode())
    report,code=record_snapshot(snapshot,db,None);require(code==0,'snapshot not clean');migration=report['run_id']
    _,code=record_snapshot(snapshot,db,migration);require(code==0,'plan refused')
    run([cli,'migration','execute','--approved-plan',migration,'--staging-db',db,'--snapshot',snapshot,'--vault-key-file',key])
    # Dedicated Caddy, relay and API identities; all binaries remain unchanged.
    for path in (base/'auth.caddy',base/'Caddyfile'):os.chown(path,0,982)
    for path in [data_dir,*data_dir.rglob('*')]:os.chown(path,982,982)
    put(base/'Caddyfile',caddyfile,0o640,982)
    setpriv=Path('/usr/bin/setpriv')
    def unpriv(uid):return [setpriv,'--reuid='+str(uid),'--regid='+str(986 if uid==999 else uid),'--clear-groups','--bounding-set=-all']
    relay=dict(log=dict(disabled=True),inbounds=[dict(type='http',listen='127.0.0.1',listen_port=1081)],outbounds=[dict(type='direct',tag='echo')],
               route=dict(rules=[dict(ip_cidr=['192.0.2.119/32'],port=p,action='route',outbound='echo',override_address='127.0.0.1') for p in (19876,19877)]))
    put('/run/relay/config.json',json.dumps(relay),0o640,986)
    policy=dict(address='127.0.0.1',port=18443,domain='lab.example',ca_file=str(ca_file),site_sha256=hashlib.sha256(b'site').hexdigest(),
                binary=str(BIN/'sing-box'),auth_file=str(base/'auth.caddy'),canary_login='master_user',scratch_dir='/run/vpn-control/probes',
                tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,udp_mode='echo',udp_host='192.0.2.119',udp_port=19877)
    put('/etc/vpn-control/probe-lab.json',json.dumps(policy))
    worker=dict(installation='lab',owner_run=migration,socket='/run/caddy-admin/admin.sock',helper=str(ROOT/'owned_auth.py'),
                validate_command=[str(x) for x in unpriv(982)]+[str(BIN/'caddy'),'validate','--config','-'],
                probe_command=[str(python),'-B',str(ROOT/'create_probe.py'),'--policy','/etc/vpn-control/probe-lab.json'])
    put('/etc/vpn-control/worker-lab.json',json.dumps(worker))
    os.environ.update(XDG_DATA_HOME=str(data_dir),XDG_CONFIG_HOME=str(data_dir))
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay_process=start(stack,unpriv(999)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081)
        caddy_process=start(stack,unpriv(982)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        for process,uid in ((relay_process,999),(caddy_process,982)):
            service_identity(process,uid)
        admin=Path('/run/caddy-admin/admin.sock')
        mode=admin.stat().st_mode&0o777
        require(admin.stat().st_uid==982 and mode&0o077==0 and mode&0o200!=0
                and admin.parent.stat().st_uid==982 and admin.parent.stat().st_mode&0o777==0o700,'socket ownership/mode mismatch')
        print('staging admin socket: uid=982 mode='+format(mode,'04o')+' parent=0700',flush=True)
        # No socket access for the actual API/relay UIDs.
        denial='import socket;s=socket.socket(socket.AF_UNIX);s.connect("/run/caddy-admin/admin.sock")'
        for uid in (981,999):
            result=subprocess.run([str(x) for x in unpriv(uid)]+[str(python),'-c',denial],capture_output=True)
            require(result.returncode!=0,'admin socket exposed to isolated service')
        api_dir=Path('/run/vpn-control/api');api_dir.mkdir(mode=0o700);os.chown(api_dir,981,981)
        for p in (panel,db,key):os.chown(p,981,981)
        api_process=subprocess.Popen([str(x) for x in unpriv(981)]+[str(api),'--socket',str(api_dir/'api.sock'),'--profile-domain','lab.example','--vault-key-file',str(key)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stack.callback(lambda: (api_process.terminate(),api_process.wait(timeout=5)))
        import time
        for _ in range(100):
            if (api_dir/'api.sock').exists():break
            require(api_process.poll() is None,'owner API exited');time.sleep(.05)
        service_identity(api_process,981)
        def restore_runtime():
            caddy_process.terminate();caddy_process.wait(timeout=5)
            arguments=[python,'-B',ROOT/'g3_restore_runtime.py','--installation','lab','--snapshot',snapshot,
                       '--approved-plan',migration,'--legacy-uid','999','--legacy-gid','986','--admin-socket',str(admin)]
            interrupted='''import os,sys
sys.path.insert(0,"/work")
import g3_restore_runtime as module
original=module.publish
def publish(path,data,**kwargs):
 original(path,data,**kwargs)
 if path.name=="Caddyfile":os._exit(79)
module.publish=publish
module.main()
'''
            failed=subprocess.run([str(python),'-B','-c',interrupted,*[str(a) for a in arguments[3:]]],capture_output=True)
            require(failed.returncode==79,'runtime restoration interruption was not reached')
            run(arguments);run(arguments)
            require((base/'Caddyfile').read_bytes()==source_caddy.encode(),'runtime restore changed original directives')
            require(all(p.stat().st_gid==986 for p in (base/'auth.caddy',base/'Caddyfile')),'legacy auth reader group not restored')
            require(all(p.stat().st_uid==999 and p.stat().st_gid==986 for p in [data_dir,*data_dir.rglob('*')]),'ACME ownership not restored')
            restored=start(stack,unpriv(999)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
            service_identity(restored,999)
        cutover_args=[cli,'migration','cutover','--installation','lab','--approved-plan',migration,'--snapshot',snapshot,'--legacy-writers-stopped']
        denied=subprocess.run([str(a) for a in cutover_args[:-1]],capture_output=True)
        require(denied.returncode==2,'cutover accepted missing stopped-writer acknowledgement')
        cutover_failure=os.environ.get('VPN_REHEARSAL_CUTOVER_FAILURE','none')
        require(cutover_failure in ('none','probe','sqlite','source','abort'),'unknown cutover failure')
        if cutover_failure!='none':
            before_manifest=(state/'manifest.json').read_bytes()
            with sqlite3.connect(db) as connection:
                before_secrets=connection.execute('SELECT id,nonce,ciphertext FROM credentials ORDER BY id').fetchall()
            if cutover_failure in ('probe','abort'):
                invalid=dict(policy,site_sha256='0'*64);put('/etc/vpn-control/probe-lab.json',json.dumps(invalid))
            elif cutover_failure=='source':put(base/'Caddyfile',caddyfile+'\n# external drift\n',0o640,982)
            else:
                with sqlite3.connect(db) as connection:connection.execute("CREATE TRIGGER reject_cutover BEFORE UPDATE OF phase ON legacy_migration_runs WHEN NEW.phase='verified_cutover' BEGIN SELECT RAISE(ABORT,'fixture'); END")
            failed=subprocess.run([str(a) for a in cutover_args],capture_output=True,timeout=120)
            require(failed.returncode!=0,'cutover fault not observed')
            with sqlite3.connect(db) as connection:
                phase,stage=connection.execute('SELECT phase,status FROM legacy_migration_runs WHERE id=?',(migration,)).fetchone()
                require(connection.execute("SELECT count(*) FROM users WHERE status!='provisioning'").fetchone()[0]==0,'users activated after failed cutover')
                require(before_secrets==connection.execute('SELECT id,nonce,ciphertext FROM credentials ORDER BY id').fetchall(),'cutover failure changed secrets')
            if cutover_failure=='source':
                require((phase,stage)==('importing','staged') and (state/'manifest.json').read_bytes()==before_manifest,'pre-publication drift changed writer')
                put(base/'Caddyfile',caddyfile,0o640,982)
            else:
                require((phase,stage)==('reconcile_required','reconcile_required'),'ambiguous cutover not blocked')
                if cutover_failure=='abort':
                    abort=[python,'-B',ROOT/'handoff_legacy.py','--installation','lab','--snapshot',snapshot,
                           '--staging-db',db,'--approved-plan',migration,'--admin-socket',str(admin),
                           '--wrapper-sha256',hashlib.sha256(Path('/usr/local/bin/vpn-add-user').read_bytes()).hexdigest(),
                           '--rollback','--reconcile']
                    require(json.loads(run(abort))['status']=='handoff_rolled_back','failed cutover abort refused')
                    restore_runtime()
                    profile_client(stack,template,19082,ca_file)
                    run([python,'-B','/usr/local/bin/vpn-add-user'],input=b'Return-Probe\nn\n')
                    print('full-worker: failed MIG-05/reconcile/abort/runtime restore/old profile PASS')
                    return
                refused=subprocess.run([str(a) for a in cutover_args],capture_output=True,timeout=120)
                require(refused.returncode!=0,'cutover bypassed reconciliation')
                if cutover_failure=='probe':put('/etc/vpn-control/probe-lab.json',json.dumps(policy))
                else:
                    with sqlite3.connect(db) as connection:connection.execute('DROP TRIGGER reject_cutover')
                cutover_args.append('--reconcile')
        cutover=json.loads(run(cutover_args))
        require(cutover==json.loads(run(cutover_args)),'cutover replay changed receipt')
        with sqlite3.connect(db) as connection:
            require(connection.execute('SELECT phase,status FROM legacy_migration_runs WHERE id=?',(migration,)).fetchone()==('verified_cutover','verified_cutover'),'MIG-05 did not verify')
        status,headers,_=request(api_dir/'api.sock','POST','/login',urllib.parse.urlencode(dict(username='owner',password=owner_password)),
                                 {'Origin':'https://panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
        require(status==303,'owner login failed');cookie=headers['Set-Cookie'].split(';',1)[0]
        profile_client(stack,template,19082,ca_file)
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
            with ssl.create_default_context(cafile=str(ca_file)).wrap_socket(raw,server_hostname='lab.example') as secured:
                secured.sendall(b'GET /config/ HTTP/1.1\r\nHost: lab.example\r\nConnection: close\r\n\r\n')
                response=http.client.HTTPResponse(secured);response.begin()
                require(response.status==200 and response.read()==b'site','admin route exposed over HTTPS')
        # The original wrapper runs unmodified apart from its installation token.
        wrapper_path='/usr/local/bin/vpn-add-user'
        def return_installer():
            saved=json.loads(run([python,'-B',ROOT/'g3_snapshot.py','lab',window,'post']))
            require(saved['generation']>=1,'post snapshot lost generation')
            arguments=[python,'-B',ROOT/'return_legacy.py','--installation','lab','--staging-db',db,
                       '--approved-plan',migration,'--vault-key-file',key,'--vpnctl','/usr/local/bin/vpnctl']
            require(json.loads(run(arguments))['status']=='installer_returned','working-layout return failed')
            require(json.loads(run(arguments))['status']=='installer_returned','working-layout return replay failed')
            returned=json.loads((state/'manifest.json').read_bytes())
            require('panel_generation' not in returned and returned['returned_run_id']==migration,'writer not returned')
            require((base/'auth.caddy').stat().st_mode&0o777==0o640,'return changed auth access mode')
            require((base/'auth.caddy').stat().st_gid==982,'return changed auth reader identity')
            require((state/'master_user.sfa.json').read_bytes()==old_profile,'return changed original profile')
            require((state/'vpn-Old-User.json').read_bytes()==old_regular_bytes,'return changed regular original profile')
            with sqlite3.connect(db) as connection:
                require(connection.execute('SELECT phase,status FROM legacy_migration_runs WHERE id=?',(migration,)).fetchone()==('rolled_back','installer_returned'),'return registry state incorrect')
            # The installer branch is reachable and can decline a new issuance
            # without changing users; no restart is requested or performed.
            run([python,'-B',wrapper_path],input=b'Return-Probe\nn\n')
            restore_runtime()
        if os.environ.get('VPN_REHEARSAL_RETURN_BEFORE')=='1':
            return_installer()
            require(attempt(19082),'old profile lost access before-change return')
            print('full-worker: working-layout installer return before user changes PASS')
            return
        run([python,'-B',wrapper_path],input=b'New-User\n')
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
            run([python,'-B',wrapper_path],input=b'New-User\n')
            with sqlite3.connect(db) as connection:
                after=connection.execute('SELECT nonce,ciphertext FROM credentials WHERE user_id=?',(user,)).fetchone()
                require(before==after and connection.execute("SELECT count(*) FROM users WHERE login='New-User'").fetchone()[0]==1,'response replay changed identity or secret')
        require(json.loads(run([cli,'worker','once','--installation','lab','--owner-run',migration]))==dict(state='idle'),'worker replay changed state')
        require(request(api_dir/'api.sock','GET',route)[0]==401,'profile leaked without session')
        status,headers,body=request(api_dir/'api.sock','GET',route,headers={'Cookie':cookie})
        require(status==200 and headers.get('Cache-Control')=='no-store','owner download failed')
        profile=json.loads(body)
        outbound=profile_client(stack,profile,19081,ca_file)
        require((state/'master_user.sfa.json').read_bytes()==old_profile,'original profile changed')
        export=Path('/run/export');export.mkdir(mode=0o700)
        run([cli,'migration','reverse-export','--approved-plan',migration,'--staging-db',db,'--vault-key-file',key,'--output-dir',export])
        exported=json.loads((export/'clients.json').read_bytes())['clients']
        require({u['username'] for u in exported}=={'master_user','Old-User','New-User'},'reverse export lost active users')
        require(next(u['password'] for u in exported if u['username']=='master_user')==canary,'old password changed')
        with sqlite3.connect(db) as connection:
            require(connection.execute('SELECT count(*) FROM profile_issuance').fetchone()[0]==1,'profile issuance not audited')
        return_installer()
        from create_probe import probe
        probe('/etc/vpn-control/probe-lab.json','New-User',outbound['password'])
        require(attempt(19081),'downloaded profile lost access after return')
        require(attempt(19082),'original profile lost access after return')
        print('full-worker: MIG-05/'+cutover_failure+'/real paths/CLI/unprivileged validate/TLS/TCP/UoT/socket denial/owner download/installer return PASS')


if __name__=='__main__':
    main()
