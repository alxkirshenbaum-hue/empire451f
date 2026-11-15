"""Portable acceptance helpers. Only runs in marked synthetic RootDirectory."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from full_worker_rehearsal import require, run, put


def semantic_snapshot(db_path, key_path):
    """Private equality evidence; never emit credential values or digests."""
    cipher=AESGCM(Path(key_path).read_bytes())
    with closing(sqlite3.connect(db_path)) as db:
        users=db.execute('SELECT id,login,kind,protected,display_name,status,deleted_at,row_version FROM users ORDER BY id').fetchall()
        credentials=[]
        for cid,uid,sv,kv,nonce,sealed,revoked in db.execute('SELECT id,user_id,secret_version,key_version,nonce,ciphertext,revoked_at FROM credentials ORDER BY id'):
            encoded=uid.encode();aad=b'vpn-control/credential/v1\0'+bytes([len(encoded)])+encoded+struct.pack('>QQ',sv,kv)
            secret=cipher.decrypt(nonce,sealed,aad)
            credentials.append([cid,uid,sv,hashlib.sha256(secret).hexdigest(),revoked])
        tables={}
        for name in ('user_current_credentials','profile_templates','template_revisions','profile_routing_variants','user_profiles'):
            tables[name]=db.execute('SELECT * FROM '+name+' ORDER BY 1').fetchall()
    return dict(users=users,credentials=credentials,tables=tables)


def capture(cli,migration,worker,api_socket,cookie,old_profile,disabled_secret):
    require(Path('/.vpn-control-rehearsal').is_file(),'isolated portable fixture required')
    from backup_restore_rehearsal import capture as backup_capture
    for login in ('Alex','alex'):
        run([cli,'user','create','--installation','lab','--owner-run',migration,'--login',login])
        run([cli,'worker','once','--installation','lab','--owner-run',migration])
    backup_capture(cli,migration,worker,api_socket,cookie,old_profile,disabled_secret)
    proof=Path('/root/backup-proof')
    context=json.loads((proof/'context.json').read_bytes())
    env=dict(os.environ,VPNCTL_SESSION_FILE=str(proof/'session'),VPNCTL_SOCKET=str(api_socket))
    download=proof/'portable-export.jwe'
    run([cli,'backup','download',context['backup_id'],'--output',download,'--sha256',context['sha256']],env=env)
    require(hashlib.sha256(download.read_bytes()).hexdigest()==context['sha256'],'owner download digest mismatch')
    expected=semantic_snapshot('/var/lib/vpn-control/state.db','/var/lib/vpn-control/vault.key')
    require({'Alex','alex','master_user','Old-User','New-User'} <= {row[1] for row in expected['users']},'exact-case fixture missing')
    require(next(row[5] for row in expected['users'] if row[1]=='New-User')=='disabled','disabled fixture missing')
    put(proof/'portable-expected.json',json.dumps(expected))
    context['downloaded_path']=str(download)
    context['source_key_sha256']=hashlib.sha256(Path('/var/lib/vpn-control/vault.key').read_bytes()).hexdigest()
    put(proof/'context.json',json.dumps(context))
    print('portable-source: owner encrypted export/download and private semantic fixture PASS',flush=True)


def receive():
    import contextlib,secrets,threading,time,subprocess,urllib.parse
    from full_worker_rehearsal import ROOT,BIN,profile_client,request,service_identity
    from recovery_probe import Echo,EchoServer,EchoDatagram,EchoDatagramServer,start
    require(Path('/.vpn-control-rehearsal').is_file() and set(os.listdir('/sys/class/net'))=={'lo'},'isolated clean destination required')
    os.umask(0o077);inputs=Path('/root/portable-input');context=json.loads((inputs/'context.json').read_bytes())
    base=Path('/etc/empire-vpn/lab');state=Path('/var/lib/empire-vpn/lab');panel=Path('/var/lib/vpn-control');data=Path('/var/lib/empire-vpn-acme');cert=Path('/etc/vpn-control/lab-ca.pem')
    for p in (base,state,Path('/etc/vpn-control'),Path('/run/lock'),Path('/run/vpn-control/probes'),Path('/run/caddy-admin'),Path('/run/caddy-data'),Path('/run/relay')):
        p.mkdir(mode=0o700,parents=True,exist_ok=True);p.chmod(0o700)
    base.parent.chmod(0o755);base.chmod(0o755);Path('/run/vpn-control').chmod(0o755)
    for p in (Path('/run/caddy-admin'),Path('/run/caddy-data')):os.chown(p,982,982)
    os.chown('/run/relay',999,986)
    fresh=secrets.token_hex(24);auth='basic_auth "master_user" '+json.dumps(fresh)+'\n';put(base/'auth.caddy',auth,0o640,982)
    caddyfile='{\n admin unix//run/caddy-admin/admin.sock\n persist_config off\n auto_https off\n order forward_proxy before file_server\n}\nhttps://:18443 {\n bind 127.0.0.1\n tls '+str(data/'cert')+' '+str(data/'key')+'\n route {\n forward_proxy {\n import '+str(base/'auth.caddy')+'\n hide_ip\n hide_via\n probe_resistance\n upstream http://127.0.0.1:1081\n }\n respond "site" 200\n }\n}\n'
    put(base/'Caddyfile',caddyfile,0o640,982)
    manifest=dict(transaction='portable-clean-destination',config=dict(id='lab',domain='lab.example'),files={str(base/'auth.caddy'):hashlib.sha256(auth.encode()).hexdigest(),str(base/'Caddyfile'):hashlib.sha256(caddyfile.encode()).hexdigest()})
    put(state/'manifest.json',json.dumps(manifest))
    cli=ROOT/'rehearsal-bin/vpnctl';api=ROOT/'rehearsal-bin/vpn-control';template=ROOT/'templates/sfa-profile.json'
    run([cli,'registry','init','--installation','lab','--sfa-template',template,'--approve-sha256',hashlib.sha256(template.read_bytes()).hexdigest()])
    owner_password='Independent portable destination owner'
    run([api,'--bootstrap-owner','destination-owner','--owner-password-stdin'],input=(owner_password+'\n').encode())
    own_key=(panel/'vault.key').read_bytes();require(hashlib.sha256(own_key).hexdigest()!=context['source_key_sha256'],'destination key not independent')
    with closing(sqlite3.connect(panel/'state.db')) as db:
        require(db.execute('SELECT count(*) FROM users').fetchone()[0]==0,'destination not clean');owner_before=db.execute('SELECT * FROM admin_accounts').fetchall()
    def unpriv(uid):return ['/usr/bin/setpriv','--reuid='+str(uid),'--regid='+str(986 if uid==999 else uid),'--clear-groups','--bounding-set=-all']
    put('/run/relay/config.json',(inputs/'relay.json').read_bytes(),0o640,986)
    policy=dict(address='127.0.0.1',port=18443,domain='lab.example',ca_file=str(cert),site_sha256=hashlib.sha256(b'site').hexdigest(),binary=str(BIN/'sing-box'),auth_file=str(base/'auth.caddy'),canary_login='master_user',scratch_dir='/run/vpn-control/probes',tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,udp_mode='echo',udp_host='192.0.2.119',udp_port=19877)
    put('/etc/vpn-control/probe-lab.json',json.dumps(policy))
    worker=dict(installation='lab',owner_run=context['destination_run'],socket='/run/caddy-admin/admin.sock',helper=str(ROOT/'owned_auth.py'),validate_command=unpriv(982)+[str(BIN/'caddy'),'validate','--config','-'],probe_command=['/usr/bin/python3','-B',str(ROOT/'create_probe.py'),'--policy','/etc/vpn-control/probe-lab.json'])
    put('/etc/vpn-control/worker-lab.json',json.dumps(worker));os.environ.update(XDG_DATA_HOME=str(data),XDG_CONFIG_HOME=str(data))
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay=start(stack,unpriv(999)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081);caddy=start(stack,unpriv(982)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        service_identity(relay,999);service_identity(caddy,982)
        common=['--installation','lab','--source-db',str(inputs/'source.db'),'--source-key',str(inputs/'source.key'),'--source-owner-run',context['owner_run'],'--source-operation',context['own_operation'],'--destination-run',context['destination_run']]
        wrong_source=inputs/'wrong-source.key';put(wrong_source,secrets.token_bytes(32))
        bad_common=list(common);bad_common[bad_common.index('--source-key')+1]=str(wrong_source)
        before_bad=hashlib.sha256((panel/'state.db').read_bytes()).hexdigest()
        rejected=subprocess.run([str(x) for x in [cli,'portable','preview',*bad_common]],capture_output=True,timeout=30)
        require(rejected.returncode!=0 and hashlib.sha256((panel/'state.db').read_bytes()).hexdigest()==before_bad and (panel/'vault.key').read_bytes()==own_key,'wrong source key changed existing clean destination')
        preview=json.loads(run([cli,'portable','preview',*common]));approved=['--plan-sha256',preview['plan_sha256'],'--expected-installation-sha256',preview['installation_sha256'],'--replace-initial-catalog']
        source_before=(inputs/'source.db').read_bytes()
        # Deliberately occupied master is a visible conflict, never an overwrite.
        with closing(sqlite3.connect(panel/'state.db')) as db:
            db.execute("INSERT INTO users(id,login,kind,protected,source,display_name,status,created_at,updated_at) VALUES('conflict','master_user','service',1,'installer','bootstrap','active','now','now')")
        blocked=subprocess.run([str(x) for x in [cli,'portable','preview',*common]],capture_output=True,timeout=30)
        require(blocked.returncode!=0,'occupied master destination accepted')
        with closing(sqlite3.connect(panel/'state.db')) as db:
            require(db.execute("SELECT display_name FROM users WHERE id='conflict'").fetchone()==('bootstrap',),'conflict silently overwritten')
            db.execute("DELETE FROM users WHERE id='conflict'")
        wrong_source=inputs/'wrong-source.key';put(wrong_source,secrets.token_bytes(32))
        bad_common=list(common);bad_common[bad_common.index('--source-key')+1]=str(wrong_source)
        before_bad=hashlib.sha256((panel/'state.db').read_bytes()).hexdigest()
        rejected=subprocess.run([str(x) for x in [cli,'portable','preview',*bad_common]],capture_output=True,timeout=30)
        require(rejected.returncode!=0 and hashlib.sha256((panel/'state.db').read_bytes()).hexdigest()==before_bad and (panel/'vault.key').read_bytes()==own_key,'wrong source key changed existing clean destination')
        preview=json.loads(run([cli,'portable','preview',*common]));approved=['--plan-sha256',preview['plan_sha256'],'--expected-installation-sha256',preview['installation_sha256'],'--replace-initial-catalog']
        before_auth=(base/'auth.caddy').read_bytes();before_manifest=(state/'manifest.json').read_bytes()
        failed=subprocess.run([str(x) for x in [cli,'portable','import',*common,*approved]],env=dict(os.environ,VPN_PORTABLE_TEST_FAULT='after_auth_publish'),capture_output=True,timeout=300)
        require(failed.returncode!=0,'partial publication fault not reached')
        import base64
        journal=json.loads((state/'panel-auth-pending.json').read_bytes())
        require(journal['run']==context['destination_run'],'wrong partial journal')
        require((base/'auth.caddy').read_bytes()==base64.b64decode(journal['targets'][0]['after']) and (base/'auth.caddy').read_bytes()!=before_auth,'auth partial publication not reached')
        require((state/'manifest.json').read_bytes()==before_manifest==base64.b64decode(journal['targets'][1]['before']),'manifest advanced before injected fault')
        with closing(sqlite3.connect(panel/'state.db')) as db:
            require(db.execute("SELECT o.status,m.status FROM operations o JOIN legacy_migration_runs m ON m.id=o.target_id WHERE o.id=?",(journal['operation'],)).fetchone()==('running','portable_staged'),'partial operation not durably gated')
        gated=subprocess.run([str(cli),'worker','once','--installation','lab','--owner-run',context['destination_run']],capture_output=True,timeout=30)
        require(gated.returncode!=0,'ordinary worker bypassed portable gate')
        with closing(sqlite3.connect(panel/'state.db')) as db:
            require(db.execute("SELECT count(*) FROM legacy_migration_runs WHERE id=? AND phase='verified_cutover'",(context['destination_run'],)).fetchone()[0]==0,'partial import falsely verified')
        unapproved=subprocess.run([str(x) for x in [cli,'portable','import',*common,*approved]],capture_output=True,timeout=60)
        require(unapproved.returncode!=0,'implicit partial import retry accepted')
        completed=json.loads(run([cli,'portable','import',*common,*approved,'--resume']))
        completed_semantics=semantic_snapshot(panel/'state.db',panel/'vault.key')
        replay=json.loads(run([cli,'portable','import',*common,*approved,'--resume']))
        require(replay['operation_id']==completed['operation_id'] and semantic_snapshot(panel/'state.db',panel/'vault.key')==completed_semantics,'completed portable replay changed identity or credentials')
        require((inputs/'source.db').read_bytes()==source_before,'source snapshot changed during import/recovery')
        expected=json.loads((inputs/'portable-expected.json').read_bytes());actual=semantic_snapshot(panel/'state.db',panel/'vault.key')
        require(json.dumps(actual,sort_keys=True)==json.dumps(expected,sort_keys=True),'portable account semantics changed')
        require((panel/'vault.key').read_bytes()==own_key,'destination vault key replaced')
        with closing(sqlite3.connect(panel/'state.db')) as db:require(db.execute('SELECT * FROM admin_accounts').fetchall()==owner_before,'destination admin replaced')
        profile=json.loads((inputs/'old-profile.json').read_bytes());profile_client(stack,profile,19088,cert)
        from create_probe import probe
        probe('/etc/vpn-control/probe-lab.json','New-User',context['revoked_secret'],active=False)
        api_dir=Path('/run/vpn-control/portable-api');api_dir.mkdir(mode=0o700);os.chown(api_dir,981,981)
        for p in (panel,panel/'state.db',panel/'vault.key'):os.chown(p,981,981)
        process=subprocess.Popen(unpriv(981)+[str(api),'--socket',str(api_dir/'api.sock'),'--profile-domain','lab.example','--vault-key-file',str(panel/'vault.key'),'--owner-run',context['destination_run']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stack.callback(lambda:(process.terminate(),process.wait(timeout=5)))
        for _ in range(100):
            if (api_dir/'api.sock').exists():break
            require(process.poll() is None,'independent destination API exited');time.sleep(.05)
        status,_,_=request(api_dir/'api.sock','POST','/login',urllib.parse.urlencode(dict(username='destination-owner',password=owner_password)),{'Origin':'https://panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
        require(status==303,'destination owner login failed')
        print('portable-import: independent destination/key/admin exact-case/status/master/profile links old TCP-UoT disabled rejection PASS',flush=True)


if __name__=='__main__':receive()
