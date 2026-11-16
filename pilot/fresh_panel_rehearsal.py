"""Actual bundle install_panel through service boundary, in existing isolated root only.
Not a two-VDS/full OS install proof. Never returns simulated service success.
"""
import contextlib, hashlib, json, os, pathlib, secrets, shutil, socket, sys, threading, time, types, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'pilot'))
from full_worker_rehearsal import put,run,require,service_identity
from recovery_probe import BIN,start,EchoServer,Echo,EchoDatagramServer,EchoDatagram

class ServiceBoundary(BaseException):pass

def main():
    require(Path('/.vpn-control-rehearsal').is_file() and set(os.listdir('/sys/class/net'))=={'lo'},'isolated marked loopback root required')
    os.umask(0o022)
    archive=ROOT/'installer.zip';raw=archive.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==os.environ['VPN_FRESH_BUNDLE_SHA256'],'explicit final bundle SHA required')
    with zipfile.ZipFile(archive) as z:
        bundle={n:z.read(n).decode('utf-8') for n in z.namelist()}
    for name in ('render','remote','client','delivery','controller'):
        module=types.ModuleType(name);module.__file__='/work/'+name+'.py';sys.modules[name]=module
        if name=='controller':module.BUNDLE=bundle
        exec(compile(bundle[name+'.py'],name+'.py','exec'),module.__dict__)
    remote,controller,renderer,delivery=[sys.modules[n] for n in ('remote','controller','render','delivery')]
    c=json.loads((ROOT/'fresh-fixture.json').read_bytes());c.update(id='lab',domain='lab.example',tls='ready',panel_enabled=True)
    c=renderer.validate(c);base=Path('/etc/empire-vpn/lab');state=Path('/var/lib/empire-vpn/lab')
    for p in (base,state,Path('/etc/systemd/system'),Path('/etc/tmpfiles.d'),Path('/usr/local/bin'),Path('/run/lock'),Path('/root')):p.mkdir(parents=True,exist_ok=True)
    state.chmod(0o700);Path('/root').chmod(0o700)
    require(not Path('/var/lib/vpn-control').exists(),'panel must be absent at start')
    clients={'format':'empire-vpn-clients','schema_version':1,'clients':[{'username':'master_user','password':secrets.token_hex(24)},{'username':'Old-User','password':secrets.token_hex(24)}]}
    with controller.installer_lock():users=controller._clients(c,clients,True)
    templates={n.split('/',1)[1]:v for n,v in bundle.items() if n.startswith('templates/')}
    files=renderer.render(c,'entry',{'interface':'ens99','ssh_port':2222},{'entry':'A'*43+'=','exit':'B'*43+'='},users,templates)
    # Isolated environment only: local certificate/port, no ACME/external DNS.
    data=Path('/var/lib/empire-vpn-acme');data.mkdir(mode=0o700)
    run(['openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1','-subj','/CN=lab.example','-addext','subjectAltName=DNS:lab.example','-keyout',data/'key','-out',data/'cert'])
    for p in [data,*data.iterdir()]:os.chown(p,982,982)
    ca=Path('/etc/lab-ca.pem');put(ca,(data/'cert').read_bytes(),0o644)
    cf=files[str(base/'Caddyfile')]['content']
    require(cf.count('admin unix//run/evpn-lab-caddy-admin/admin.sock')==1 and 'admin off' not in cf,'actual fresh renderer admin required')
    original_hash=hashlib.sha256(cf.encode()).hexdigest()
    cf=cf.replace(':443, lab.example {','https://:18443 {\n bind 127.0.0.1\n tls '+str(data/'cert')+' '+str(data/'key'))
    require(cf!=files[str(base/'Caddyfile')]['content'],'local TLS adaptation required');files[str(base/'Caddyfile')]['content']=cf
    for name,item in files.items():
        remote.atomic(name,item['content'],item['mode'])
    for directory in base.rglob('*'):
        if directory.is_dir():directory.chmod(0o755)
    for name in ('Caddyfile','auth.caddy'):os.chown(base/name,0,982);(base/name).chmod(0o640)
    admin=Path('/run/evpn-lab-caddy-admin');admin.mkdir(mode=0o700);os.chown(admin,982,982)
    # VPN prepare/apply is not executed: materialize its committed renderer output.
    manifest={'schema_version':1,'role':'entry','config':c,'transaction':'synthetic-vpn-commit','files':{n:hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in files}}
    put(state/'manifest.json',json.dumps(manifest))
    for u in users['clients']:
        profile=delivery.profile(templates['sfa-profile.json'],c,u['password'])
        next(o for o in profile['outbounds'] if o['type']=='naive')['username']=u['username']
        put(state/('master_user.sfa.json' if u['username']=='master_user' else 'vpn-'+u['username']+'.json'),json.dumps(profile))
    payload=json.loads(bundle['panel/payload.json']);owner_password=secrets.token_hex(24)
    original_atomic,original_run=remote.atomic,remote.run
    adapted=[]
    def atomic(path,content,mode=0o600,*args,**kw):
        name=str(path)
        if name=='/etc/vpn-control/probe-lab.json':
            d=json.loads(content);d.update(port=18443,ca_file=str(ca),tcp_mode='echo',tcp_host='192.0.2.119',tcp_port=19876,udp_mode='echo',udp_host='192.0.2.119',udp_port=19877);content=json.dumps(d);adapted.append('loopback-probe')
        elif name=='/etc/vpn-control/worker-lab.json':
            d=json.loads(content)
            for key in ('validate_command','probe_command'):
                require(d[key][1:4]==['netns','exec','naive'],'namespace prefix contract changed');d[key]=d[key][4:]
            content=json.dumps(d);adapted.append('existing-private-network-instead-of-naive-prefix')
        return original_atomic(path,content,mode,*args,**kw)
    def invoke(args,*a,**kw):
        if args[0]=='systemctl':
            require(args==['systemctl','daemon-reload'],'unexpected first service action')
            raise ServiceBoundary()
        return original_run(args,*a,**kw)
    relay={'log':{'disabled':True},'inbounds':[{'type':'http','listen':'127.0.0.1','listen_port':1081}],'outbounds':[{'type':'direct','tag':'echo'}],'route':{'rules':[{'ip_cidr':['192.0.2.119/32'],'port':p,'action':'route','outbound':'echo','override_address':'127.0.0.1'} for p in (19876,19877)]}}
    Path('/run/relay').mkdir(mode=0o755);put('/run/relay/config.json',json.dumps(relay),0o644)
    setpriv=str(Path(shutil.which('setpriv')).resolve())
    def unpriv(uid,gid):return [setpriv,'--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--bounding-set=-all']
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay_process=start(stack,unpriv(999,986)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081)
        # Match the canonical VPN Caddy unit, without changing installer env.
        caddy_identity=[setpriv,'--reuid=982','--regid=982','--clear-groups','--bounding-set=-all,+net_bind_service','--inh-caps=+net_bind_service','--ambient-caps=+net_bind_service']
        caddy_process=start(stack,caddy_identity+['/usr/bin/env','XDG_DATA_HOME='+str(data),'XDG_CONFIG_HOME='+str(data),BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        service_identity(relay_process,999)
        identity=dict(line.split(':',1) for line in Path('/proc/'+str(caddy_process.pid)+'/status').read_text().splitlines() if ':' in line)
        require(identity['Uid'].split()==['982']*4 and identity['Gid'].split()==['982']*4 and not identity['Groups'].split() and identity['NoNewPrivs'].strip()=='1','canonical Caddy UID/groups/NNP mismatch')
        require(all(int(identity[k].strip(),16)==1<<10 for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'canonical Caddy must have only NET_BIND_SERVICE')
        require(os.stat('/proc/'+str(caddy_process.pid)+'/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino,'Caddy outside isolated namespace')
        remote.atomic,remote.run=atomic,invoke
        reached=False
        try:remote.install_panel(c,payload,'owner',owner_password)
        except ServiceBoundary:reached=True
        finally:remote.atomic,remote.run=original_atomic,original_run
        require(reached,'actual install_panel did not reach service boundary')
        put('/root/fresh-owner-password',owner_password)
        put('/root/fresh-gate-context.json',json.dumps({'schema':1,'owner_run':json.loads(Path('/etc/vpn-control/worker-lab.json').read_bytes())['owner_run'],'api_pid':None,'domain':'lab.example','config':c}))
        put('/root/fresh-gate-receipt.json',json.dumps({'schema':1,'bundle_sha256':hashlib.sha256(raw).hexdigest(),'core_sha':payload['source_sha'],'fresh_renderer_caddy_sha256':original_hash,'actual_install_panel_to_service_boundary':True,'services_started':False,'full_fresh_vpn_install_proven':False,'adaptations':adapted+['local-rendered-TLS-port','synthetic-committed-VPN-renderer-output']}))
        put('/run/fresh-service-boundary',b'')
        print('Actual bundled install_panel reached real service-start boundary; external canonical-unit phase REQUIRED',flush=True)
        while Path('/run/fresh-service-boundary').exists():time.sleep(0.25)

def services(project,number):
    import subprocess,urllib.parse
    from panel_frontend_rehearsal import canonical_service,canonical_lab_service
    project=Path(project).resolve();number=int(number);root=project/('rehearsal-root-'+str(number))
    marker=root/'run/fresh-service-boundary'
    require(marker.is_file() and (root/'.vpn-control-rehearsal').is_file(),'actual fresh boundary required')
    pid=int(subprocess.check_output(['systemctl','show','vpn-full-worker-root-'+str(number),'-p','MainPID','--value']))
    require(pid>1 and Path('/proc/'+str(pid)+'/root').samefile(root),'owned root identity required')
    ctx=json.loads((root/'root/fresh-gate-context.json').read_bytes());owner_run=ctx['owner_run']
    front=root/'run/ui-frontend';front.mkdir(mode=0o700)
    tls=root/'etc/vpn-control/private-panel'
    for source,target in [('leaf.crt','cert'),('tls.key','key')]:shutil.copyfile(tls/source,front/target);(front/target).chmod(0o600)
    conf=(tls/'Caddyfile').read_text();require(conf.count('/run/vpn-control-api/api.sock')==1,'generated frontend API socket contract')
    put(front/'restart-config',conf.replace('/run/vpn-control-api/api.sock','/api/api.sock'))
    shutil.copyfile(root/'etc/vpn-control/api.env',root/'etc/vpn-control/restart-api.env')
    created=[];failures=[];stop=threading.Event()
    api_name='vpn-w9u-api-'+str(number);worker_name='vpn-fresh-worker-'+str(number)
    def launch(name,properties,executable,wait=False):
        args=['systemd-run','--quiet','--unit='+name]
        if wait:args+=['--wait','--pipe']
        for prop in properties:args+=['-p',prop]
        result=subprocess.run(args+list(map(str,executable)),capture_output=True,timeout=190)
        require(result.returncode==0,'generated derived unit failed: '+name)
    try:
        for kind,filename in [('api','vpn-control-api.service'),('panel','vpn-control-panel.service')]:
            entries=canonical_service(root/'etc/systemd/system'/filename)
            name,props,exe=canonical_lab_service(entries,kind,root,project,number,pid,owner_run)
            if kind=='api':exe[0]='/usr/local/bin/vpn-control'
            else:
                props=[('InaccessiblePaths=+/proc +/var/lib/vpn-control +/var/lib/empire-vpn +/etc/empire-vpn +/run/evpn-lab-caddy-admin' if prop.startswith('InaccessiblePaths=') else prop) for prop in props]
            props+=['BindReadOnlyPaths='+str(root/'usr/local')+':/usr/local']
            launch(name,props,exe);created.append(name)
        socket_path=root/('run/'+api_name+'/api.sock')
        deadline=time.monotonic()+25
        while not socket_path.is_socket() and time.monotonic()<deadline:time.sleep(.1)
        require(socket_path.is_socket(),'generated API did not start')
        for name in created:
            service_pid=int(subprocess.check_output(['systemctl','show',name,'-p','MainPID','--value']))
            require(service_pid>1,'derived service inactive')
            fields=dict(line.split(':',1) for line in Path('/proc/'+str(service_pid)+'/status').read_text().splitlines() if ':' in line)
            require(fields['Uid'].split()==['981']*4 and int(fields['CapEff'],16)==0,'service UID/caps mismatch')
        # Wait for real frontend -> API readiness, not merely Type=exec PIDs.
        deadline=time.monotonic()+30
        while True:
            ready=subprocess.run(['nsenter','-t',str(pid),'-n','curl','--noproxy','*','--max-time','3','--cacert',str(tls/'ca.crt'),'--resolve','panel.home.arpa:18650:127.0.0.1','--silent','--show-error','--fail','--output','/dev/null','https://panel.home.arpa:18650/login'],capture_output=True,timeout=5)
            if ready.returncode==0:break
            require(time.monotonic()<deadline,'generated TLS frontend/API readiness failed')
            time.sleep(.2)
        # Real TLS login using generated private panel CA, password only via stdin.
        login_code="""import http.client,ssl,sys,urllib.parse,json
from pathlib import Path
root=Path(sys.argv[1]);password=sys.stdin.read()
c=http.client.HTTPSConnection('127.0.0.1',18650,context=ssl.create_default_context(cafile=str(root/'etc/vpn-control/private-panel/ca.crt')),timeout=10)
# Connect by loopback while validating the actual panel.home.arpa certificate.
s=__import__('socket').create_connection(('127.0.0.1',18650),10)
c.sock=ssl.create_default_context(cafile=str(root/'etc/vpn-control/private-panel/ca.crt')).wrap_socket(s,server_hostname='panel.home.arpa')
c.request('POST','/login',urllib.parse.urlencode({'username':'owner','password':password}),{'Origin':'https://panel.home.arpa','Host':'panel.home.arpa','Content-Type':'application/x-www-form-urlencoded'})
r=c.getresponse();assert r.status==303
cookie=r.getheader('Set-Cookie').split(';',1)[0].split('=',1)[1]
print(cookie)
"""
        login=subprocess.run(['nsenter','-t',str(pid),'-n','python3','-B','-c',login_code,str(root)],input=(root/'root/fresh-owner-password').read_text(),text=True,capture_output=True,timeout=20)
        require(login.returncode==0,'generated frontend TLS owner login failed')
        put(root/'root/ui-owner-session',login.stdout.strip()+'\n')
        put(root/'run/ui-context.json',json.dumps({'synthetic':True,'api_socket':'/run/'+api_name+'/api.sock','owner_run':owner_run}))
        put(root/'run/ui-hold',b'');shutil.copyfile(root/'etc/lab-ca.pem',root/'etc/vpn-control/lab-ca.pem')
        entries=canonical_service(root/'etc/systemd/system/vpn-control-worker@.service')
        worker_props=[];worker_exe=None
        for key,value in entries:
            value=value.replace('%i','lab')
            if key=='ExecStart':worker_exe=['/usr/local/bin/vpnctl','worker','once','--installation','lab','--owner-run',owner_run];continue
            if key=='EnvironmentFile':value=str(root/'etc/vpn-control/worker-lab.env')
            if key=='ReadWritePaths':value=' '.join('+'+p for p in value.split())
            worker_props.append(key+'='+value)
        worker_props+=['RootDirectory='+str(root),'MountAPIVFS=yes','NetworkNamespacePath=/proc/'+str(pid)+'/ns/net','BindReadOnlyPaths=/usr','BindReadOnlyPaths=/opt/empire-vpn/bin','BindReadOnlyPaths='+str(root/'usr/local')+':/usr/local']
        def worker():
            while not stop.is_set():
                try:launch(worker_name,worker_props,worker_exe,True)
                except BaseException as e:failures.append(type(e).__name__);stop.set();return
                stop.wait(.5)
        thread=threading.Thread(target=worker);thread.start()
        try:
            result=subprocess.run(['python3','-B',str(project/'pilot/owner_cli_rehearsal.py'),str(project),str(number)],capture_output=True,timeout=190)
            require(result.returncode==0 and not failures,'actual owner create/download/worker/profile check failed')
        finally:stop.set();thread.join(190)
        old_profile=root/'var/lib/empire-vpn/lab/master_user.sfa.json'
        old_hash=hashlib.sha256(old_profile.read_bytes()).hexdigest()
        old_code="""import contextlib,json,sys
from pathlib import Path
project,root=map(Path,sys.argv[1:]);sys.path[:0]=[str(project),str(project/'pilot')]
from full_worker_rehearsal import profile_client
with contextlib.ExitStack() as stack:profile_client(stack,json.loads((root/'var/lib/empire-vpn/lab/master_user.sfa.json').read_bytes()),19107,root/'etc/lab-ca.pem')
"""
        old=subprocess.run(['nsenter','-t',str(pid),'-n','python3','-B','-c',old_code,str(project),str(root)],capture_output=True,timeout=35)
        require(old.returncode==0 and hashlib.sha256(old_profile.read_bytes()).hexdigest()==old_hash,'old master profile TCP/UoT/preservation failed')
        receipt=json.loads((root/'root/fresh-gate-receipt.json').read_bytes())
        receipt.update(services_started=True,generated_api_frontend_uid_caps=True,owner_tls_login=True,owner_create_download_new_profile_tcp_uot=True,old_master_profile_tcp_uot=True,full_fresh_vpn_install_proven=False)
        put(root/'root/fresh-gate-receipt.json',json.dumps(receipt))
        print('Actual generated API/frontend/worker, TLS owner login and new profile TCP/UoT PASS',flush=True)
    finally:
        stop.set()
        for name in [worker_name,*reversed(created)]:subprocess.run(['systemctl','stop',name],capture_output=True,timeout=30)
        for name in created:
            state=subprocess.check_output(['systemctl','show',name,'-p','MainPID','--value'],text=True).strip();require(state=='0','owned service not stopped')
        if (root/'run/ui-hold').exists():(root/'run/ui-hold').unlink()
        if marker.exists():marker.unlink()

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--services':services(sys.argv[2],sys.argv[3])
    else:main()
