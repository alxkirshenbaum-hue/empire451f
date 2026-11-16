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
    cf=cf.replace(' acme_ca https://acme-v02.api.letsencrypt.org/directory',' auto_https off')
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
    os.environ.update(XDG_DATA_HOME=str(data),XDG_CONFIG_HOME=str(data))
    with contextlib.ExitStack() as stack:
        for server in (EchoServer(('127.0.0.1',19876),Echo),EchoDatagramServer(('127.0.0.1',19877),EchoDatagram)):
            server.daemon_threads=True;threading.Thread(target=server.serve_forever,daemon=True).start();stack.callback(server.server_close)
        relay_process=start(stack,unpriv(999,986)+[BIN/'sing-box','run','-c','/run/relay/config.json'],1081)
        caddy_process=start(stack,unpriv(982,982)+[BIN/'caddy','run','--config',base/'Caddyfile','--adapter','caddyfile'],18443)
        service_identity(relay_process,999);service_identity(caddy_process,982)
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

if __name__=='__main__':main()
