"""G0b lab driver. Requires a private network namespace containing ONLY lo."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import runpy

from verify import connect, readn

BIN = Path('/opt/empire-vpn/bin')
TARGET = '192.0.2.119'
NULL = subprocess.DEVNULL


def run(*args):
    subprocess.run(args, check=True, stdout=NULL, stderr=NULL, timeout=30)


def spawn(*args):
    return subprocess.Popen(args, stdout=NULL, stderr=NULL)


def stop(proc, timeout=4):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return True
    return False


def await_port(port, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f'Process for port {port} exited: {proc.returncode}')
        try:
            socket.create_connection(('127.0.0.1', port), timeout=.2).close()
            return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f'Listener {port} missing')


def save(path, obj):
    Path(path).write_text(json.dumps(obj))


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(1024):
            self.request.sendall(data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def flows(stack, port):
    tcp = stack.enter_context(connect(port, TARGET, 19876))
    control = stack.enter_context(socket.create_connection(('127.0.0.1', port), 3))
    control.sendall(b'\x05\x01\x00')
    assert readn(control, 2) == b'\x05\x00'
    control.sendall(b'\x05\x03\x00\x01' + bytes(6))
    assert readn(control, 4) == b'\x05\x00\x00\x01'
    ip = socket.inet_ntoa(readn(control, 4))
    relay = int.from_bytes(readn(control, 2))
    udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    udp.connect(('127.0.0.1' if ip == '0.0.0.0' else ip, relay))
    header = b'\x00\x00\x00\x01' + socket.inet_aton(TARGET) + (19876).to_bytes(2)
    tcp.settimeout(1)
    udp.settimeout(1)
    def tick_tcp():
        nonce = os.urandom(16)
        tcp.sendall(nonce)
        return readn(tcp, len(nonce)) == nonce
    def tick_udp():
        nonce = os.urandom(16)
        udp.send(header + nonce)
        return udp.recv(512) == header + nonce
    return tick_tcp, tick_udp


def new_socks_stream(port):
    try:
        with connect(port, TARGET, 19876) as sock:
            nonce = os.urandom(16)
            sock.sendall(nonce)
            return readn(sock, len(nonce)) == nonce
    except (OSError, RuntimeError):
        return False


def client(stack, name, password, port):
    cfg = f'client-{port}.json'
    save(cfg, dict(log=dict(disabled=True), inbounds=[dict(type='socks', listen='127.0.0.1',
        listen_port=port)], outbounds=[dict(type='naive', server='127.0.0.1', server_port=18443,
        username=name, password=password, tls=dict(enabled=True, server_name='lab.example',
        certificate_path=str(Path('cert').resolve())), udp_over_tcp=dict(enabled=True, version=2))]))
    proc = spawn(BIN/'sing-box', 'run', '-c', cfg)
    stack.callback(stop, proc)
    await_port(port, proc)


def experiment(mode, issuer):
    cfg = Path('Caddyfile').resolve()
    auth = cfg.with_name('auth.caddy')
    admin = 'off' if mode == 'restart' else 'unix/'+str(Path('admin.sock').resolve())
    cfg.write_text('{\n admin '+admin+'\n persist_config off\n auto_https off\n'
        ' order forward_proxy before file_server\n servers {\n protocols h1 h2\n }\n}\n'
        'https://:18443 {\n bind 127.0.0.1\n tls cert key\n route {\n forward_proxy {\n'
        ' import '+str(auth)+'\n hide_ip\n hide_via\n probe_resistance\n upstream http://127.0.0.1:1081\n'
        ' }\n respond "site" 200\n }\n}\n')
    stable, target = 'stable', 'target'
    users = {k:secrets.token_urlsafe() for k in (stable,target)}
    def write_auth():
        auth.write_text(''.join('basic_auth '+json.dumps(n)+' '+json.dumps(p)+'\n' for n,p in users.items()))
    write_auth()
    def start():
        proc = spawn(BIN/'caddy','run','--config',cfg,'--adapter','caddyfile')
        await_port(18443,proc)
        return proc
    proc = start()
    trust = ssl.create_default_context(cafile='cert')
    def fresh(n,p):
        token = base64.b64encode(f'{n}:{p}'.encode()).decode()
        with socket.create_connection(('127.0.0.1',18443),1) as raw, trust.wrap_socket(raw,server_hostname='lab.example') as sock:
            addr=TARGET+':19876'
            sock.sendall(f'CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n'.encode())
            buf = sock.makefile('rb')
            line = buf.readline(4096)
            if not line.startswith(b'HTTP/1.1 200 '): return False
            while True:
                line=buf.readline(4096)
                if line==b'\r\n':break
                if line.lower().startswith(b'content-length:'):return False
                if not line: return False
            nonce=os.urandom(16)
            sock.sendall(nonce)
            return buf.read(16)==nonce
    def apply():
        nonlocal proc
        if mode=='reload':
            run(BIN/'caddy','reload','--config',cfg,'--adapter','caddyfile','--address',admin)
        else:
            forced=stop(proc,90)
            print('restart forced kill:',forced,flush=True)
            proc=start()
    try:
        assert fresh(stable,users[stable]) and not fresh(stable,'wrong')
        for operation in ('create','rotate','disable'):
            with contextlib.ExitStack() as stack:
                checks={}
                for port,n in enumerate((stable,target),19080):
                    client(stack,n,users[n],port)
                    a,b=flows(stack,port)
                    checks[n+'_TCP']=a
                    checks[n+'_UoT']=b
                checks['new_stable_CONNECT']=lambda:fresh(stable,users[stable])
                events={k:[] for k in checks}
                done=threading.Event()
                def monitor(k,probe):
                    while not done.is_set():
                        try: ok=probe()
                        except (OSError,RuntimeError,ValueError):ok=False
                        events[k].append((time.monotonic(),ok))
                        done.wait(.2)
                threads=[threading.Thread(target=monitor,args=item,daemon=True) for item in checks.items()]
                for t in threads:t.start()
                try:
                    time.sleep(2)
                    assert all(len(v)>=2 and v[-1][1] for v in events.values()),'baseline flow'
                    old=users[target]
                    begin=time.monotonic()
                    if operation=='create':
                        issue=runpy.run_path(issuer)['issue']
                        save('manifest.json',{'files':{str(auth):hashlib.sha256(auth.read_bytes()).hexdigest()},'config':{'domain':'lab.example','entry':{'ssh':'lab'}}})
                        save('clients.json',{'clients':[dict(username=k,password=v) for k,v in users.items()]})
                        save('master_user.sfa.json',{'outbounds':[dict(type='naive')]})
                        # Use actual issue() and its validate/commit sequence. Substitute lab
                        # paths, unprivileged atomic writer and the isolated lifecycle hook.
                        def write(path,data):
                            tmp=path.with_name('.stage')
                            tmp.write_bytes(data)
                            tmp.replace(path)
                        with patch.dict(issue.__globals__,STATE=cfg.parent,AUTH=auth,write=write,restart=apply),patch('builtins.input',return_value='y'),contextlib.redirect_stdout(io.StringIO()):
                            issue('newuser')
                        users['newuser']=json.loads(Path('vpn-newuser.json').read_text())['outbounds'][0]['password']
                    else:
                        if operation=='rotate':users[target]=secrets.token_urlsafe()
                        else:del users[target]
                        write_auth()
                        apply()
                    end=time.monotonic()
                    assert fresh('newuser',users['newuser']) and fresh(stable,users[stable])
                    assert not fresh(target,'wrong')
                    if operation!='create':assert not fresh(target,old)
                    if target in users:assert fresh(target,users[target])
                    if operation in ('rotate','disable'):
                        assert new_socks_stream(19080), 'unchanged Naive account failed'
                        pooled = new_socks_stream(19081)
                        client(stack,target,old,19082)
                        cold = new_socks_stream(19082)
                        print(json.dumps(dict(mode=mode, operation=operation,
                            pooled_old_login_new_stream=pooled,
                            fresh_old_login_new_stream=cold)), flush=True)
                        assert not cold, 'new Naive client accepted revoked credential'
                    time.sleep(2)
                finally:
                    done.set()
                    for t in threads:t.join(3)
                result={}
                for k,series in events.items():
                    successes=[t for t,ok in series if ok]
                    result[k]=dict(failures=sum(not ok for _,ok in series),after=sum(t>=end for t in successes),max_success_gap_s=round(max((b-a for a,b in zip(successes,successes[1:])),default=0),2))
                print(json.dumps(dict(mode=mode,operation=operation,apply_s=round(end-begin,2),probes=result)),flush=True)
    finally:
        stop(proc)


def main():
    if set(os.listdir('/sys/class/net'))!={'lo'}:
        raise SystemExit('Requires a fresh loopback-only network namespace')
    os.umask(0o077)
    issuer=str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        os.chdir(tmp)
        os.environ['HOME']=tmp
        run('openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1',
            '-subj','/CN=lab.example','-addext','subjectAltName=DNS:lab.example','-keyout','key','-out','cert')
        for server in (socketserver.ThreadingTCPServer(('127.0.0.1',19876),TCP),socketserver.ThreadingUDPServer(('127.0.0.1',19876),UDP)):
            server.daemon_threads=True
            threading.Thread(target=server.serve_forever,daemon=True).start()
            stack.callback(server.server_close)
        save('relay.json',dict(log=dict(disabled=True),inbounds=[dict(type='http',listen='127.0.0.1',listen_port=1081)],outbounds=[dict(type='direct',tag='lab')],route=dict(rules=[dict(ip_cidr=[TARGET+'/32'],port=19876,action='route',outbound='lab',override_address='127.0.0.1')])))
        relay=spawn(BIN/'sing-box','run','-c','relay.json')
        stack.callback(stop,relay)
        await_port(1081,relay)
        modes = sys.argv[2:] or ['restart','reload']
        if not set(modes) <= {'restart','reload'}:
            raise ValueError('Expected restart or reload')
        for mode in modes:
            print('start',mode,flush=True)
            Path('vpn-newuser.json').unlink(missing_ok=True)
            experiment(mode,issuer)


if __name__=='__main__':main()
