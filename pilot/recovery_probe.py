"""Probe a restored synthetic auth include with Caddy and a real Naive client."""
import contextlib
import copy
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


BIN=Path('/opt/empire-vpn/bin')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data=self.request.recv(128)
        if data:
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def start(stack,args,port):
    child=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def close():
        child.terminate()
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    stack.callback(close)
    for _ in range(80):
        if child.poll() is not None:
            raise RuntimeError('isolated process exited')
        try:
            socket.create_connection(('127.0.0.1',port),timeout=.2).close()
            return
        except OSError:time.sleep(.05)
    raise TimeoutError('listener missing')


def readn(sock,n):
    buf=b''
    while len(buf)<n:
        part=sock.recv(n-len(buf))
        if not part:raise EOFError()
        buf+=part
    return buf


def attempt(port):
    # Request an echo using the synthetic destination in the test relay.
    with socket.create_connection(('127.0.0.1',port),3) as sock:
        sock.sendall(b'\x05\x01\x00')
        if readn(sock,2)!=b'\x05\x00':raise RuntimeError('SOCKS negotiation')
        sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('192.0.2.119')+(19876).to_bytes(2))
        head=readn(sock,4)
        if head[1]!=0:return False
        size={1:4,4:16}.get(head[3])
        if size is None:size=readn(sock,1)[0]
        readn(sock,size+2)
        nonce=secrets.token_bytes(16)
        sock.sendall(nonce)
        return readn(sock,len(nonce))==nonce


def perform(req, issue=None):
    if set(os.listdir('/sys/class/net'))!={'lo'}:
        raise RuntimeError('requires isolated loopback')
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        os.chdir(tmp)
        os.environ['HOME']=tmp
        def run(args):
            subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=20)
        run(['openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','1','-subj',
             '/CN=lab.example','-addext','subjectAltName=DNS:lab.example','-keyout','key','-out','cert'])
        Path('auth.caddy').write_text(req['auth'])
        admin = 'unix/' + str(Path('admin.sock').resolve()) if issue else 'off'
        Path('Caddyfile').write_text('{\n admin '+admin+'\n persist_config off\n auto_https off\n order forward_proxy before file_server\n}\nhttps://:18443 {\n bind 127.0.0.1\n tls cert key\n route {\n forward_proxy {\n import auth.caddy\n hide_ip\n hide_via\n probe_resistance\n upstream http://127.0.0.1:1081\n }\n respond "site" 200\n }\n}\n')
        echo=EchoServer(('127.0.0.1',19876),Echo)
        echo.daemon_threads=True
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        stack.callback(echo.server_close)
        relay=dict(log=dict(disabled=True),inbounds=[dict(type='http',listen='127.0.0.1',listen_port=1081)],
                   outbounds=[dict(type='direct',tag='echo')],route=dict(rules=[dict(ip_cidr=['192.0.2.119/32'],
                       port=19876,action='route',outbound='echo',override_address='127.0.0.1')]))
        Path('relay.json').write_text(json.dumps(relay))
        start(stack,[BIN/'sing-box','run','-c','relay.json'],1081)
        start(stack,[BIN/'caddy','run','--config','Caddyfile','--adapter','caddyfile'],18443)
        def client(port, outbound):
            o=copy.deepcopy(outbound)
            o.update(server='127.0.0.1',server_port=18443)
            o.pop('domain_resolver',None)
            o['tls'].update(server_name='lab.example',certificate_path=str(Path('cert').resolve()))
            cfg=dict(log=dict(disabled=True),inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=port)],outbounds=[o])
            path=Path(f'client-{port}.json')
            path.write_text(json.dumps(cfg))
            start(stack,[BIN/'sing-box','run','-c',path],port)
        if issue:
            profile = issue(client, run, admin)
        else:
            profile = req['profile']
        Path('restored.json').write_text(json.dumps(profile))
        run([BIN/'sing-box','check','-c','restored.json'])
        outbound,=[o for o in profile['outbounds'] if o['type']=='naive']
        client(19081,outbound)
        client(19082,dict(outbound,username=req.get('revoked_login','revoked'),password=req['revoked']))
        assert attempt(19081)
        try:revoked=attempt(19082)
        except (EOFError,OSError):revoked=False
        assert not revoked
        assert attempt(19081)
        return {'profile_check':'PASS','restored_Naive_TCP':'PASS','revoked_TCP':'BLOCKED'}
