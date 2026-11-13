"""Fresh Naive/TLS, TCP, UoT and website checks for the privileged worker.

Policy is installed by the approved G3 procedure. Credentials enter on stdin
or are read from the managed auth file; diagnostics never include their values.
"""
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from inspect_legacy import auth_lines, unique_fields
from render import credentials
from verify import connect, readn, udp, https_ip, require


def root_file(path, private=False):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and not path.is_symlink() and info.st_uid == 0 and info.st_mode & 0o022 == 0
            and (not private or info.st_mode & 0o077 == 0), 'Untrusted probe policy')
    return path


def website(p):
    trust = ssl.create_default_context(cafile=p.get('ca_file'))
    with socket.create_connection((p['address'],p['port']),6) as raw:
        with trust.wrap_socket(raw,server_hostname=p['domain']) as secured:
            secured.sendall(('GET / HTTP/1.1\r\nHost: '+p['domain']+'\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(secured)
            response.begin()
            body = response.read(1024*1024+1)
            require(response.status == 200 and len(body) <= 1024*1024
                    and hashlib.sha256(body).hexdigest() == p['site_sha256'], 'Website baseline changed')


@contextmanager
def client(p, login, password):
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0))
        port = reserve.getsockname()[1]
    outbound = dict(type='naive',tag='proxy',server=p['address'],server_port=p['port'],
                    username=login,password=password,udp_over_tcp=dict(enabled=True,version=2),
                    tls=dict(enabled=True,server_name=p['domain']))
    if p.get('ca_file'):
        outbound['tls']['certificate_path'] = p['ca_file']
    config = dict(log=dict(disabled=True),inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=port)],
                  outbounds=[outbound],route=dict(final='proxy'))
    scratch = Path(p['scratch_dir'])
    require(scratch.is_dir() and scratch.resolve() == scratch and scratch.stat().st_uid == 0
            and scratch.stat().st_mode & 0o077 == 0, 'Private probe scratch directory required')
    with tempfile.TemporaryDirectory(prefix='create-',dir=scratch) as folder:
        file = Path(folder)/'client.json'
        file.write_text(json.dumps(config));file.chmod(0o600)
        subprocess.run([p['binary'],'check','-c',str(file)],check=True,timeout=20,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        child = subprocess.Popen([p['binary'],'run','-c',str(file)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                require(child.poll() is None,'Naive probe client exited')
                try:
                    socket.create_connection(('127.0.0.1',port),.2).close()
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Naive probe listener unavailable')
            yield port
        finally:
            child.terminate()
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill();child.wait()


def tcp(p, port):
    if p['tcp_mode'] == 'exit_https':
        require(https_ip(port) == p['expected_exit'], 'Unexpected TCP exit')
    elif p['tcp_mode'] == 'echo':
        nonce = secrets.token_bytes(32)
        with connect(port,p['tcp_host'],p['tcp_port']) as stream:
            stream.sendall(nonce)
            require(readn(stream,len(nonce)) == nonce,'TCP echo mismatch')
    else:
        raise ValueError('Unsupported TCP probe')


def datagram(p, port):
    if p['udp_mode'] == 'dns':
        tx = secrets.token_bytes(2)
        query = tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        response = udp(port,p['udp_host'],p['udp_port'],query)
        require(len(response) >= 12 and response[:2] == tx and response[2]&128 and response[3]&15 == 0,'DNS over UoT failed')
    elif p['udp_mode'] == 'echo':
        nonce = secrets.token_bytes(32)
        require(udp(port,p['udp_host'],p['udp_port'],nonce) == nonce,'UoT echo mismatch')
    else:
        raise ValueError('Unsupported UoT probe')


def probe(policy_path, login, password):
    p = json.loads(root_file(policy_path,True).read_bytes(),object_pairs_hook=unique_fields)
    credentials(dict(format='empire-vpn-clients',schema_version=1,clients=[dict(username=login,password=password)]))
    root_file(p['binary'])
    if p.get('ca_file'): root_file(p['ca_file'])
    users = dict(auth_lines(root_file(p['auth_file']).read_bytes()))
    canary = p['canary_login']
    require(canary != login and canary in users,'Independent control user required')
    website(p)
    for name,secret in ((canary,users[canary]),(login,password)):
        with client(p,name,secret) as port:
            tcp(p,port);datagram(p,port)
    with client(p,login,secrets.token_hex(32)) as port:
        try: tcp(p,port)
        except (OSError,RuntimeError,subprocess.TimeoutExpired): pass
        else: raise RuntimeError('Wrong password accepted')
    # A negative trial alone cannot distinguish rejection from an outage.
    with client(p,canary,users[canary]) as port:
        tcp(p,port);datagram(p,port)
    website(p)


def main():
    try:
        require(len(sys.argv) == 3 and sys.argv[1] == '--policy','Expected probe policy')
        login,password = json.loads(sys.stdin.buffer.read(4097))
        probe(sys.argv[2],login,password)
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,http.client.HTTPException,subprocess.SubprocessError):
        print('Fresh Naive/TLS/TCP/UoT/site probe failed.',file=sys.stderr)
        return 1
    print('{"verified":true}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
