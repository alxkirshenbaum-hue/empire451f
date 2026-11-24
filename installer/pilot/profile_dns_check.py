"""Check the generated exact panel DNS policy with a real client, loopback only."""
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time

def name_end(packet,offset):
    while True:
        size=packet[offset];offset+=1
        if size & 0xc0 == 0xc0: return offset+1
        if size==0: return offset
        if size>63: raise RuntimeError('Invalid DNS name')
        offset+=size

def addresses(packet,tx,kind):
    if packet[:2]!=tx or packet[3]&15 or not packet[2]&128:
        raise RuntimeError('Unexpected DNS response')
    questions,answers=struct.unpack('!HH',packet[4:8])
    offset=12
    for _ in range(questions): offset=name_end(packet,offset)+4
    found=[]
    for _ in range(answers):
        offset=name_end(packet,offset)
        typ,cls,ttl,length=struct.unpack('!HHIH',packet[offset:offset+10]);offset+=10
        data=packet[offset:offset+length];offset+=length
        if typ==kind and cls==1:
            found.append(socket.inet_ntop(socket.AF_INET if kind==1 else socket.AF_INET6,data))
    return found

def main():
    if len(sys.argv)!=2 or set(os.listdir('/sys/class/net'))!={'lo'}:
        raise RuntimeError('Dedicated PrivateNetwork required')
    profile=json.loads(sys.stdin.buffer.read(2*1024*1024))
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    config=dict(log=dict(disabled=True),dns=profile['dns'],outbounds=profile['outbounds'],
        inbounds=[dict(type='direct',tag='dns-test',listen='127.0.0.1',listen_port=port,network='udp')],
        route=dict(rules=[dict(inbound=['dns-test'],action='hijack-dns')],final='naive-out'))
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as root:
        file=Path(root)/'client.json';file.write_text(json.dumps(config));file.chmod(0o600)
        child=subprocess.Popen([sys.argv[1],'run','-c',str(file)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for kind in (1,28):
                for attempt in range(30):
                    if child.poll() is not None: raise RuntimeError('DNS client exited')
                    tx=secrets.token_bytes(2)
                    query=tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05panel\x04home\x04arpa\x00'+struct.pack('!HH',kind,1)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                        client.settimeout(.3);client.sendto(query,('127.0.0.1',port))
                        try: packet,_=client.recvfrom(4096)
                        except socket.timeout: continue
                    found=addresses(packet,tx,kind)
                    if found != (['192.0.2.119'] if kind==1 else []):
                        raise RuntimeError('Unexpected panel address')
                    break
                else: raise RuntimeError('Panel DNS response missing')
        finally:
            child.terminate()
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired: child.kill();child.wait()
    print('profile-panel-DNS: exact A/AAAA policy PASS')

if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,RuntimeError,IndexError,struct.error,subprocess.SubprocessError):
        print('Generated profile panel DNS probe failed.',file=sys.stderr)
        sys.exit(1)
