"""End-to-end Naive/TLS + TCP/UoT checks. No insecure TLS or proxy credentials in argv."""
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def readn(sock, size):
    value = b''
    while len(value) < size:
        part = sock.recv(size - len(value))
        require(part, 'Unexpected EOF')
        value += part
    return value


def connect(port, host, target_port):
    s = socket.create_connection(('127.0.0.1', port), timeout=6)
    s.settimeout(6)
    try:
        s.sendall(b'\x05\x01\x00')
        require(readn(s, 2) == b'\x05\x00', 'SOCKS handshake failed')
        name = host.encode()
        s.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', target_port))
        h = readn(s, 4)
        require(h[1] == 0, 'SOCKS request rejected')
        if h[3] == 1:
            readn(s, 6)
        elif h[3] == 4:
            readn(s, 18)
        elif h[3] == 3:
            readn(s, readn(s, 1)[0] + 2)
        else:
            raise RuntimeError('Invalid SOCKS address')
        return s
    except BaseException:
        s.close()
        raise


def udp(port, address, target_port, payload):
    # Service port MUST be zero (the previous SOCKS upstream bug was here).
    with connect(port, 'sp.v2.udp-over-tcp.arpa', 0) as s:
        s.sendall(b'\x01\x01' + socket.inet_aton(address) + struct.pack('!H', target_port) + struct.pack('!H', len(payload)) + payload)
        return readn(s, struct.unpack('!H', readn(s, 2))[0])


def https_ip(port):
    p = subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port), '-4', '-fsS', '--max-time', '12', 'https://api.ipify.org'], capture_output=True, timeout=16)
    require(p.returncode == 0, 'TCP HTTPS failed')
    return p.stdout.decode().strip()


def must_fail(fn, label):
    try:
        fn()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return
    raise RuntimeError('Unexpected successful traffic: ' + label)


def ipv6_probe(port):
    with connect(port, '2606:4700:4700::1111', 443) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname='one.one.one.one') as secured:
            secured.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
            require(secured.recv(64), 'No IPv6 response')


def verify(c, clients, blocked=False, before_block=None):
    binary = '/opt/empire-vpn/bin/sing-box'
    if c['entry']['kind'] == 'legacy':
        binary = '/usr/local/lib/sing-box/sing-box'
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    user = clients['clients'][0]
    if not blocked:
        for attempt in range(12):
            site = subprocess.run(['curl', '-fsS', '--max-time', '8', '--resolve', c['domain'] + ':443:' + c['entry']['address'], 'https://' + c['domain'] + '/'], capture_output=True, timeout=12)
            if site.returncode == 0 and b'<!doctype html>' in site.stdout.lower():
                break
            time.sleep(5)
        else:
            raise RuntimeError('Website/TLS not ready; check DNS, provider firewall and ACME')
    conf = {'log': {'disabled': True}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port}],
            'outbounds': [{'type': 'naive', 'tag': 'proxy', 'server': c['entry']['address'], 'server_port': 443,
                           'username': user['username'], 'password': user['password'],
                           'tls': {'enabled': True, 'server_name': c['domain']}}], 'route': {'final': 'proxy'}}
    with tempfile.TemporaryDirectory(prefix='evpn-verify-', dir='/run') as folder:
        os.chmod(folder, 0o700)
        cfg = Path(folder) / 'client.json'
        cfg.write_text(json.dumps(conf))
        cfg.chmod(0o600)
        check = subprocess.run([binary, 'check', '-c', str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(check.returncode == 0, 'Naive client configuration invalid')
        child = subprocess.Popen([binary, 'run', '-c', str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        held = None
        try:
            for _ in range(40):
                require(child.poll() is None, 'Naive client exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Naive client did not start')
            query = b'\x52\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            if blocked:
                if before_block:
                    held = ssl.create_default_context().wrap_socket(connect(port, 'www.cloudflare.com', 443), server_hostname='www.cloudflare.com')
                    before_block()
                    def existing():
                        held.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n')
                        require(held.recv(64), 'Existing TCP closed')
                    must_fail(existing, 'existing TCP with WG down')
                must_fail(lambda: https_ip(port), 'TCP with WG down')
                must_fail(lambda: udp(port, c['dns'], 53, query), 'DNS with WG down')
            else:
                require(https_ip(port) == c['exit']['address'], 'Wrong TCP exit IP')
                answer = udp(port, c['dns'], 53, query)
                require(answer[:2] == query[:2] and answer[2] & 128 and answer[3] & 15 == 0, 'UoT DNS failed')
                tx = os.urandom(12)
                answer = udp(port, socket.gethostbyname('stun.l.google.com'), 19302, struct.pack('!HHI', 1, 0, 0x2112a442) + tx)
                require(answer[:2] == b'\x01\x01' and answer[8:20] == tx, 'STUN failed')
                found = None
                pos = 20
                while pos + 4 <= len(answer):
                    typ, length = struct.unpack('!HH', answer[pos:pos + 4])
                    value = answer[pos + 4:pos + 4 + length]
                    pos += 4 + ((length + 3) // 4) * 4
                    if typ == 0x20 and len(value) >= 8 and value[1] == 1:
                        found = socket.inet_ntoa(bytes(a ^ b for a, b in zip(value[4:8], b'\x21\x12\xa4\x42')))
                require(found == c['exit']['address'], 'Wrong UDP exit IP')
                p = subprocess.run(['curl', '-fsS', '--max-time', '20', '--resolve', c['domain'] + ':443:' + c['entry']['address'], 'https://' + c['domain'] + '/'], capture_output=True, timeout=25)
                require(p.returncode == 0 and b'<!doctype html>' in p.stdout.lower(), 'Website or trusted TLS failed')
            must_fail(lambda: ipv6_probe(port), 'IPv6')
            must_fail(lambda: udp(port, '127.0.0.1', 53, query), 'private UDP')
            return {'TCP': 'BLOCKED' if blocked else 'PASS', 'UoT_DNS': 'BLOCKED' if blocked else 'PASS', 'IPv6_private': 'BLOCKED', 'STUN_site_TLS': 'not-tested' if blocked else 'PASS'}
        finally:
            if held:
                held.close()
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
