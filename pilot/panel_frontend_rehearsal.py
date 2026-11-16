"""Verify the real private TLS frontend in a disposable RootDirectory only."""
import argparse, os, subprocess, time
from pathlib import Path

def command(args):
    result=subprocess.run([str(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if result.returncode: raise RuntimeError(result.stdout.strip() or "isolated subprocess failed")
    return result.stdout.strip()
def require(value,label):
    if not value: raise RuntimeError(label)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("project",type=Path); parser.add_argument("run",type=int)
    parser.add_argument("--browser-port",type=int)
    args=parser.parse_args(); project=args.project.resolve()
    require(args.browser_port is None or 1024 <= args.browser_port <= 65535, "invalid browser port")
    root=project/("rehearsal-root-"+str(args.run))
    require(root.is_dir() and (root/".vpn-control-rehearsal").is_file() and (root/"run/ui-hold").is_file(),"active synthetic root required")
    pid=int(command(["systemctl","show","vpn-full-worker-root-"+str(args.run),"-p","MainPID","--value"]))
    require(pid>1,"copy unit is not running")
    require(root.resolve() == root, "synthetic root must not be symlinked")
    require(command(["systemctl","show","vpn-full-worker-root-"+str(args.run),"-p","RootDirectory","--value"]) == str(root), "copy unit root mismatch")
    import json
    context=json.loads((root/"run/ui-context.json").read_text())
    require(context.get("synthetic") is True and context.get("api_socket") == "/run/vpn-control/api/api.sock", "synthetic API context required")
    require(command(["nsenter","-t",pid,"-n","ip","-o","link","show"]).count("\n")==0,"loopback-only fixture required")
    unit="vpn-panel-tls-copy-"+str(args.run)+"-"+str(time.time_ns())
    # RootDirectory + credentials gets a private /run. Bind only the API
    # directory outside it; never expose the whole runtime or secret trees.
    require((root/"run/vpn-control/api/api.sock").is_socket(), "fixture API socket missing")
    require((root/"run/caddy-admin/admin.sock").is_socket(), "fixture admin socket missing")
    properties=[
        "RootDirectory="+str(root),"MountAPIVFS=yes",
        "NetworkNamespacePath=/proc/"+str(pid)+"/ns/net",
        "User=981","Group=981","NoNewPrivileges=yes","CapabilityBoundingSet=",
        "AmbientCapabilities=","ProtectSystem=strict","ProtectHome=yes",
        "PrivateTmp=yes","PrivateDevices=yes","RestrictSUIDSGID=yes","RestrictNamespaces=yes",
        "SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "IPAddressDeny=any","IPAddressAllow=localhost",
        "InaccessiblePaths=+/proc +/var/lib/vpn-control +/var/lib/empire-vpn +/etc/empire-vpn",
        "BindReadOnlyPaths=/usr","BindReadOnlyPaths=/opt/empire-vpn/bin",
        "BindReadOnlyPaths="+str(root/"run/vpn-control/api")+":/api",
        "RuntimeDirectory=ui-frontend-home","RuntimeDirectoryMode=0700","Environment=HOME=/run/ui-frontend-home",
    ]
    config=root/"run/ui-frontend/config-frontend"
    config.write_text((root/"run/ui-frontend/config").read_text().replace("/run/vpn-control/api/api.sock", "/api/api.sock"))
    config.chmod(0o600)
    for name in ("cert","key","config"):
        properties.append("LoadCredential="+name+":"+str(config if name=="config" else root/"run/ui-frontend"/name))
    start=["systemd-run","--quiet","--unit="+unit]
    for prop in properties:start.extend(["-p",prop])
    try:
        command(start+["/opt/empire-vpn/bin/caddy","run","--adapter","caddyfile","--config","${CREDENTIALS_DIRECTORY}/config"])
        ready=None
        for _ in range(60):
            tls_pid=int(command(["systemctl","show",unit,"-p","MainPID","--value"]))
            if tls_pid:
                ready=subprocess.run(["nsenter","-t",str(pid),"-n","ss","-ltnH","sport = :18650"],capture_output=True,text=True)
                if ready.stdout:break
            time.sleep(.1)
        require(tls_pid>1 and ready and ready.stdout,"TLS frontend failed to listen")
        fields=dict(line.split(":",1) for line in Path("/proc/"+str(tls_pid)+"/status").read_text().splitlines() if ":" in line)
        require(fields["Uid"].split()==["981"]*4 and int(fields["CapEff"],16)==0,"frontend identity/caps")
        require(os.readlink("/proc/"+str(pid)+"/ns/net")==os.readlink("/proc/"+str(tls_pid)+"/ns/net"),"frontend namespace")
        client=r"""
import http.client, socket, ssl, sys
context=ssl.create_default_context(cafile=sys.argv[1])
def get(path):
    raw=socket.create_connection(('127.0.0.1',18650),timeout=5)
    wrapped=context.wrap_socket(raw,server_hostname='panel.home.arpa')
    connection=http.client.HTTPConnection('panel.home.arpa');connection.sock=wrapped
    connection.request('GET',path)
    response=connection.getresponse();body=response.read();headers=dict(response.getheaders());connection.close()
    return response.status,headers,body
status,headers,body=get('/')
assert status==200 and b'Owner sign in' in body, ('frontend HTTP status',status,'body bytes',len(body))
assert headers.get('Cache-Control')=='no-store'
assert headers.get('Referrer-Policy')=='same-origin'
assert get('/api/v1/users')[0]==401
assert get('/config/')[0]==404
print('HTTPS exact SNI/trusted CA/login/no-store/owner denial/admin denial PASS')
"""

        probe=r"""
import os, socket
assert os.geteuid()==981
for path in ['/var/lib/vpn-control','/var/lib/empire-vpn','/etc/empire-vpn','/proc/1/root','/run/caddy-admin/admin.sock']:
    try:
        if path.endswith('admin.sock') or path.endswith('/root'): os.stat(path)
        else: os.listdir(path)
    except PermissionError:pass
    except FileNotFoundError:
        assert path.endswith("admin.sock"), "unexpected missing boundary: "+path
    else:raise RuntimeError('frontend secret boundary readable: '+path)
s=socket.socket(socket.AF_UNIX);s.connect('/api/api.sock');s.close()
print('Frontend vault/proc-root/admin denied; private API socket allowed PASS')
"""
        probe_command=["systemd-run","--quiet","--wait","--pipe","--unit="+unit+"-denials"]
        for prop in properties:
            if not prop.startswith("LoadCredential="):probe_command.extend(["-p",prop])
        print(command(probe_command+["/usr/bin/python3","-B","-c",probe]))
        print(command(["nsenter","-t",pid,"-n","python3","-c",client,root/"run/ui-frontend/cert"]))
        print("Frontend UID981/CapEff0/isolated namespace PASS")
        if args.browser_port is not None:
            validate_browser_root(root,args.run,pid)
            serve_browser(root,args.browser_port)
    finally:subprocess.run(["systemctl","stop",unit],check=False,capture_output=True)

# This adapter is disposable test transport, never a deployment listener.
BROWSER_PATHS = frozenset(('/', '/assets/panel.js', '/api/v1/dashboard',
    '/api/v1/system/resources', '/api/v1/auth/me', '/api/v1/templates',
    '/api/v1/capabilities', '/api/v1/operations', '/api/v1/audits', '/api/v1/backups',
    '/api/v1/users?limit=100&search=&status='))
BROWSER_LIMIT = 2 * 1024 * 1024

def browser_request_allowed(method, target, headers, port):
    origin = 'http://127.0.0.1:' + str(port)
    return (method in ('GET', 'HEAD') and target in BROWSER_PATHS
        and headers.get_all('Host', []) == ['127.0.0.1:' + str(port)]
        and headers.get_all('Origin', []) in ([], [origin])
        and headers.get_all('Sec-Fetch-Site', []) in ([], ['none'], ['same-origin'])
        and not headers.get('Upgrade') and not headers.get('Transfer-Encoding')
        and headers.get_all('Content-Length', []) in ([], ['0']))

def require_fixed_socket(root):
    import stat
    path = root / 'run/vpn-control/api/api.sock'
    require(path.resolve(strict=True) == path and stat.S_ISSOCK(path.lstat().st_mode),
            'fixed synthetic API socket required')

def validate_browser_root(root, run, pid):
    unit = 'vpn-full-worker-root-' + str(run)
    require(command(['systemctl','show',unit,'-p','ActiveState','--value']) == 'active'
        and command(['systemctl','show',unit,'-p','MainPID','--value']) == str(pid)
        and command(['systemctl','show',unit,'-p','RootDirectory','--value']) == str(root),
        'active owned synthetic unit required')
    require((root/'.vpn-control-rehearsal').is_file() and (root/'run/ui-hold').is_file(),
            'active synthetic root required')
    require_fixed_socket(root)

def browser_session(root):
    import stat
    path = root / 'root/ui-owner-session'
    parent = path.parent
    require(parent.resolve() == parent and path.resolve() == path, 'unsafe synthetic session path')
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'private synthetic session parent required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and 1 <= info.st_size <= 513, 'private synthetic session required')
        value = os.read(descriptor, 514)
    finally:
        os.close(descriptor)
    token = value.rstrip(b'\n')
    require(1 <= len(token) <= 512 and all(33 <= c <= 126 and c not in b';,"\\' for c in token),
            'invalid synthetic session')
    return token.decode('ascii')

def browser_upstream(root, token, target):
    import http.client, socket, threading
    connection = http.client.HTTPConnection('localhost', timeout=5)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.settimeout(5)
    upstream_socket = connection.sock
    def expire():
        try: upstream_socket.shutdown(socket.SHUT_RDWR)
        except OSError: pass
    timer = threading.Timer(5, expire); timer.daemon = True; timer.start()
    try:
        connection.sock.connect(str(root / 'run/vpn-control/api/api.sock'))
        connection.request('GET', target, headers={'Cookie': 'session=' + token, 'Accept': '*/*'})
        response = connection.getresponse()
        require(response.status in (200, 401, 403, 404, 503), 'unexpected upstream response')
        body = response.read(BROWSER_LIMIT + 1)
        require(len(body) <= BROWSER_LIMIT, 'upstream response too large')
        # Explicit selection excludes Set-Cookie, redirects, credentials and hop-by-hop headers.
        headers = [(name, response.getheader(name)) for name in
            ('Content-Type', 'Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy')
            if response.getheader(name)]
        return response.status, headers, body
    finally:
        timer.cancel()
        connection.close()

def serve_browser(root, port, lifetime=900):
    import http.server, signal, threading
    require(1024 <= port <= 65535 and 0 < lifetime <= 900, 'invalid browser adapter bounds')
    token = browser_session(root)
    stopped = threading.Event()
    class View(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        def log_message(self, *args): pass
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()
        def setup(self):
            self.request.settimeout(5)
            super().setup()
        def handle_one_request(self):
            try: super().handle_one_request()
            except (OSError, ValueError): self.close_connection = True
        def parse_request(self):
            if not super().parse_request(): return False
            if self.command not in ("GET", "HEAD"):
                self.send_error(405, "Read-only view"); self.close_connection = True; return False
            return True
        def do_GET(self):
            if not browser_request_allowed(self.command, self.path, self.headers, port):
                self.send_error(403, 'Request refused'); return
            try: status, headers, body = browser_upstream(root, token, self.path)
            except Exception:
                self.send_error(503, 'View unavailable'); return
            self.send_response(status)
            for name, value in headers: self.send_header(name, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command != 'HEAD': self.wfile.write(body)
        do_HEAD = do_GET
        def refused(self): self.send_error(405, 'Read-only view')
        do_POST = do_PUT = do_PATCH = do_DELETE = do_CONNECT = do_OPTIONS = do_TRACE = refused
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 4
        def __init__(self):
            self.slots = threading.BoundedSemaphore(4)
            super().__init__(('127.0.0.1', port), View)
            self.timeout = .25
        def process_request(self, request, address):
            if not self.slots.acquire(False): self.shutdown_request(request); return
            try: super().process_request(request, address)
            except Exception:
                self.slots.release(); raise
        def process_request_thread(self, request, address):
            try: super().process_request_thread(request, address)
            finally: self.slots.release()
        def handle_error(self, request, address): pass
    previous = {}
    try:
        with Server() as server:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda *_: stopped.set())
            print('Readonly synthetic browser view ready on 127.0.0.1:' + str(port), flush=True)
            deadline = time.monotonic() + lifetime
            while not stopped.is_set() and time.monotonic() < deadline:
                server.handle_request()
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)

if __name__=="__main__":main()
