"""Verify the real private TLS frontend in a disposable RootDirectory only."""
import argparse, os, subprocess, time
from pathlib import Path

def command(args):
    return subprocess.check_output([str(x) for x in args],stderr=subprocess.STDOUT,text=True).strip()
def require(value,label):
    if not value: raise RuntimeError(label)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("project",type=Path); parser.add_argument("run",type=int)
    args=parser.parse_args(); project=args.project.resolve()
    root=project/("rehearsal-root-"+str(args.run))
    require(root.is_dir() and (root/".vpn-control-rehearsal").is_file() and (root/"run/ui-hold").is_file(),"active synthetic root required")
    pid=int(command(["systemctl","show","vpn-full-worker-root-"+str(args.run),"-p","MainPID","--value"]))
    require(pid>1,"copy unit is not running")
    require(command(["nsenter","-t",pid,"-n","ip","-o","link","show"]).count("\n")==0,"loopback-only fixture required")
    unit="vpn-panel-tls-copy-"+str(args.run)
    properties=[
        "RootDirectory="+str(root),"MountAPIVFS=yes",
        "NetworkNamespacePath=/proc/"+str(pid)+"/ns/net",
        "User=981","Group=981","NoNewPrivileges=yes","CapabilityBoundingSet=",
        "AmbientCapabilities=","ProtectSystem=strict","ProtectHome=yes",
        "PrivateTmp=yes","PrivateDevices=yes","RestrictSUIDSGID=yes","RestrictNamespaces=yes",
        "SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "IPAddressDeny=any","IPAddressAllow=localhost",
        "InaccessiblePaths=+/proc +/var/lib/vpn-control +/var/lib/empire-vpn +/etc/empire-vpn +/run/caddy-admin",
        "BindReadOnlyPaths=/usr","BindReadOnlyPaths=/opt/empire-vpn/bin",
        "ReadWritePaths=+/run/ui-frontend-home","Environment=HOME=/run/ui-frontend-home",
    ]
    for name in ("cert","key","config"):
        properties.append("LoadCredential="+name+":"+str(root/"run/ui-frontend"/name))
    start=["systemd-run","--quiet","--unit="+unit]
    for prop in properties:start.extend(["-p",prop])
    try:
        command(start+["/opt/empire-vpn/bin/caddy","run","--adapter","caddyfile","--config","${CREDENTIALS_DIRECTORY}/config"])
        ready=None
        for _ in range(60):
            tls_pid=int(command(["systemctl","show",unit,"-p","MainPID","--value"]))
            if tls_pid:
                ready=subprocess.run(["nsenter","-t",pid,"-n","ss","-ltnH","sport = :18650"],capture_output=True,text=True)
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
assert status==200 and b'Owner sign in' in body
assert headers.get('Cache-Control')=='no-store'
assert headers.get('Referrer-Policy')=='same-origin'
assert get('/api/v1/users')[0]==401
assert get('/config/')[0]==404
print('HTTPS exact SNI/trusted CA/login/no-store/owner denial/admin denial PASS')
"""
        print(command(["nsenter","-t",pid,"-n","python3","-c",client,root/"run/ui-frontend/cert"]))
        probe=r"""
import os, socket
assert os.geteuid()==981
for path in ['/var/lib/vpn-control','/var/lib/empire-vpn','/etc/empire-vpn','/proc/1/root','/run/caddy-admin/admin.sock']:
    try:os.stat(path)
    except PermissionError:pass
    else:raise RuntimeError('frontend secret boundary readable')
s=socket.socket(socket.AF_UNIX);s.connect('/run/vpn-control/api/api.sock');s.close()
print('Frontend vault/proc-root/admin denied; private API socket allowed PASS')
"""
        probe_command=["systemd-run","--quiet","--wait","--pipe","--unit="+unit+"-denials"]
        for prop in properties:
            if not prop.startswith("LoadCredential="):probe_command.extend(["-p",prop])
        print(command(probe_command+["/usr/bin/python3.14","-B","-c",probe]))
        print("Frontend UID981/CapEff0/isolated namespace PASS")
    finally:subprocess.run(["systemctl","stop",unit],check=False,capture_output=True)
if __name__=="__main__":main()