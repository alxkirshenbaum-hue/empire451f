import json,os,subprocess,socket
from pathlib import Path
pid=int(subprocess.check_output(["systemctl","show","vpn-control-panel.service","-p","MainPID","--value"],text=True))
api=int(subprocess.check_output(["systemctl","show","vpn-control-api.service","-p","MainPID","--value"],text=True))
status=dict(line.split(":",1) for line in Path("/proc/"+str(pid)+"/status").read_text().splitlines() if ":" in line)
assert status["Uid"].split()==["981"]*4 and int(status["CapEff"],16)==0 and int(status["Seccomp"])==2
assert os.stat("/proc/"+str(pid)+"/ns/net").st_ino==os.stat("/run/netns/naive").st_ino
probe=r"""
import os,socket,sys
assert os.geteuid()==981
for path in ['/var/lib/vpn-control','/var/lib/empire-vpn','/etc/empire-vpn','/proc/1/root','/run/evpn-nh1-caddy-admin/admin.sock']:
    try:
        if path.endswith('/root') or path.endswith('admin.sock'):os.stat(path)
        else:os.listdir(path)
    except PermissionError:pass
    else:raise RuntimeError('Frontend boundary readable: '+path)
s=socket.socket(socket.AF_UNIX);s.connect('/run/vpn-control-api/api.sock');s.close()
print('Actual frontend mount/UID: vault, profiles, proc-root, admin denied; API connect PASS')
"""
result=subprocess.run(["nsenter","-t",str(pid),"-m","-n","-r","-w","/usr/bin/setpriv","--reuid=981","--regid=981","--clear-groups","--bounding-set=-all","/usr/bin/python3","-B","-c",probe],capture_output=True,text=True)
assert result.returncode==0,result.stderr
print(result.stdout.strip())
print('Frontend UID981/CapEff0/Seccomp2/exact naive namespace PASS')
