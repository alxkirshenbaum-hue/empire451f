"""Controlled outage tests. Invoked with the pinned verifier by Audit-Vpn.ps1."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


def cmd(*argv):
    return subprocess.check_output(argv, timeout=50, text=True, stderr=subprocess.DEVNULL).strip()


def controlled(action, ident):
    if not re.fullmatch('[a-z][a-z0-9]{2,9}', ident):
        raise ValueError('Invalid deployment ID')
    state = Path('/var/lib/empire-vpn') / ident
    meta = json.loads((state/'manifest.json').read_text())
    c = meta['config']
    role = meta['role']
    assert c['id'] == ident and not (state/'pending.json').exists() and c[role]['kind'] != 'legacy'
    if action == 'pair':
        print(role,c['entry']['address'],c['exit']['address'])
        return
    if action == 'boot-check':
        warnings = cmd('journalctl','-b','-p','warning','-o','cat','--no-pager')
        if re.search('ordering cycle|deleted to break',warnings,re.I):
            raise RuntimeError('systemd ordering cycle reported')
        return
    if action == 'reboot':
        cmd('systemd-run','--collect','--on-active=3s','/usr/bin/systemctl','reboot')
        return
    assert role == 'entry'
    users = json.loads((state/'clients.json').read_text())
    if action == 'health':
        print(verify(c,users),flush=True)
        return
    assert action == 'exercise'
    prefix = 'evpn-'+ident+'-'
    services = [prefix+x+'.service' for x in ('network','singbox','caddy')]
    def healthy():
        for _ in range(30):
            if all(subprocess.run(['systemctl','is-active','--quiet',s]).returncode==0 for s in services):
                break
            time.sleep(1)
        print(verify(c,users), flush=True)
    healthy()
    timer = prefix+'audit-'+uuid.uuid4().hex[:8]
    restore = 'set -e; ip -n naive link set wg0 up; ip -n naive route replace default dev wg0'
    cmd('systemd-run','--collect','--unit='+timer,'--on-active=100s','/bin/sh','-ec',restore)
    try:
        def down():
            cmd('ip','-n','naive','link','set','wg0','down')
            print('WG down: testing established TCP, new TCP, DNS and IPv6',flush=True)
        print(verify(c,users,blocked=True,before_block=down),flush=True)
    finally:
        cmd('/bin/sh','-ec',restore)
        cmd('systemctl','stop',timer+'.timer')
    healthy()
    for s in reversed(services[1:]):
        pid = cmd('systemctl','show','-p','MainPID','--value',s)
        assert int(pid)>1
        print('Crash test: '+s,flush=True)
        cmd('systemctl','kill','--kill-whom=main','--signal=SIGKILL',s)
        try:
            for _ in range(35):
                new = cmd('systemctl','show','-p','MainPID','--value',s)
                if int(new)>1 and new!=pid and all(subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0 for unit in services):
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Automatic process recovery failed: '+s)
            healthy()
        finally:
            cmd('systemctl','start',*services)
    print('Namespace recreation',flush=True)
    # Hold a reference so the kernel cannot recycle this inode during the test.
    fallback = prefix+'audit-net-'+uuid.uuid4().hex[:8]
    cmd('systemd-run','--collect','--unit='+fallback,'--on-active=100s','/usr/bin/systemctl','start',*services)
    old = os.open('/run/netns/naive',os.O_RDONLY)
    try:
        cmd('systemctl','stop',services[0])
        assert not Path('/run/netns/naive').exists()
        cmd('systemctl','start',services[-1])
        assert os.stat('/run/netns/naive').st_ino != os.fstat(old).st_ino
        healthy()
    finally:
        os.close(old)
        cmd('systemctl','start',*services)
        cmd('systemctl','stop',fallback+'.timer')


if __name__ == '__main__':
    controlled(*sys.argv[1:])
