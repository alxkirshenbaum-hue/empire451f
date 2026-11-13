"""Prepare a new synthetic root under /run, without touching host configuration."""
import os
import shutil
from pathlib import Path
import sys


def main():
    root=Path(sys.argv[1])
    if root.parent != Path('/run/vpn-w3-worker-tests') or not root.name.startswith('rehearsal-root-') or root.exists():
        raise RuntimeError('new dedicated rehearsal root required')
    # Inside chroot this is '/', which dedicated service UIDs must traverse.
    # The host parent remains private; secret subdirectories below use 0700.
    root.mkdir(mode=0o755)
    for name in ('usr','work','proc','sys','dev','tmp','var/tmp','etc/ssl','opt/empire-vpn/bin','run','var/lib'):
        (root/name).mkdir(parents=True,exist_ok=True)
    (root/'tmp').chmod(0o1777);(root/'var/tmp').chmod(0o1777)
    for name,target in (('bin','usr/bin'),('sbin','usr/sbin'),('lib','usr/lib'),('lib64','usr/lib64')):
        (root/name).symlink_to(target)
    (root/'.vpn-control-rehearsal').write_text('synthetic root, not a production cutover\n')
    (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nevpn-panel:x:981:981:web:/nonexistent:/bin/false\nevpn:x:999:986:relay:/nonexistent:/bin/false\nevpn-caddy:x:982:982:caddy:/nonexistent:/bin/false\n')
    (root/'etc/group').write_text('root:x:0:\nevpn-panel:x:981:\nevpn:x:986:\nevpn-caddy:x:982:\n')
    # Bind only a source subtree that does not contain RootDirectory itself.
    # A recursive read-only bind of its ancestor would also cover the test root.
    source=root.parent/'rehearsal-source'
    source.mkdir(mode=0o700,exist_ok=True)
    project=Path(__file__).resolve().parents[1]
    for name in ('owned_auth.py','create_probe.py','g3_snapshot.py','g3_restore_runtime.py','inspect_legacy.py','handoff_legacy.py','return_legacy.py','render.py','verify.py'):
        shutil.copy2(project/name,source/name)
    for name in ('templates','rehearsal-bin'):
        shutil.copytree(project/name,source/name,dirs_exist_ok=True)
    (source/'local/bin').mkdir(parents=True,exist_ok=True)
    shutil.copy2(project/'rehearsal-bin/vpnctl',source/'local/bin/vpnctl')
    template=(project/'templates/vpn-add-user').read_text()
    (source/'vpn-add-user.template').write_text(template)
    (source/'local/bin/vpn-add-user').write_text(template.replace('@STATE@','/var/lib/empire-vpn/lab').replace('@BASE@','/etc/empire-vpn/lab').replace('@PREFIX@','evpn-lab'))
    (source/'local/bin/vpn-add-user').chmod(0o755)
    (source/'pilot').mkdir(exist_ok=True)
    for name in ('recovery_probe.py','full_worker_rehearsal.py'):
        shutil.copy2(project/'pilot'/name,source/'pilot'/name)
    # git archive may carry group-write bits. Reproduce secure installation
    # modes explicitly; the worker correctly refuses writable helper scripts.
    source.chmod(0o755)
    for path in source.rglob('*'):
        if path.is_dir():path.chmod(0o755)
        elif path.is_file():path.chmod(0o644 | (path.stat().st_mode & 0o111))


if __name__=='__main__':main()
