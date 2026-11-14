"""Host-only synthetic encrypted backup/isolated restore drill. Never a deploy tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def run(args, **kw):
    result=subprocess.run([str(x) for x in args],capture_output=True,timeout=600,**kw)
    if result.returncode:
        # Synthetic diagnostics stay in the private run tree, not the report.
        (WORK/'last-failure.log').write_bytes(result.stdout+result.stderr)
        raise RuntimeError('drill subprocess failed: '+Path(str(args[0])).name)
    return result.stdout


def private_write(path,data):
    with path.open('xb') as out:out.write(data)
    path.chmod(0o600)


def completed(unit):
    fields=run(['systemctl','show',unit,'-p','ActiveState','-p','MainPID','-p','Result']).decode()
    if 'MainPID=0' not in fields or 'Result=success' not in fields:raise RuntimeError('unit not successfully finished')
    return fields


def runtime(project,root,unit):
    args=['systemd-run','--quiet','--wait','--pipe','--unit='+unit]
    for prop in ['RootDirectory='+str(root),'MountAPIVFS=yes','PrivateNetwork=yes','PrivateDevices=yes','NoNewPrivileges=yes','ProtectSystem=strict',
                 'ReadWritePaths=+/etc','ReadWritePaths=+/var/lib','ReadWritePaths=+/run','ReadWritePaths=+/tmp','ReadWritePaths=+/root',
                 'BindReadOnlyPaths=/usr','BindReadOnlyPaths='+str(project/'rehearsal-source/local')+':/usr/local','BindReadOnlyPaths=/opt/empire-vpn/bin',
                 'BindReadOnlyPaths=/etc/ssl','BindReadOnlyPaths='+str(project/'rehearsal-source')+':/work','WorkingDirectory=/work']:
        args+=['-p',prop]
    result=run(args+['/usr/bin/python3','-B','/work/pilot/backup_restore_rehearsal.py'])
    completed(unit)
    if b'old profile fresh TCP-UoT / revoked negative / Caddy validate PASS' not in result:raise RuntimeError('runtime proof absent')
    return result.decode()


def main():
    global WORK
    f=argparse.ArgumentParser();f.add_argument('--project',required=True,type=Path);f.add_argument('--run-id',required=True)
    a=f.parse_args();project=a.project.resolve();ident=a.run_id
    if os.geteuid()!=0 or not ident.isdigit() or len(ident)>12:raise RuntimeError('root and numeric unique run ID required')
    WORK=project/('backup-drill-'+ident);WORK.mkdir(mode=0o700)
    os.umask(0o077)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private=WORK/'owner-private.pem';public=WORK/'recipient.pem'
    private_write(private,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    private_write(public,key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    env=dict(os.environ,VPN_REHEARSAL_PROJECT=str(project),VPN_REHEARSAL_BACKUP='1',VPN_REHEARSAL_BACKUP_PUBLIC=str(public))
    run(['sh',project/'pilot/run_full_worker_rehearsal.sh','normal',ident],env=env)
    source=project/('rehearsal-root-'+ident);completed('vpn-full-worker-root-'+ident)
    proof=source/'root/backup-proof';context=json.loads((proof/'context.json').read_bytes())
    cipher=source/context['encrypted_path'].lstrip('/')
    original_cipher=hashlib.sha256(cipher.read_bytes()).hexdigest()
    if original_cipher!=context['sha256']:raise RuntimeError('ciphertext mismatch')
    prepared_parent=WORK/'prepared';prepared_parent.mkdir(mode=0o700)
    stage=WORK/'verified';cli=project/'rehearsal-bin/vpnctl';helper=project/'backup_artifact.py'
    args=[cli,'backup','offline-verify','--envelope',cipher,'--private-key',private,'--cipher-sha256',context['sha256'],
          '--manifest-sha256',context['manifest_sha256'],'--owner-run',context['owner_run'],'--own-operation',context['own_operation'],
          '--backup-id',context['backup_id'],'--prepare-parent',prepared_parent,'--staging',stage,'--helper',helper,
          '--source-panel-root','/var/lib/vpn-control','--source-state-root','/var/lib/empire-vpn/lab','--source-config-root','/etc/empire-vpn']
    checked=json.loads(run(args));candidate=Path(checked['prepared_copy'])
    # Parse only after authenticated/canonical offline verification. No tar extraction.
    plain=WORK/'authenticated.tar'
    request=dict(action='decrypt',envelope=str(cipher),private_key_path=str(private),output=str(plain),expected_sha256=context['sha256'])
    run(['python3','-B',helper],input=json.dumps(request).encode())
    with tarfile.open(plain,'r:') as archive:
        entry=archive.getmember('manifest.json')
        if entry.size>1024*1024:raise RuntimeError('manifest limit')
        manifest=json.load(archive.extractfile(entry))
    recovered=project/('rehearsal-root-'+str(int(ident)+1))
    run(['python3','-B',project/'pilot/prepare_rehearsal_root.py',recovered])
    # Excluded TLS/relay/probe and proof are independently trusted synthetic fixtures.
    for name in ['root/backup-proof','var/lib/empire-vpn-acme']:
        shutil.copytree(source/name,recovered/name)
    for name in ['run/relay/config.json','etc/vpn-control/probe-lab.json','etc/vpn-control/lab-ca.pem']:
        dest=recovered/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/name,dest)
    for name in ['etc/empire-vpn','etc/empire-vpn/lab']:
        p=recovered/name;p.mkdir(parents=True,exist_ok=True);p.chmod(0o750);os.chown(p,0,982)
    for member in manifest['members']:
        name=member['path'].lstrip('/');dest=recovered/name
        if member.get('xattrs') or member['mode']&0o027 or member['uid'] not in (0,981) or member['gid'] not in (0,981,982):raise RuntimeError('fixture destination metadata policy mismatch')
        dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        data=candidate if name=='var/lib/vpn-control/state.db' else stage/name
        shutil.copyfile(data,dest);os.chown(dest,member['uid'],member['gid']);dest.chmod(member['mode'])
    restored=runtime(project,recovered,'w8-restored-'+ident)
    rollback=runtime(project,source,'w8-rollback-'+ident)
    if hashlib.sha256(cipher.read_bytes()).hexdigest()!=original_cipher:raise RuntimeError('source ciphertext changed')
    report=dict(outcome='restored_runtime_pass',backup_id=context['backup_id'],cipher_sha256=original_cipher,
                restored=restored.strip(),rollback=rollback.strip(),private_key_off_runtime=True,
                note='Synthetic local drill; aggregate resource and full-suite gates remain separate')
    private_write(WORK/'report.json',json.dumps(report,indent=2).encode())
    print(json.dumps(report))


if __name__=='__main__':main()
