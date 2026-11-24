"""One host-side W8U export/clean-import proof; synthetic/local only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def run(args,**kw):
    p=subprocess.run([str(a) for a in args],capture_output=True,timeout=600,**kw)
    if p.returncode:
        (WORK/'last-failure.log').write_bytes(p.stdout+p.stderr)
        raise RuntimeError('portable drill subprocess failed: '+Path(str(args[0])).name)
    return p.stdout


def execute_root(project,root,unit):
    args=['systemd-run','--quiet','--wait','--pipe','--unit='+unit]
    for prop in ['RootDirectory='+str(root),'MountAPIVFS=yes','PrivateNetwork=yes','PrivateDevices=yes','NoNewPrivileges=yes','ProtectSystem=strict',
                 'ReadWritePaths=+/etc','ReadWritePaths=+/var/lib','ReadWritePaths=+/run','ReadWritePaths=+/tmp','ReadWritePaths=+/root',
                 'BindReadOnlyPaths=/usr','BindReadOnlyPaths='+str(project/'rehearsal-source/local')+':/usr/local','BindReadOnlyPaths=/opt/empire-vpn/bin','BindReadOnlyPaths=/etc/ssl','BindReadOnlyPaths='+str(project/'rehearsal-source')+':/work','WorkingDirectory=/work']:
        args+=['-p',prop]
    return run(args+['/usr/bin/python3','-B','/work/pilot/portable_import_rehearsal.py'])


def main():
    global WORK
    f=argparse.ArgumentParser();f.add_argument('--project',required=True,type=Path);f.add_argument('--run-id',required=True);f.add_argument('--resume-source',action='store_true');f.add_argument('--destination-id')
    a=f.parse_args();project=a.project.resolve();ident=a.run_id
    if os.geteuid()!=0 or not ident.isdigit():raise RuntimeError('root/numeric unique run required')
    os.umask(0o077);WORK=project/('portable-drill-'+ident)
    if not a.resume_source:WORK.mkdir(mode=0o700)
    elif not WORK.is_dir() or WORK.is_symlink() or WORK.stat().st_mode&0o077:raise RuntimeError('preserved private source work required')
    if shutil.disk_usage(project).free<100_000_000:raise RuntimeError('insufficient free space for bounded portable operation')
    private=WORK/'owner-private.pem';public=WORK/'recipient.pem'
    if not a.resume_source:
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        env=dict(os.environ,VPN_REHEARSAL_PROJECT=str(project),VPN_REHEARSAL_BACKUP='1',VPN_REHEARSAL_PORTABLE='1',VPN_REHEARSAL_BACKUP_PUBLIC=str(public))
        run(['sh',project/'pilot/run_full_worker_rehearsal.sh','normal',ident],env=env)
    source=project/('rehearsal-root-'+ident)
    status=run(['systemctl','show','vpn-full-worker-root-'+ident,'-p','MainPID','-p','Result']).decode()
    if 'MainPID=0' not in status or 'Result=success' not in status:raise RuntimeError('source not completed')
    proof=source/'root/backup-proof';context=json.loads((proof/'context.json').read_bytes());cipher=source/context['downloaded_path'].lstrip('/')
    digest=hashlib.sha256(cipher.read_bytes()).hexdigest()
    if digest!=context['sha256']:raise RuntimeError('owner download changed')
    destination=a.destination_id or str(int(ident)+1);recovery=WORK/('receiver-'+destination);recovery.mkdir(mode=0o700)
    cli=project/'rehearsal-bin/vpnctl';helper=project/'backup_artifact.py';stage=recovery/'verified'
    def verify_args(envelope,key,staging):return [cli,'backup','offline-verify','--envelope',envelope,'--private-key',key,'--cipher-sha256',digest,'--manifest-sha256',context['manifest_sha256'],'--owner-run',context['owner_run'],'--own-operation',context['own_operation'],'--staging',staging,'--helper',helper,'--source-panel-root','/var/lib/vpn-control','--source-state-root','/var/lib/empire-vpn/lab','--source-config-root','/etc/empire-vpn','--source-wrapper','/usr/local/bin/vpn-add-user','--source-wrapper-sha256',hashlib.sha256((project/'rehearsal-source/local/bin/vpn-add-user').read_bytes()).hexdigest()]
    wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048);wrongfile=recovery/'wrong-key.pem';wrongfile.write_bytes(wrong.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    corrupted=recovery/'corrupt.jwe';raw=bytearray(cipher.read_bytes());raw[len(raw)//2]^=1;corrupted.write_bytes(raw)
    for envelope,key,name in [(cipher,wrongfile,'wrong'),(corrupted,private,'corrupt')]:
        rejected=recovery/name;p=subprocess.run([str(x) for x in verify_args(envelope,key,rejected)],capture_output=True,timeout=90)
        if p.returncode==0 or rejected.exists():raise RuntimeError('invalid encrypted input accepted/published')
    run(verify_args(cipher,private,stage))
    root=project/('rehearsal-root-'+destination);run(['python3','-B',project/'pilot/prepare_rehearsal_root.py',root])
    inputs=root/'root/portable-input';inputs.mkdir(parents=True,mode=0o700);(root/'root').chmod(0o700)
    for name in ('portable-expected.json','old-profile.json','relay.json'):shutil.copy2(proof/name,inputs/name)
    # Only portable account snapshot/key enter private staging. Never source owner
    # account DB as destination, and never recipient RSA private key in runtime.
    shutil.copy2(stage/'var/lib/vpn-control/state.db',inputs/'source.db');shutil.copy2(stage/'var/lib/vpn-control/vault.key',inputs/'source.key')
    context['destination_run']=str(uuid.uuid4());(inputs/'context.json').write_text(json.dumps(context))
    shutil.copytree(source/'var/lib/empire-vpn-acme',root/'var/lib/empire-vpn-acme')
    for p in [root/'var/lib/empire-vpn-acme',*(root/'var/lib/empire-vpn-acme').rglob('*')]:os.chown(p,982,982)
    cert=root/'etc/vpn-control/lab-ca.pem';cert.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/'etc/vpn-control/lab-ca.pem',cert)
    output=execute_root(project,root,'w8u-portable-'+destination)
    if b'old TCP-UoT disabled rejection PASS' not in output:raise RuntimeError('portable runtime proof missing')
    if hashlib.sha256(cipher.read_bytes()).hexdigest()!=digest:raise RuntimeError('source export changed')
    report=dict(outcome='W8U_PORTABLE_PASS',source_run=ident,destination_run=destination,cipher_sha256=digest,wrong_key_rejected=True,corrupt_rejected=True,private_key_off_runtime=True,runtime=output.decode().strip(),free_disk_bytes=shutil.disk_usage(project).free)
    (recovery/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
