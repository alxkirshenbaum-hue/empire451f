"""Return a private rehearsal copy to installer ownership after user changes."""
import argparse
from contextlib import closing
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import uuid

from handoff_legacy import publish, require, open_lock
from inspect_legacy import registry_uri, unique_fields, auth_lines
from render import credentials


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    require(not path.is_symlink() and path.is_file())
    return path.read_bytes()


def restore(root, registry, run, key, vpnctl, key_version=1, config_dir=None, lock_fd=None):
    import fcntl
    require(str(uuid.UUID(run)) == run and root.is_dir() and not root.is_symlink()
            and root.stat().st_mode & 0o077 == 0)
    identity = root.stat()
    working = config_dir is not None
    if working:
        require(root == Path('/var/lib/empire-vpn')/root.name
                and config_dir == Path('/etc/empire-vpn')/root.name
                and root.resolve() == root and config_dir.resolve() == config_dir
                and config_dir.is_dir())
    auth_path = config_dir/'auth.caddy' if working else root/'auth.caddy'
    paths = {'auth.caddy':auth_path,'clients.json':root/'clients.json','manifest.json':root/'manifest.json'}
    ref = f'installation{ "" if working else "-copy"}:{identity.st_dev}:{identity.st_ino}'
    final_status = 'installer_returned' if working else 'copy_returned'
    fd=open_lock(Path('/run/lock/empire-vpn.lock') if working else root/'empire-vpn.lock',lock_fd)
    with os.fdopen(fd, 'r+b') as lock, closing(sqlite3.connect(registry_uri(registry), uri=True)) as db:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db.execute('PRAGMA synchronous=FULL')
        require(not any(os.path.lexists(root/n) for n in ('pending.json','user-rollback.json','panel-auth-pending.json')))
        row = db.execute('SELECT phase,status,report_ref FROM legacy_migration_runs WHERE id=?',(run,)).fetchone()
        require(row and row[2] == ref)
        manifest = root/'manifest.json'
        before = read(manifest)
        meta = json.loads(before, object_pairs_hook=unique_fields)
        if row[:2] == ('rolled_back',final_status):
            require(meta.get('returned_run_id') == run and 'panel_generation' not in meta)
            intent_path = root/'return-intent.json'
            if os.path.lexists(intent_path):
                intent = json.loads(read(intent_path))
                require(intent['run']==run and all(checksum(read(paths[n]))==intent['after'][n]
                        for n in ('clients.json','auth.caddy','manifest.json')))
                intent_path.unlink()
                sync_directory(root)
            return final_status
        require(row[:2] == (('verified_cutover','verified_cutover') if working else ('importing','copy_handed_off')))
        version = db.execute('PRAGMA data_version').fetchone()
        with tempfile.TemporaryDirectory(dir=registry.parent) as tmp:
            subprocess.run([str(vpnctl),'migration','reverse-export','--approved-plan',run,
                            '--staging-db',str(registry),'--vault-key-file',str(key),
                            '--key-version',str(key_version),'--output-dir',tmp],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            export = read(Path(tmp)/'clients.json')
        users = credentials(json.loads(export))['clients']
        auth = ''.join('basic_auth '+json.dumps(u['username'])+' '+json.dumps(u['password'])+'\n'
                       for u in users).encode()
        active = {u['username']:u['password'] for u in users}
        if working:
            require(meta['config']['id']==root.name and dict(auth_lines(read(auth_path)))==active)
            require(str(config_dir/'Caddyfile') in meta['files'])
            require(all(checksum(read(Path(path)))==digest for path,digest in meta['files'].items()))
        master = json.loads(read(root/'master_user.sfa.json'))
        outbound, = [o for o in master['outbounds'] if o['type']=='naive']
        require(outbound['username']=='master_user' and outbound['password']==active['master_user']
                and outbound['server']==meta['config']['domain'])
        auth_ref = '/etc/empire-vpn/'+meta['config']['id']+'/auth.caddy'
        intent_path = root/'return-intent.json'
        current = {'auth.caddy':checksum(read(auth_path)),
                   'clients.json':checksum(read(root/'clients.json')), 'manifest.json':checksum(before)}
        # The manifest is published last. Do not restore the obsolete installer
        # transaction pointer: its old rollback journal could revive revoked access.
        switched = meta.get('panel_run_id') == run and 'panel_generation' in meta
        if switched:
            require(auth_ref not in meta['files'] and 'transaction' not in meta)
            expected_auth = meta['panel_auth_hash']
            for field in ('panel_run_id','panel_generation','panel_previous_transaction','panel_auth_hash'):
                del meta[field]
            meta['files'][auth_ref] = checksum(auth)
            meta['returned_run_id'] = run
            final = json.dumps(meta,sort_keys=True).encode()
        else:
            require(os.path.lexists(intent_path) and meta.get('returned_run_id')==run)
            final = before
        target = {'clients.json':export,'auth.caddy':auth,'manifest.json':final}
        after = {name:checksum(data) for name,data in target.items()}
        with db:
            db.execute('BEGIN IMMEDIATE')
            require(db.execute('PRAGMA data_version').fetchone()==version)
            # No competing database writer may commit during publication.
            if os.path.lexists(intent_path):
                intent = json.loads(read(intent_path))
                require(intent['run']==run and intent['after']==after)
                require(all(current[n] in (intent['before'][n],after[n]) for n in target))
            else:
                require(switched and current['auth.caddy']==expected_auth)
                publish(intent_path,json.dumps(dict(run=run,before=current,after=after)).encode())
                sync_directory(root)
            for name,data in target.items():
                if current[name]!=after[name]:
                    publish(paths[name],data,preserve=True) if working else publish(paths[name],data)
                    sync_directory(paths[name].parent)
            db.execute("""UPDATE legacy_migration_runs SET phase='rolled_back',status=?,
                          finished_at=CURRENT_TIMESTAMP WHERE id=?""",(final_status,run))
        intent_path.unlink()
        sync_directory(root)
        return final_status


def sync_directory(root):
    fd = os.open(root,os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--installation-copy',type=Path)
    source.add_argument('--installation',help='Working installation ID; requires approved maintenance window')
    p.add_argument('--staging-db',type=Path,required=True)
    p.add_argument('--approved-plan',required=True)
    p.add_argument('--vault-key-file',type=Path,required=True)
    p.add_argument('--key-version',type=int,default=1)
    p.add_argument('--lock-fd',type=int)
    p.add_argument('--vpnctl',type=Path,default=Path('/usr/local/bin/vpnctl'))
    args=p.parse_args()
    try:
        if args.installation:
            require(re.fullmatch('[a-z][a-z0-9]{2,9}',args.installation) is not None and os.geteuid()==0)
        root=Path('/var/lib/empire-vpn')/args.installation if args.installation else args.installation_copy
        config=Path('/etc/empire-vpn')/args.installation if args.installation else None
        result=restore(root,args.staging_db,args.approved_plan,args.vault_key_file,
                       args.vpnctl.resolve(),args.key_version,config,args.lock_fd)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,sqlite3.Error,subprocess.SubprocessError,ImportError):
        p.exit(1,'Return refused. Check the copy, registry and migration state.\n')
    print(json.dumps({'status':result,'run_id':args.approved_plan}))


if __name__=='__main__':
    main()
