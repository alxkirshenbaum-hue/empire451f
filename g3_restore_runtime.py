"""Restore installer runtime files after journaled writer return, under its lock.

Does not stop/start services or change units/accounts. The approved window does
that while holding the same inherited lock. Never restores obsolete auth/users.
"""
import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid
from handoff_legacy import open_lock, publish, require
from inspect_legacy import registry_uri, auth_lines
from return_legacy import read, sync_directory


def restore(installation, snapshot, run, uid, gid, admin_socket, lock_fd=None):
    require(os.geteuid()==0 and re.fullmatch('[a-z][a-z0-9]{2,9}',installation)
            and str(uuid.UUID(run))==run and uid>0 and gid>0
            and admin_socket.startswith('/') and '\n' not in admin_socket)
    state=Path('/var/lib/empire-vpn')/installation
    base=Path('/etc/empire-vpn')/installation
    require(state.resolve()==state and base.resolve()==base and snapshot.resolve()==snapshot
            and snapshot.is_dir() and snapshot.stat().st_mode&0o077==0)
    with os.fdopen(open_lock(Path('/run/lock/empire-vpn.lock'),lock_fd),'r+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        require(not any(os.path.lexists(state/n) for n in ('pending.json','user-rollback.json','return-intent.json','panel-auth-pending.json')))
        identity=state.stat();ref=f'installation:{identity.st_dev}:{identity.st_ino}'
        with closing(sqlite3.connect(registry_uri(Path('/var/lib/vpn-control/state.db')),uri=True)) as db:
            row=db.execute('SELECT phase,status,report_ref FROM legacy_migration_runs WHERE id=?',(run,)).fetchone()
            require(row is not None and (row==('rolled_back','installer_returned',ref)
                    or row==('importing','handoff_rolled_back',ref)))
            require(db.execute("SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back')").fetchone()[0]==0)
        manifest=state/'manifest.json';meta=json.loads(read(manifest))
        require(meta['config']['id']==installation and 'panel_generation' not in meta)
        source=read(snapshot/'Caddyfile');original=json.loads(read(snapshot/'manifest.json'))
        digest=lambda data:hashlib.sha256(data).hexdigest()
        require(digest(source)==original['files'][str(base/'Caddyfile')])
        current=read(base/'Caddyfile')
        # Only the reviewed admin-off -> Unix-socket change is reversible here.
        candidate,count=re.subn(rb'(?m)^([ \t]*)admin[ \t]+off[ \t]*$',
                lambda match:match[1]+b'admin unix/'+admin_socket.encode(),source)
        require(count==1 and current in (source,candidate))
        require(meta['files'][str(base/'Caddyfile')] in (digest(candidate),digest(source)))
        auth=read(base/'auth.caddy');users=json.loads(read(state/'clients.json'))['clients']
        require(dict(auth_lines(auth))=={u['username']:u['password'] for u in users}
                and meta['files'][str(base/'auth.caddy')]==digest(auth))
        for path,expected in meta['files'].items():
            if path in (str(base/'Caddyfile'),'/usr/local/bin/vpn-add-user'):continue
            require(digest(read(Path(path)))==expected)
        acme=Path('/var/lib/empire-vpn-acme')
        paths=[acme,*acme.rglob('*')]
        require(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in paths))
        # Idempotent after interruption: Caddyfile can be either known image;
        # auth/export/profiles are never replaced from the pre-change snapshot.
        if current!=source:publish(base/'Caddyfile',source,preserve=True)
        for path in (base/'Caddyfile',base/'auth.caddy'):os.chown(path,0,gid)
        for path in paths:os.chown(path,uid,gid)
        meta['files'][str(base/'Caddyfile')]=digest(source)
        meta['files']['/usr/local/bin/vpn-add-user']=digest(read(Path('/usr/local/bin/vpn-add-user')))
        publish(manifest,json.dumps(meta,sort_keys=True).encode(),preserve=True)
        sync_directory(base);sync_directory(state)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--installation',required=True)
    p.add_argument('--snapshot',type=Path,required=True)
    p.add_argument('--approved-plan',required=True)
    p.add_argument('--legacy-uid',type=int,required=True)
    p.add_argument('--legacy-gid',type=int,required=True)
    p.add_argument('--admin-socket',required=True)
    p.add_argument('--lock-fd',type=int)
    args=p.parse_args()
    try:restore(args.installation,args.snapshot,args.approved_plan,args.legacy_uid,args.legacy_gid,args.admin_socket,args.lock_fd)
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        p.exit(1,'Runtime restore refused; preserve files and reconcile through SSH.\n')
    print('Installer runtime files restored; restart and access verification still required.')


if __name__=='__main__':main()
