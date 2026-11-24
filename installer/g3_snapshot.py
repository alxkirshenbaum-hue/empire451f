"""Bounded root-only rollback snapshot; no network or service changes.

Archive/flat import remain outside Git. SQLite uses its online backup API.
The owner encrypts the archive off-node using the existing recovery envelope.
"""
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import uuid
from handoff_legacy import open_lock

LIMIT=32*1024*1024


def require(value):
    if not value:raise ValueError('Snapshot precondition failed')


def checksum(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(installation,window,phase):
    require(os.geteuid()==0 and re.fullmatch('[a-z][a-z0-9]{2,9}',installation)
            and str(uuid.UUID(window))==window and phase in ('pre','post'))
    state=Path('/var/lib/empire-vpn')/installation;base=Path('/etc/empire-vpn')/installation
    require(state.is_dir() and state.resolve()==state and state.stat().st_mode&0o077==0)
    target=Path('/root/vpn-control-g3')/window/phase
    if target.exists():
        require(target.is_dir() and not target.is_symlink() and target.stat().st_mode&0o077==0)
        result=json.loads((target/'receipt.json').read_bytes())
        require((result['installation'],result['window'],result['phase'])==(installation,window,phase)
                and result['archive']==str(target/'snapshot.tar') and checksum(target/'snapshot.tar')==result['sha256'])
        return result
    target.mkdir(parents=True,mode=0o700)
    target.parent.chmod(0o700);target.parent.parent.chmod(0o700)
    stage=target/'files';stage.mkdir(mode=0o700)
    with os.fdopen(open_lock(Path('/run/lock/empire-vpn.lock')),'r+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        require(not any(os.path.lexists(state/n) for n in ('pending.json','user-rollback.json','return-intent.json','panel-auth-pending.json')))
        required=[base/'auth.caddy',base/'Caddyfile',state/'manifest.json',state/'clients.json',state/'master_user.sfa.json']+sorted(state.glob('vpn-*.json'))
        optional=[Path('/usr/local/bin/vpn-add-user'),Path('/etc/systemd/system')/('evpn-'+installation+'-caddy.service'),
                  Path('/etc/systemd/system')/('evpn-'+installation+'-caddy.service.d'),Path('/var/lib/empire-vpn-acme'),Path('/var/lib/vpn-control/vault.key')]
        require(all(p.is_file() and not p.is_symlink() for p in required))
        selected=required+[p for p in optional if p.exists()]
        def inventory():
            result={}
            def visit(path):
                info=path.lstat();require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
                attrs={name:hashlib.sha256(os.getxattr(path,name)).hexdigest() for name in os.listxattr(path)}
                result[str(path)]=[info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),checksum(path) if path.is_file() else None,attrs]
                if path.is_dir():
                    for child in sorted(path.iterdir()):visit(child)
            for path in selected:visit(path)
            return result
        before=inventory()
        require(sum(Path(p).stat().st_size for p,v in before.items() if v[3] is not None)<LIMIT)
        def copy_path(source):
            destination=stage/str(source).lstrip('/')
            if source.is_dir():
                destination.mkdir(parents=True,exist_ok=True)
                for child in sorted(source.iterdir()):copy_path(child)
                shutil.copystat(source,destination,follow_symlinks=False)
            else:
                destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,destination)
            info=source.stat();os.chown(destination,info.st_uid,info.st_gid);os.chmod(destination,stat.S_IMODE(info.st_mode))
        for path in selected:copy_path(path)
        db=Path('/var/lib/vpn-control/state.db')
        if db.exists():
            require(db.is_file() and not db.is_symlink())
            destination=stage/'var/lib/vpn-control/state.db';destination.parent.mkdir(parents=True,exist_ok=True)
            with closing(sqlite3.connect(db.as_uri()+'?mode=ro',uri=True)) as source,closing(sqlite3.connect(destination)) as backup:
                source.backup(backup)
                require(backup.execute('PRAGMA integrity_check').fetchone()==('ok',))
                backup.execute('PRAGMA journal_mode=DELETE')
            info=db.stat();os.chown(destination,info.st_uid,info.st_gid);os.chmod(destination,stat.S_IMODE(info.st_mode))
        require(inventory()==before)
        manifest=json.loads((state/'manifest.json').read_bytes())
        metadata=dict(format='vpn-control-g3-snapshot-v1',installation=installation,window=window,phase=phase,
                      generation=manifest.get('panel_generation',0),files=before,absent=[str(p) for p in optional if not p.exists()])
        (stage/'G3-SNAPSHOT.json').write_text(json.dumps(metadata,sort_keys=True))
        archive=target/'snapshot.tar'
        result=subprocess.run(['tar','--acls','--xattrs','--numeric-owner','-cpf',str(archive),'-C',str(stage),'.'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        require(result.returncode==0 and archive.stat().st_size<=LIMIT and inventory()==before)
        archive.chmod(0o600)
        # The canonical import consumes the same protected before-image.
        flat=target/'import';flat.mkdir(mode=0o700)
        for source in required:
            shutil.copyfile(stage/str(source).lstrip('/'),flat/source.name);(flat/source.name).chmod(0o600)
        result=dict(installation=installation,window=window,phase=phase,directory=str(target),archive=str(archive),sha256=checksum(archive),import_snapshot=str(flat),generation=metadata['generation'])
        receipt=target/'receipt.json';receipt.write_text(json.dumps(result,sort_keys=True));receipt.chmod(0o600)
        return result


def main():
    try:
        require(len(sys.argv)==4)
        print(json.dumps(snapshot(*sys.argv[1:]),sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error,subprocess.SubprocessError):
        print('Protected snapshot refused; no service changes were made.',file=sys.stderr);return 1
    return 0


if __name__=='__main__':sys.exit(main())
