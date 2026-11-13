"""Transfer writer ownership on a private Linux rehearsal copy."""
import argparse
from contextlib import closing
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import uuid

from inspect_legacy import inspect_sources, registry_uri


def require(condition):
    if not condition:
        raise ValueError('Handoff precondition failed')


def open_lock(path, inherited=None, create=False):
    if inherited is not None:
        expected=path.stat(follow_symlinks=False);actual=os.fstat(inherited)
        require(stat.S_ISREG(expected.st_mode) and (expected.st_dev,expected.st_ino)==(actual.st_dev,actual.st_ino))
        return os.dup(inherited)
    descriptor=os.open(path,os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT if create else 0),0o600)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor);raise ValueError('Invalid installation lock')
    return descriptor


def publish(path, data, preserve=False):
    # Runtime auth is group-readable by Caddy; migration copies remain 0600.
    metadata = path.lstat() if preserve else None
    if metadata is not None:
        require(not path.is_symlink() and path.is_file())
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            if metadata is not None:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), metadata.st_mode & 0o777)
                for attribute in os.listxattr(path):
                    os.setxattr(stream.fileno(), attribute, os.getxattr(path, attribute))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def verify_stage(db, run, generation, actions, allow_reconcile=False):
    row = db.execute("""SELECT d.body,r.source_hashes,r.status,r.report_ref FROM legacy_migration_runs r
        JOIN legacy_migration_documents d ON d.run_id=r.id AND d.kind='plan'
        JOIN operations o ON o.target_id=r.id AND o.kind='legacy.stage' AND o.status='succeeded'
        WHERE r.id=? AND r.phase IN ('importing',?) AND r.approved_at IS NOT NULL AND o.request_hash=?""",
        (run, 'reconcile_required' if allow_reconcile else 'importing', generation)).fetchone()
    require(row is not None)
    plan = json.loads(row[0])
    require(plan['run_id'] == run and plan['snapshot_sha256'] == generation and
            json.loads(row[1]) == {'snapshot_sha256': generation} and plan['users'] == actions)
    expected = [(a['login'], a['kind'], a['protected']) for a in actions]
    actual = db.execute("""SELECT u.login,u.kind,u.protected FROM users u
        JOIN legacy_migration_items m ON m.imported_user_id=u.id AND m.login_exact=u.login
        JOIN user_current_credentials a ON a.user_id=u.id
        JOIN credentials c ON c.id=a.credential_id AND c.user_id=u.id
        WHERE m.run_id=? AND c.revoked_at IS NULL AND u.row_version=1
        AND u.source='legacy_import' AND u.status='provisioning' ORDER BY u.login""", (run,)).fetchall()
    require(actual == expected and db.execute('SELECT count(*) FROM users').fetchone()[0] == len(actual))
    return row[2], row[3]


def check_copy(root, hashes):
    expected = {name for name in hashes if name.startswith('vpn-') and name.endswith('.json')}
    require(expected == {p.name for p in root.glob('vpn-*.json')})
    for name in ('pending.json', 'user-rollback.json'):
        require(not os.path.lexists(root / name))
    for name, digest in hashes.items():
        p = root / name
        require(not p.is_symlink() and p.is_file())
        if name != 'manifest.json':
            require(hashlib.sha256(p.read_bytes()).hexdigest() == digest)


def handoff(snapshot, root, registry, run, rollback=False, config_dir=None, socket=None, wrapper_hash=None, reconcile=False, lock_fd=None):
    import fcntl
    require(str(uuid.UUID(run)) == run and root.is_dir() and not root.is_symlink()
            and root.stat().st_mode & 0o077 == 0 and not snapshot.samefile(root))
    report, actions, hashes, original = inspect_sources(snapshot)
    require(not report['review_required'])
    meta = json.loads(original)
    require('transaction' in meta and not any(k.startswith('panel_') for k in meta))
    auth = '/etc/empire-vpn/' + meta['config']['id'] + '/auth.caddy'
    require(meta['files'].get(auth) == hashes['auth.caddy'])
    working = config_dir is not None
    if working:
        require(os.geteuid()==0 and root==Path('/var/lib/empire-vpn')/meta['config']['id']
                and config_dir==Path('/etc/empire-vpn')/meta['config']['id']
                and root.resolve()==root and config_dir.resolve()==config_dir
                and isinstance(socket,str) and socket.startswith('/') and '\n' not in socket
                and re.fullmatch('[0-9a-f]{64}',wrapper_hash or '') is not None)
        source_caddy=(snapshot/'Caddyfile').read_bytes()
        caddy_ref=str(config_dir/'Caddyfile')
        require(hashlib.sha256(source_caddy).hexdigest()==meta['files'].get(caddy_ref))
        patched,count=re.subn(rb'(?m)^([ \t]*)admin[ \t]+off[ \t]*$',
                             lambda m:m[1]+b'admin unix/'+socket.encode(),source_caddy)
        require(count==1 and (config_dir/'Caddyfile').read_bytes()==patched)
        meta['files'][caddy_ref]=hashlib.sha256(patched).hexdigest()
        meta['files']['/usr/local/bin/vpn-add-user']=wrapper_hash
    meta.update(panel_generation=1, panel_run_id=run, panel_auth_hash=meta['files'].pop(auth),
                panel_previous_transaction=meta.pop('transaction'))
    switched = json.dumps(meta, sort_keys=True).encode()
    manifest = root / 'manifest.json'
    identity = root.stat()
    copy_ref = f'installation{"" if working else "-copy"}:{identity.st_dev}:{identity.st_ino}'
    def check():
        if not working:
            check_copy(root,hashes)
            return
        require(not any(os.path.lexists(root/name) for name in ('pending.json','user-rollback.json','return-intent.json','panel-auth-pending.json')))
        require({p.name for p in root.glob('vpn-*.json')}=={name for name in hashes if name.startswith('vpn-') and name.endswith('.json')})
        for name,expected in hashes.items():
            path=config_dir/name if name=='auth.caddy' else root/name
            require(path.is_file() and not path.is_symlink())
            if name!='manifest.json':require(hashlib.sha256(path.read_bytes()).hexdigest()==expected)
        for path,expected in meta['files'].items():
            source=Path(path)
            require(source.is_file() and not source.is_symlink() and hashlib.sha256(source.read_bytes()).hexdigest()==expected)
    # All writers in the rehearsal share this copy's lock.
    lock_path=Path('/run/lock/empire-vpn.lock') if working else root/'empire-vpn.lock'
    fd=open_lock(lock_path,lock_fd,create=True)
    with os.fdopen(fd, 'r+b') as lock, closing(sqlite3.connect(registry_uri(registry), uri=True)) as db:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        intent = 'rollback_pending' if rollback else 'handoff_pending'
        final = 'handoff_rolled_back' if rollback else ('working_handed_off' if working else 'copy_handed_off')
        target = original if rollback else switched
        with db:
            db.execute('BEGIN IMMEDIATE')
            status, bound_copy = verify_stage(db, run, report['snapshot_sha256'], actions,working and reconcile)
            require(bound_copy == copy_ref or (status == 'staged' and bound_copy is None))
            check()
            current = manifest.read_bytes()
            require(current in (original, switched))
            if status == final:
                require(current == target)
                return final
            if rollback:
                require(status in ('copy_handed_off','working_handed_off', 'handoff_pending', intent)
                        or working and reconcile and status=='reconcile_required')
                if status in ('copy_handed_off','working_handed_off'):
                    require(current == switched)
            else:
                require(status in ('staged', intent) or working and reconcile and status=='reconcile_required')
                if status == 'staged':
                    require(current == original)
            db.execute("UPDATE legacy_migration_runs SET phase='importing',status=?,report_ref=? WHERE id=?", (intent, copy_ref, run))
        with db:
            db.execute('BEGIN IMMEDIATE')
            require(verify_stage(db, run, report['snapshot_sha256'], actions) == (intent, copy_ref))
            check()
            current = manifest.read_bytes()
            require(current in (original, switched))
            if current != target:
                publish(manifest, target,preserve=True) if working else publish(manifest,target)
            directory = os.open(root, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            db.execute('UPDATE legacy_migration_runs SET status=? WHERE id=?', (final, run))
        return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--installation-copy', type=Path)
    source.add_argument('--installation')
    parser.add_argument('--admin-socket')
    parser.add_argument('--wrapper-sha256')
    parser.add_argument('--reconcile',action='store_true')
    parser.add_argument('--lock-fd',type=int)
    parser.add_argument('--staging-db', type=Path, required=True)
    parser.add_argument('--approved-plan', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        if args.installation:require(re.fullmatch('[a-z][a-z0-9]{2,9}',args.installation) is not None)
        root=Path('/var/lib/empire-vpn')/args.installation if args.installation else args.installation_copy
        config=Path('/etc/empire-vpn')/args.installation if args.installation else None
        result = handoff(args.snapshot, root, args.staging_db,args.approved_plan,args.rollback,
                         config,args.admin_socket,args.wrapper_sha256,args.reconcile,args.lock_fd)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError, AttributeError, ImportError):
        print('Handoff refused. Check the staged plan, snapshot and copy.', file=sys.stderr)
        return 1
    print(json.dumps({'run_id': args.approved_plan, 'status': result}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
