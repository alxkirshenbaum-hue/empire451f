"""Transfer writer ownership on a private Linux rehearsal copy."""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import uuid

from inspect_legacy import inspect_sources, registry_uri


def require(condition):
    if not condition:
        raise ValueError('Handoff precondition failed')


def publish(path, data):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def verify_stage(db, run, generation, actions):
    row = db.execute("""SELECT d.body,r.source_hashes,r.status,r.report_ref FROM legacy_migration_runs r
        JOIN legacy_migration_documents d ON d.run_id=r.id AND d.kind='plan'
        JOIN operations o ON o.target_id=r.id AND o.kind='legacy.stage' AND o.status='succeeded'
        WHERE r.id=? AND r.phase='importing' AND r.approved_at IS NOT NULL AND o.request_hash=?""",
        (run, generation)).fetchone()
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


def handoff(snapshot, root, registry, run, rollback=False):
    import fcntl
    require(str(uuid.UUID(run)) == run and root.is_dir() and not root.is_symlink()
            and root.stat().st_mode & 0o077 == 0 and not snapshot.samefile(root))
    report, actions, hashes, original = inspect_sources(snapshot)
    require(not report['review_required'])
    meta = json.loads(original)
    require('transaction' in meta and not any(k.startswith('panel_') for k in meta))
    auth = '/etc/empire-vpn/' + meta['config']['id'] + '/auth.caddy'
    require(meta['files'].get(auth) == hashes['auth.caddy'])
    meta.update(panel_generation=1, panel_run_id=run, panel_auth_hash=meta['files'].pop(auth),
                panel_previous_transaction=meta.pop('transaction'))
    switched = json.dumps(meta, sort_keys=True).encode()
    manifest = root / 'manifest.json'
    identity = root.stat()
    copy_ref = f'installation-copy:{identity.st_dev}:{identity.st_ino}'
    # All writers in the rehearsal share this copy's lock.
    fd = os.open(root / 'empire-vpn.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as lock, closing(sqlite3.connect(registry_uri(registry), uri=True)) as db:
        fcntl.flock(lock, fcntl.LOCK_EX)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        intent = 'rollback_pending' if rollback else 'handoff_pending'
        final = 'handoff_rolled_back' if rollback else 'copy_handed_off'
        target = original if rollback else switched
        with db:
            db.execute('BEGIN IMMEDIATE')
            status, bound_copy = verify_stage(db, run, report['snapshot_sha256'], actions)
            require(bound_copy == copy_ref or (status == 'staged' and bound_copy is None))
            check_copy(root, hashes)
            current = manifest.read_bytes()
            require(current in (original, switched))
            if status == final:
                require(current == target)
                return final
            if rollback:
                require(status in ('copy_handed_off', 'handoff_pending', intent))
                if status == 'copy_handed_off':
                    require(current == switched)
            else:
                require(status in ('staged', intent))
                if status == 'staged':
                    require(current == original)
            db.execute('UPDATE legacy_migration_runs SET status=?,report_ref=? WHERE id=?', (intent, copy_ref, run))
        with db:
            db.execute('BEGIN IMMEDIATE')
            require(verify_stage(db, run, report['snapshot_sha256'], actions) == (intent, copy_ref))
            check_copy(root, hashes)
            current = manifest.read_bytes()
            require(current in (original, switched))
            if current != target:
                publish(manifest, target)
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
    parser.add_argument('--installation-copy', type=Path, required=True)
    parser.add_argument('--staging-db', type=Path, required=True)
    parser.add_argument('--approved-plan', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    try:
        result = handoff(args.snapshot, args.installation_copy, args.staging_db,
                         args.approved_plan, args.rollback)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError, AttributeError, ImportError):
        print('Handoff refused. Check the staged plan, snapshot and copy.', file=sys.stderr)
        return 1
    print(json.dumps({'run_id': args.approved_plan, 'status': result}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
