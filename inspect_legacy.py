"""Inspect a private offline snapshot of v0.3.6 metadata without modifying it."""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from collections import Counter
from contextlib import closing
from pathlib import Path

from render import credentials

def auth_lines(data):
    # Managed v0.3.6 format: the installer serializes each token as a JSON string.
    decoder = json.JSONDecoder()
    for line in data.decode().splitlines():
        if not line.strip():
            continue
        directive, sep, tokens = line.strip().partition(' ')
        if directive != 'basic_auth' or not sep:
            raise ValueError('Unknown authentication directive')
        name, end = decoder.raw_decode(tokens.lstrip())
        tail = tokens.lstrip()[end:]
        if not tail.startswith((' ', '\t')):
            raise ValueError('Missing token separator')
        password = json.loads(tail)
        if not isinstance(name, str) or not isinstance(password, str):
            raise ValueError('Invalid credential fields')
        yield name, password


def inspect(auth, export, digest, profiles):
    rows = list(auth_lines(auth))
    checked = credentials(export)['clients']
    active = dict(rows)
    saved = {u['username']: u['password'] for u in checked}
    names = set(active) | set(saved)
    collisions = Counter(name.lower() for name in names)
    return {
        'manifest_matches': hashlib.sha256(auth).hexdigest() == digest,
        'duplicate_auth_names': len(rows) - len(active),
        'case_collision_groups': sum(count > 1 for count in collisions.values()),
        'caddy_only': len(active.keys() - saved.keys()),
        'export_only': len(saved.keys() - active.keys()),
        'password_conflicts': sum(active[n] != saved[n] for n in active.keys() & saved.keys()),
        'master_in_both': 'master_user' in active and 'master_user' in saved,
        'unmatched_profiles': sum(n not in active or active[n] != p for n, p in profiles),
    }


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def inspect_sources(directory):
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('Invalid snapshot directory')
    if any((directory / name).exists() or (directory / name).is_symlink()
           for name in ('pending.json', 'user-rollback.json')):
        raise ValueError('Unfinished installer transaction')

    hashes = {}

    def read(name):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected regular snapshot file')
        data = path.read_bytes()
        hashes[name] = hashlib.sha256(data).hexdigest()
        return data

    def document(name):
        value = json.loads(read(name), object_pairs_hook=unique_fields)
        if not isinstance(value, dict):
            raise ValueError('Invalid snapshot document')
        return value

    manifest = read('manifest.json')
    meta = json.loads(manifest, object_pairs_hook=unique_fields)
    ident = meta['config']['id']
    if not re.fullmatch(r'[a-z][a-z0-9]{2,9}', ident):
        raise ValueError('Invalid installation ID')
    digest = meta['files'].get(f'/etc/empire-vpn/{ident}/auth.caddy')
    auth = read('auth.caddy')
    export = document('clients.json')
    profiles = []
    binding_errors = 0
    personal = sorted(p.name for p in directory.iterdir()
                      if p.name.startswith('vpn-') and p.name.endswith('.json'))
    for name in ['master_user.sfa.json', *personal]:
        expected = 'master_user' if name == 'master_user.sfa.json' else name[4:-5]
        outbound, = [o for o in document(name)['outbounds'] if o['type'] == 'naive']
        login, password = outbound['username'], outbound['password']
        if not isinstance(login, str) or not isinstance(password, str):
            raise ValueError('Invalid profile binding')
        binding_errors += login != expected or outbound['server'] != meta['config']['domain']
        profiles.append((login, password))

    result = inspect(auth, export, digest, profiles)
    result['profile_binding_conflicts'] = binding_errors
    result['profiles_checked'] = len(profiles)
    result['snapshot_sha256'] = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    findings = ('duplicate_auth_names', 'case_collision_groups', 'caddy_only',
                'export_only', 'password_conflicts', 'unmatched_profiles',
                'profile_binding_conflicts')
    result['review_required'] = (not result['manifest_matches'] or not result['master_in_both']
                                 or any(result[key] for key in findings))
    actions = []
    if not result['review_required']:
        for client in sorted(export['clients'], key=lambda row: row['username']):
            login = client['username']
            actions.append({'login': login, 'kind': 'service' if login == 'master_user' else 'regular',
                            'protected': login == 'master_user',
                            'legacy_accepted': not bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}', login)),
                            'action': 'stage_existing_credential'})
    return result, actions, hashes, manifest


def inspect_inputs(directory):
    report, actions, _, _ = inspect_sources(directory)
    return report, actions


def inspect_snapshot(directory):
    return inspect_inputs(directory)[0]


def registry_uri(registry):
    if not registry.is_file() or registry.is_symlink() or registry.parent.is_symlink():
        raise ValueError('Invalid registry')
    if os.name == 'posix' and (registry.stat().st_mode | registry.parent.stat().st_mode) & 0o077:
        raise ValueError('Expected private registry')
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = registry.with_name(registry.name + suffix)
        if sidecar.is_symlink() or (sidecar.exists() and (not sidecar.is_file() or
                (os.name == 'posix' and sidecar.stat().st_mode & 0o077))):
            raise ValueError('Invalid registry sidecar')
    return registry.resolve().as_uri() + '?mode=rw'


def record_snapshot(directory, registry, run_id):
    with closing(sqlite3.connect(registry_uri(registry), uri=True)) as db, db:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT max(version) FROM schema_migrations').fetchone() not in ((3,), (4,)):
            raise ValueError('Unsupported registry schema')
        report, actions = inspect_inputs(directory)
        generation = report['snapshot_sha256']
        source = json.dumps({'snapshot_sha256': generation}, sort_keys=True)
        if run_id is None:
            run_id = str(uuid.uuid4())
            status = 'review_required' if report['review_required'] else 'clean'
            db.execute("""INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status)
                          VALUES(?,'inspect',?,CURRENT_TIMESTAMP,?)""", (run_id, source, status))
            db.execute("INSERT INTO legacy_migration_documents VALUES(?,'inspection',?)",
                       (run_id, json.dumps(report, sort_keys=True)))
            return dict(report, run_id=run_id), int(report['review_required'])

        row = db.execute('SELECT phase,source_hashes,status FROM legacy_migration_runs WHERE id=?',
                         (run_id,)).fetchone()
        if not row:
            raise ValueError('Unknown run')
        phase, original, status = row
        if phase not in ('inspect', 'planned') or status == 'stale':
            return {'run_id': run_id, 'status': status, 'phase': phase}, 1
        if original != source:
            db.execute("""UPDATE legacy_migration_runs SET phase='reconcile_required',status='stale'
                          WHERE id=?""", (run_id,))
            return {'run_id': run_id, 'status': 'stale'}, 1
        if report['review_required'] or status == 'review_required':
            return {'run_id': run_id, 'status': 'review_required'}, 1
        if phase == 'planned':
            body, = db.execute("SELECT body FROM legacy_migration_documents WHERE run_id=? AND kind='plan'",
                               (run_id,)).fetchone()
            return json.loads(body), 0
        plan = {'run_id': run_id, 'snapshot_sha256': generation, 'phase': 'planned',
                'users': actions, 'caddy_action': 'preserve', 'profile_action': 'preserve',
                'rollback_before_cutover': 'discard_staging_keep_installer_writer'}
        db.execute("INSERT INTO legacy_migration_documents VALUES(?,'plan',?)",
                   (run_id, json.dumps(plan, sort_keys=True)))
        db.execute("UPDATE legacy_migration_runs SET phase='planned',status='planned' WHERE id=?", (run_id,))
        return plan, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--registry', type=Path, help='Record inspection in an existing panel registry')
    parser.add_argument('--plan', metavar='RUN_ID', help='Check snapshot and prepare or retrieve its plan')
    args = parser.parse_args()
    if args.plan is not None and args.registry is None:
        parser.error('--plan requires --registry')
    try:
        if args.registry is not None:
            report, code = record_snapshot(args.snapshot, args.registry, args.plan)
        else:
            report = inspect_snapshot(args.snapshot)
            code = int(report['review_required'])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, sqlite3.Error):
        print('Cannot inspect snapshot or access migration registry.', file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
