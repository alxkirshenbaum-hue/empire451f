"""Durable auth/manifest publication under the caller's installation lock.

Internal helper, not a cutover command. Never advances verified_cutover or
reloads Caddy. Caller must verify the exact live candidate before commit, or
verify the restored Caddy snapshot before rollback. Journals contain secrets.
"""
import base64
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

from handoff_legacy import publish, require
from inspect_legacy import auth_lines, unique_fields, registry_uri
from render import credentials
from return_legacy import sync_directory


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, private=False):
    info = path.lstat()
    require(path.is_file() and not path.is_symlink()
            and (not private or info.st_mode & 0o077 == 0))
    return path.read_bytes()


def decode(data):
    return json.loads(data, object_pairs_hook=unique_fields)


def auth_values(config):
    found = []
    def walk(value):
        if isinstance(value, dict):
            if value.get('handler') == 'forward_proxy':
                found.append(value.get('auth_credentials'))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(config)
    require(len(found) == 1 and isinstance(found[0], list) and found[0])
    return found[0]


def encoded_auth(users):
    return [base64.b64encode(base64.b64encode((u['username']+':'+u['password']).encode())).decode()
            for u in users]


def location(path):
    path = Path(path).absolute()
    # Reject symlink components, even if they point inside the same installation.
    require(path == path.resolve())
    return path


def identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def attributes(path):
    return {name:base64.b64encode(os.getxattr(path,name)).decode() for name in os.listxattr(path)}


def prepare(state, auth, caddyfile, prepared_dir, operation, run, generation, login, password):
    state, auth, caddyfile, prepared_dir = map(location, (state, auth, caddyfile, prepared_dir))
    require(state.is_dir() and state.stat().st_mode & 0o077 == 0
            and prepared_dir.is_dir() and prepared_dir.stat().st_mode & 0o077 == 0)
    manifest = state/'manifest.json'
    journal = state/'panel-auth-pending.json'
    require(not os.path.lexists(journal) and isinstance(generation, int) and generation >= 1
            and not any(os.path.lexists(state/n) for n in ('pending.json','user-rollback.json','return-intent.json')))
    original_auth, original_manifest = read(auth), read(manifest, True)
    meta = decode(original_manifest)
    require(meta['panel_run_id'] == run and meta['panel_generation'] == generation
            and meta['panel_auth_hash'] == digest(original_auth)
            and str(auth) not in meta['files'] and 'transaction' not in meta)
    # Validate file baseline, rather than silently dropping installer directives.
    require(meta['files'].get(str(caddyfile)) == digest(read(caddyfile)))
    pairs = list(auth_lines(original_auth))
    require(login not in {name for name, _ in pairs})
    users = credentials(dict(format='empire-vpn-clients', schema_version=1,
                             clients=[dict(username=n,password=p) for n,p in pairs]
                             + [dict(username=login,password=password)]))['clients']
    prepared = decode(read(prepared_dir/'prepared.json', True))
    require(prepared['operation'] == operation and prepared['generation'] == generation
            and auth_values(prepared['before']) == encoded_auth(users[:-1])
            and auth_values(prepared['candidate']) == encoded_auth(users))
    # Ensure candidate changes exactly one managed field, even for a damaged journal.
    candidate = json.loads(json.dumps(prepared['candidate']))
    def restore_auth(value):
        if isinstance(value, dict):
            if value.get('handler') == 'forward_proxy':
                value['auth_credentials'] = encoded_auth(users[:-1])
            for child in value.values(): restore_auth(child)
        elif isinstance(value, list):
            for child in value: restore_auth(child)
    restore_auth(candidate)
    require(candidate == prepared['before'])
    suffix = ('basic_auth '+json.dumps(login)+' '+json.dumps(password)+'\n').encode()
    candidate_auth = original_auth + (b'\n' if original_auth and not original_auth.endswith(b'\n') else b'') + suffix
    meta['panel_generation'] = generation + 1
    meta['panel_auth_hash'] = digest(candidate_auth)
    candidate_manifest = json.dumps(meta, sort_keys=True).encode()
    targets = []
    for path, before, after in ((auth,original_auth,candidate_auth), (manifest,original_manifest,candidate_manifest)):
        info = path.stat()
        targets.append(dict(path=str(path), before=base64.b64encode(before).decode(),
                            after=base64.b64encode(after).decode(),
                            mode=info.st_mode & 0o777, uid=info.st_uid, gid=info.st_gid, xattrs=attributes(path)))
    intent = dict(operation=operation, run=run, generation=generation,
                  state_identity=identity(state), auth_parent_identity=identity(auth.parent),
                  prepared=str(prepared_dir/'prepared.json'), prepared_hash=digest(read(prepared_dir/'prepared.json', True)),
                  caddyfile=str(caddyfile), caddyfile_hash=digest(read(caddyfile)), targets=targets)
    # Caller holds global flock: no competing helper may publish another intent.
    publish(journal,json.dumps(intent,sort_keys=True).encode())
    sync_directory(state)
    return intent


def inspect(state, operation, run, generation):
    state = location(state)
    require(state.is_dir() and state.stat().st_mode & 0o077 == 0)
    intent = decode(read(state/'panel-auth-pending.json', True))
    require(intent['operation'] == operation and intent['run'] == run and intent['generation'] == generation)
    require(intent['state_identity'] == identity(state))
    prepared = location(intent['prepared'])
    require(digest(read(prepared, True)) == intent['prepared_hash'])
    require(digest(read(location(intent['caddyfile']))) == intent['caddyfile_hash'])
    require(len(intent['targets']) == 2 and intent['targets'][1]['path'] == str(state/'manifest.json'))
    require(intent['auth_parent_identity'] == identity(Path(intent['targets'][0]['path']).parent))
    for target in intent['targets']:
        path = location(target['path'])
        info = path.stat()
        require((info.st_mode & 0o777,info.st_uid,info.st_gid) == (target['mode'],target['uid'],target['gid']))
        require(attributes(path) == target['xattrs'])
        before, after = (base64.b64decode(target[k],validate=True) for k in ('before','after'))
        require(read(path) in (before,after))
    return intent


def publish_files(state, operation, run, generation, rollback=False):
    """Idempotent file half of the saga; live Caddy proof belongs to the caller."""
    state = location(state)
    intent = inspect(state,operation,run,generation)
    for target in intent['targets']:
        # Recheck the complete pair before every replacement; never erase drift.
        inspect(state,operation,run,generation)
        path = Path(target['path'])
        data = base64.b64decode(target['before' if rollback else 'after'],validate=True)
        if read(path) != data:
            publish(path,data,preserve=True)
            sync_directory(path.parent)


def finish(state, operation, run, generation, registry, rollback=False):
    """Only after SQLite completion (or verified rollback) has been confirmed."""
    state = location(state)
    intent = inspect(state,operation,run,generation)
    with closing(sqlite3.connect(registry_uri(location(registry)),uri=True)) as db:
        row = db.execute("""SELECT o.status,u.status FROM operations o JOIN users u ON u.id=o.target_id
            WHERE o.id=? AND o.kind='user.create' AND o.target_type='user'""",(operation,)).fetchone()
        require(row == ('succeeded','active') if not rollback else row is not None and row[0] == 'rolled_back')
    require(all(read(Path(t['path'])) == base64.b64decode(t['before' if rollback else 'after'],validate=True)
                for t in intent['targets']))
    (state/'panel-auth-pending.json').unlink()
    sync_directory(state)


def main():
    # This helper is invoked by a root-owned worker, with secrets only on stdin.
    # No paths, commands or actions are accepted from the panel's HTTP client.
    try:
        req = decode(sys.stdin.buffer.read(4*1024*1024+1))
        action = req.pop('action')
        require(action in ('prepare','inspect','publish_files','finish'))
        globals()[action](**req)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,sqlite3.Error):
        print('Owned auth operation refused; inspect protected journals.',file=sys.stderr)
        return 1
    print('{"status":"ok"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
