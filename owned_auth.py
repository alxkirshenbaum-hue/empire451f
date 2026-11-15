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
import re
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


def prepare(state, auth, caddyfile, prepared_dir, operation, run, generation, login, password, previous=""):
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
    before_users = credentials(dict(format='empire-vpn-clients', schema_version=1,
                                    clients=[dict(username=n,password=p) for n,p in pairs]))['clients']
    active = dict(pairs)
    require(login != 'master_user')
    if previous:
        require(active.get(login) == previous)
    else:
        require(login not in active)
    changed = []
    for name, secret in pairs:
        if name == login:
            if password: changed.append(dict(username=name,password=password))
        else:
            changed.append(dict(username=name,password=secret))
    if not previous and password:
        changed.append(dict(username=login,password=password))
    users = credentials(dict(format='empire-vpn-clients',schema_version=1,clients=changed))['clients']
    require(users)  # Never publish an empty auth list.
    prepared = decode(read(prepared_dir/'prepared.json', True))
    require(prepared['operation'] == operation and prepared['generation'] == generation
            and auth_values(prepared['before']) == encoded_auth(before_users)
            and auth_values(prepared['candidate']) == encoded_auth(users))
    candidate = json.loads(json.dumps(prepared['candidate']))
    def restore_auth(value):
        if isinstance(value, dict):
            if value.get('handler') == 'forward_proxy':
                value['auth_credentials'] = encoded_auth(before_users)
            for child in value.values(): restore_auth(child)
        elif isinstance(value, list):
            for child in value: restore_auth(child)
    restore_auth(candidate)
    require(candidate == prepared['before'])
    replacement = ('basic_auth '+json.dumps(login)+' '+json.dumps(password)+'\n').encode()
    lines = []
    for line in original_auth.splitlines(keepends=True):
        parsed = list(auth_lines(line))
        if parsed and parsed[0][0] == login:
            if password: lines.append(replacement)
        else:
            lines.append(line)
    candidate_auth = b''.join(lines)
    if not previous and password:
        candidate_auth += (b'\n' if candidate_auth and not candidate_auth.endswith(b'\n') else b'') + replacement
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


def prepare_portable(state, auth, caddyfile, prepared_dir, operation, run, generation, registry, users, installation_hash):
    state,auth,caddyfile,prepared_dir,registry=map(location,(state,auth,caddyfile,prepared_dir,registry))
    require(state.is_dir() and state.stat().st_mode&0o077==0 and prepared_dir.stat().st_mode&0o077==0 and generation==1)
    with closing(sqlite3.connect(registry_uri(registry),uri=True)) as db:
        row=db.execute("SELECT o.request_hash FROM operations o JOIN legacy_migration_runs m ON m.id=o.target_id WHERE o.id=? AND o.kind='portable.import' AND o.status='running' AND m.id=? AND m.phase='importing' AND m.status='portable_staged'",(operation,run)).fetchone()
        require(row is not None)
        actual=db.execute("SELECT login FROM users WHERE status='active' ORDER BY login COLLATE BINARY").fetchall()
        require([x[0] for x in actual]==sorted(u['username'] for u in users))
    require(re.fullmatch('[0-9a-f]{64}',installation_hash) is not None)
    journal=state/'panel-auth-pending.json';require(not os.path.lexists(journal))
    require(not any(os.path.lexists(state/n) for n in ('pending.json','user-rollback.json','return-intent.json')))
    before_auth,before_manifest=read(auth),read(state/'manifest.json',True)
    meta=decode(before_manifest);require('transaction' in meta and not any(k.startswith('panel_') for k in meta))
    require(meta['files'].get(str(auth))==digest(before_auth) and meta['files'].get(str(caddyfile))==digest(read(caddyfile)))
    users=credentials(dict(format='empire-vpn-clients',schema_version=1,clients=users))['clients']
    prepared=decode(read(prepared_dir/'prepared.json',True))
    before_users=[dict(username=n,password=p) for n,p in auth_lines(before_auth)]
    require(prepared['operation']==operation and prepared['generation']==generation and auth_values(prepared['before'])==encoded_auth(before_users) and auth_values(prepared['candidate'])==encoded_auth(users))
    candidate=json.loads(json.dumps(prepared['candidate']))
    def restore(v):
        if isinstance(v,dict):
            if v.get('handler')=='forward_proxy':v['auth_credentials']=encoded_auth(before_users)
            for child in v.values():restore(child)
        elif isinstance(v,list):
            for child in v:restore(child)
    restore(candidate);require(candidate==prepared['before'])
    after_auth=b''.join(('basic_auth '+json.dumps(u['username'])+' '+json.dumps(u['password'])+'\n').encode() for u in users)
    meta.update(panel_generation=1,panel_run_id=run,panel_auth_hash=digest(after_auth),panel_previous_transaction=meta.pop('transaction'));meta['files'].pop(str(auth))
    targets=[]
    for path,before,after in ((auth,before_auth,after_auth),(state/'manifest.json',before_manifest,json.dumps(meta,sort_keys=True).encode())):
        i=path.stat();targets.append(dict(path=str(path),before=base64.b64encode(before).decode(),after=base64.b64encode(after).decode(),mode=i.st_mode&0o777,uid=i.st_uid,gid=i.st_gid,xattrs=attributes(path)))
    intent=dict(operation=operation,run=run,generation=generation,state_identity=identity(state),auth_parent_identity=identity(auth.parent),prepared=str(prepared_dir/'prepared.json'),prepared_hash=digest(read(prepared_dir/'prepared.json',True)),caddyfile=str(caddyfile),caddyfile_hash=digest(read(caddyfile)),targets=targets,portable_digest=row[0],installation_hash=installation_hash)
    publish(journal,json.dumps(intent,sort_keys=True).encode());sync_directory(state)

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
        if 'portable_digest' in intent:
            row=db.execute("SELECT o.status,o.request_hash,m.phase,m.status FROM operations o JOIN legacy_migration_runs m ON m.id=o.target_id WHERE o.id=? AND o.kind='portable.import' AND m.id=?",(operation,run)).fetchone()
            require(not rollback and row==('succeeded',intent['portable_digest'],'verified_cutover','verified_cutover'))
            require(all(read(Path(t['path']))==base64.b64decode(t['after'],validate=True) for t in intent['targets']))
            (state/'panel-auth-pending.json').unlink();sync_directory(state);return
        row = db.execute("""SELECT o.status,u.status,o.kind FROM operations o JOIN users u ON u.id=o.target_id
            WHERE o.id=? AND o.target_type='user'""",(operation,)).fetchone()
        require(row is not None)
        expected = 'active'
        if row[2] != 'user.create':
            require(row[2] in ('user.disable','user.enable','user.delete','credential.rotate'))
            mutation = db.execute("SELECT after_status FROM user_mutations WHERE operation_id=? AND owner_run=?",
                                  (operation,run)).fetchone()
            require(mutation is not None)
            expected = mutation[0]
        require(row[:2] == ('succeeded',expected) if not rollback else row[0] == 'rolled_back')
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
        require(action in ('prepare','prepare_portable','inspect','publish_files','finish'))
        globals()[action](**req)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,sqlite3.Error):
        print('Owned auth operation refused; inspect protected journals.',file=sys.stderr)
        return 1
    print('{"status":"ok"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
