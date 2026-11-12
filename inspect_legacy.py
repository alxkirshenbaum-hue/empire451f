"""Inspect a private offline snapshot of v0.3.6 metadata without modifying it."""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
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


def inspect_snapshot(directory):
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

    meta = document('manifest.json')
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
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    try:
        report = inspect_snapshot(args.snapshot)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        print('Invalid or incomplete legacy snapshot.', file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return int(report['review_required'])


if __name__ == '__main__':
    sys.exit(main())
