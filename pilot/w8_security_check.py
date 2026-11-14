"""Pure synthetic surface-policy checker; never collects runtime evidence.

Use existing security_audit.audit for managed-node collection only through an
approved launcher. This module deliberately neither imports nor executes it.
Inputs contain metadata only; results never echo paths, values or exceptions.
"""
SURFACES = frozenset(('auth', 'clients', 'profiles', 'exports', 'db', 'wal',
                      'vault', 'snapshots', 'temp', 'backup', 'logs'))


def check_fixture(data):
    """Return fixed finding IDs. Empty results prove fixture policy only.

    Each surface requires owner UID, allowed UID, POSIX mode, regular-file and
    single-link assertions, a negative foreign-UID/proc-root access observation,
    and redaction observation. Windows ACL/runtime observations need staging.
    """
    findings = set()
    if not isinstance(data, dict):
        return ['INPUT']
    rows = data.get('surfaces')
    if not isinstance(rows, list):
        return ['SURFACES']
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            findings.add('SURFACE_SCHEMA')
            continue
        name = row.get('kind')
        if not isinstance(name, str) or name not in SURFACES or name in seen:
            findings.add('SURFACE_SCHEMA')
            continue
        seen.add(name)
        uid, allowed, mode = row.get('uid'), row.get('allowed_uid'), row.get('mode')
        if (type(uid) is not int or type(allowed) is not int or uid < 0 or
                allowed < 0 or uid != allowed or type(mode) is not int or
                mode < 0 or mode > 0o777 or mode & 0o077):
            findings.add('OWNER_MODE')
        if row.get('regular') is not True or row.get('single_link') is not True:
            findings.add('LINK_BOUNDARY')
        for field, code in [('foreign_uid_denied', 'FOREIGN_UID'),
                            ('proc_root_denied', 'PROC_ROOT'),
                            ('redacted', 'REDACTION')]:
            if row.get(field) is not True:
                findings.add(code)
    if seen != SURFACES:
        findings.add('SURFACES')
    for field, code in [('off_vds_key', 'KEY_CUSTODY'),
                        ('sentinel_decrypt', 'KEY_PAIRING'),
                        ('usable_restore', 'RESTORE'),
                        ('retention_verified', 'RETENTION'),
                        ('rotation_drill', 'KEY_ROTATION')]:
        if data.get(field) is not True:
            findings.add(code)
    for field, code in [('disk_peak_bytes', 'DISK'), ('aggregate_ram_peak_bytes', 'RAM')]:
        value = data.get(field)
        if type(value) is not int or not 0 <= value <= 500_000_000:
            findings.add(code)
    if data.get('resource_scope_complete') is not True:
        findings.add('RESOURCE_SCOPE')
    return sorted(findings)
# Root worker input is trusted installation layout, never an HTTP-supplied path.
# No content reads, subprocesses, sockets, service control or configuration writes.
import json
import os
import stat

SECRET_LAYOUT = {
    'auth': 'auth.caddy', 'clients': 'clients.json', 'manifest': 'manifest.json',
    'profiles': 'profiles', 'exports': 'exports', 'backups': 'backups',
    'vault': 'vault', 'ssh': 'ssh', 'wireguard': 'wireguard',
    'database': 'registry', 'snapshots': 'snapshots', 'temporary': 'temporary',
    'logs': 'logs',
}
SEC_IDS = tuple('SEC-%02d' % n for n in range(1, 23))
MAX_INVENTORY_ENTRIES = 512
MAX_INVENTORY_BYTES = 500_000_000
MAX_EVIDENCE_BYTES = 65536


def _open_directory_tree(path, allowed_uid):
    """Open every absolute component without following symlinks (POSIX only)."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError('ROOT')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        components = path.split('/')[1:]
        for component in components:
            if not component:
                continue
            if component in ('.', '..'):
                raise ValueError('ROOT')
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            # Sticky, root-owned ancestor (/tmp) may contain an already-open
            # private fixture root; all accesses remain descriptor-relative.
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, allowed_uid) or info.st_mode & 0o022 and not sticky_root:
                raise ValueError('ROOT')
        info = os.fstat(fd)
        if info.st_uid != allowed_uid or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('ROOT')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _surface_inventory(root_fd, relative, allowed_uid, budget):
    result = dict(state='ok', files=0, directories=0, bytes=0)
    parts = relative.split('/') if isinstance(relative, str) else []
    if not parts or any(p in ('', '.', '..') for p in parts) or relative.startswith('/'):
        result['state'] = 'unsafe'
        return result

    def visit(parent, name, depth=0):
        budget['entries'] += 1
        if budget['entries'] > MAX_INVENTORY_ENTRIES or depth > 16:
            result['state'] = 'oversize'
            return
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if info.st_uid != allowed_uid or stat.S_IMODE(info.st_mode) & 0o077:
            result['state'] = 'unsafe'
            return
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    result['state'] = 'unsafe'
                    return
                result['directories'] += 1
                with os.scandir(fd) as entries:
                    for entry in entries:
                        visit(fd, entry.name, depth + 1)
                        if result['state'] != 'ok':
                            break
            finally:
                os.close(fd)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            result['files'] += 1
            result['bytes'] += info.st_size
            budget['bytes'] += info.st_size
            if budget['bytes'] > MAX_INVENTORY_BYTES:
                result['state'] = 'oversize'
        else:
            result['state'] = 'unsafe'

    fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            info = os.fstat(next_fd)
            os.close(fd)
            fd = next_fd
            if info.st_uid != allowed_uid or stat.S_IMODE(info.st_mode) & 0o077:
                result['state'] = 'unsafe'
                return result
        visit(fd, parts[-1])
    except FileNotFoundError:
        result['state'] = 'missing'
    except OSError:
        result['state'] = 'unsafe'
    finally:
        os.close(fd)
    return result


def audit_safe(root_path, allowed_uid, layout=None):
    """Return bounded metadata for a trusted root, without reading secret bytes.

    This is reusable by the existing root worker. It is NOT full SEC acceptance:
    filesystem policy cannot prove log redaction, foreign UID/proc-root denial,
    network state, schema-8 integrity, vault pairing or usable restore. Those
    remain explicit gaps for their existing approved collectors/tests.
    """
    checks = [dict(id=k, status='skipped_destructive' if k in ('SEC-06', 'SEC-22') else 'not_run',
                   source='safe_inventory', code='APPROVAL_REQUIRED' if k in ('SEC-06', 'SEC-22') else 'NO_OBSERVATION')
              for k in SEC_IDS]
    evidence = dict(version=1, mode='safe', checks=checks, inventory=[],
                    inventory_complete=False, root_status='unknown')
    if type(allowed_uid) is not int or allowed_uid < 0:
        evidence['root_status'] = 'unsafe'
        return evidence
    layout = SECRET_LAYOUT if layout is None else layout
    if not isinstance(layout, dict) or set(layout) != set(SECRET_LAYOUT):
        evidence['root_status'] = 'unsafe'
        return evidence
    fd = None
    try:
        fd = _open_directory_tree(root_path, allowed_uid)
        evidence['root_status'] = 'ok'
        budget = dict(entries=0, bytes=0)
        for kind in sorted(SECRET_LAYOUT):
            row = _surface_inventory(fd, layout[kind], allowed_uid, budget)
            row['kind'] = kind
            evidence['inventory'].append(row)
        expected_roots = {value.split('/')[0] for value in layout.values() if isinstance(value, str)}
        root_complete = True
        with os.scandir(fd) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_INVENTORY_ENTRIES or entry.name not in expected_roots:
                    root_complete = False
                    break
        evidence['inventory_complete'] = root_complete and all(row['state'] == 'ok' for row in evidence['inventory'])
        checks[8].update(status='unknown', code='PERMISSIONS_ONLY' if evidence['inventory_complete'] else 'INVENTORY_GAPS')
        if any(row['state'] in ('unsafe', 'oversize') for row in evidence['inventory']):
            checks[8].update(status='fail', code='SECRET_BOUNDARY')
    except (OSError, ValueError, AttributeError):
        evidence['root_status'] = 'unsafe'
        checks[8].update(status='unknown', code='ROOT_UNAVAILABLE')
    finally:
        if fd is not None:
            os.close(fd)
    return evidence


def serialize_safe_evidence(evidence):
    """Serialize only an exact bounded safe result, never arbitrary input data."""
    if not isinstance(evidence, dict) or set(evidence) != {'version', 'mode', 'checks', 'inventory', 'inventory_complete', 'root_status'}:
        raise ValueError('EVIDENCE_SCHEMA')
    if evidence['version'] != 1 or evidence['mode'] != 'safe' or type(evidence['inventory_complete']) is not bool or evidence['root_status'] not in ('unknown', 'unsafe', 'ok'):
        raise ValueError('EVIDENCE_SCHEMA')
    if not isinstance(evidence['checks'], list) or len(evidence['checks']) != 22:
        raise ValueError('EVIDENCE_SCHEMA')
    for expected, row in zip(SEC_IDS, evidence['checks']):
        if not isinstance(row, dict) or set(row) != {'id', 'status', 'source', 'code'} or row['id'] != expected or row['source'] != 'safe_inventory' or row['status'] not in ('unknown', 'not_run', 'skipped_destructive', 'fail') or row['code'] not in ('APPROVAL_REQUIRED', 'NO_OBSERVATION', 'PERMISSIONS_ONLY', 'INVENTORY_GAPS', 'SECRET_BOUNDARY', 'ROOT_UNAVAILABLE'):
            raise ValueError('EVIDENCE_SCHEMA')
    if not isinstance(evidence['inventory'], list) or len(evidence['inventory']) > len(SECRET_LAYOUT):
        raise ValueError('EVIDENCE_SCHEMA')
    seen = set()
    for row in evidence['inventory']:
        if not isinstance(row, dict) or set(row) != {'kind', 'state', 'files', 'directories', 'bytes'} or row['kind'] not in SECRET_LAYOUT or row['kind'] in seen or row['state'] not in ('ok', 'missing', 'unsafe', 'oversize'):
            raise ValueError('EVIDENCE_SCHEMA')
        seen.add(row['kind'])
        if any(type(row[k]) is not int or row[k] < 0 or row[k] > 2**63-1 for k in ('files', 'directories', 'bytes')):
            raise ValueError('EVIDENCE_SCHEMA')
    encoded = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError('EVIDENCE_SIZE')
    return encoded
