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