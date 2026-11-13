"""Integration check driven by TestStagePythonPlan with a genuinely staged database."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import handoff_legacy as handoff


def check(snapshot, database, run):
    root = database.parent / 'installation-copy'
    shutil.copytree(snapshot, root)
    original = (root / 'manifest.json').read_bytes()
    args = ['--snapshot', str(snapshot), '--installation-copy', str(root),
            '--staging-db', str(database), '--approved-plan', run]

    def cli(expected, rollback=False):
        cmd = [sys.executable, '-B', handoff.__file__, *args]
        if rollback:
            cmd.append('--rollback')
        result = subprocess.run(cmd, capture_output=True)
        assert result.returncode == expected, 'Unexpected CLI exit'
        return json.loads(result.stdout)['status'] if expected == 0 else None

    def state():
        with sqlite3.connect(database) as db:
            return db.execute('SELECT status FROM legacy_migration_runs WHERE id=?', (run,)).fetchone()[0]

    def crash(when, rollback=False):
        pid = os.fork()
        if pid == 0:
            real_publish = handoff.publish
            def interrupted(path, data):
                if when == 'after':
                    real_publish(path, data)
                os._exit(86)
            with patch.object(handoff, 'publish', interrupted):
                handoff.handoff(snapshot, root, database, run, rollback)
            os._exit(1)
        assert os.waitpid(pid, 0)[1] == 86 << 8

    (root/'pending.json').write_bytes(b'{}')
    cli(1)
    assert state() == 'staged'
    (root/'pending.json').unlink()
    export = root/'clients.json'
    saved = export.read_bytes()
    export.write_bytes(saved + b' ')
    cli(1)
    assert state() == 'staged'
    export.write_bytes(saved)

    crash('before')
    assert state() == 'handoff_pending' and (root/'manifest.json').read_bytes() == original
    other = database.parent / 'other-copy'
    shutil.copytree(snapshot, other)
    try:
        handoff.handoff(snapshot, other, database, run)
    except ValueError:
        pass
    else:
        raise AssertionError('Resumed against a different copy')
    crash('after')
    switched = json.loads((root/'manifest.json').read_bytes())
    assert state() == 'handoff_pending' and switched['panel_run_id'] == run
    assert 'transaction' not in switched and not any(k.endswith('/auth.caddy') for k in switched['files'])
    assert cli(0) == cli(0) == 'copy_handed_off'
    assert state() == 'copy_handed_off'
    with sqlite3.connect(database) as db:
        db.execute("UPDATE users SET row_version=row_version+1 WHERE kind='regular'")
    cli(1, True)
    assert state() == 'copy_handed_off'
    with sqlite3.connect(database) as db:
        db.execute("UPDATE users SET row_version=row_version-1 WHERE kind='regular'")
    crash('before', True)
    assert state() == 'rollback_pending' and json.loads((root/'manifest.json').read_bytes()) == switched
    crash('after', True)
    assert state() == 'rollback_pending' and (root/'manifest.json').read_bytes() == original
    assert cli(0, True) == cli(0, True) == 'handoff_rolled_back'
    for path in snapshot.iterdir():
        assert path.read_bytes() == (root/path.name).read_bytes()


if __name__ == '__main__':
    check(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
