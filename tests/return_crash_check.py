"""Used by TestStagePythonPlan on a private, synthetic installation copy."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import remote
import return_legacy
from inspect_legacy import auth_lines
from render import credentials, file, change_plan, Invalid


def check(root, db, run, key, cli):
    args = (root, db, run, key, cli)
    profiles = {p:p.read_bytes() for p in root.glob('*.json') if p.name.startswith(('master_user.', 'vpn-'))}
    previous = json.loads((root/'manifest.json').read_bytes())['panel_previous_transaction']
    old_auth = (root/'auth.caddy').read_bytes()
    (root/'auth.caddy').write_bytes(old_auth+b' ')
    try:
        return_legacy.restore(*args)
    except ValueError:
        pass
    else:
        raise AssertionError('Accepted auth drift')
    (root/'auth.caddy').write_bytes(old_auth)
    for name in ('return-intent.json','clients.json','auth.caddy','manifest.json'):
        pid = os.fork()
        if pid == 0:
            publish = return_legacy.publish
            def crash(path, data):
                publish(path, data)
                if path.name == name:
                    os._exit(86)
            with patch.object(return_legacy,'publish',crash):
                return_legacy.restore(*args)
            os._exit(1)
        assert os.waitpid(pid,0)[1] == 86 << 8
        try:
            remote.require_installer_writer(json.loads((root/'manifest.json').read_bytes()),root)
        except Invalid:
            pass
        else:
            raise AssertionError('Installer admitted during return')
    assert return_legacy.restore(*args) == return_legacy.restore(*args) == 'copy_returned'
    meta = json.loads((root/'manifest.json').read_bytes())
    remote.require_installer_writer(meta,root)
    assert 'panel_generation' not in meta and meta.get('transaction') != previous
    users = credentials(json.loads((root/'clients.json').read_bytes()))['clients']
    assert [u['username'] for u in users] == ['master_user']
    auth = (root/'auth.caddy').read_bytes()
    assert list(auth_lines(auth)) == [(u['username'],u['password']) for u in users]
    path = '/etc/empire-vpn/'+meta['config']['id']+'/auth.caddy'
    desired = {path:file(''.join('basic_auth '+json.dumps(u['username'])+' '+json.dumps(u['password'])+'\n' for u in users))}
    assert change_plan(desired,{path:hashlib.sha256(auth).hexdigest()},meta['files'])[0]['action']=='unchanged'
    assert all(p.read_bytes()==data for p,data in profiles.items())
    with sqlite3.connect(db) as connection:
        assert connection.execute('SELECT phase,status FROM legacy_migration_runs WHERE id=?',(run,)).fetchone()==('rolled_back','copy_returned')


if __name__ == '__main__':
    check(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],Path(sys.argv[4]),Path(sys.argv[5]))
