"""Use W3 synthetic profiles to verify the reverse export on loopback."""
import json
from pathlib import Path
import sys

from recovery_probe import perform
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from render import credentials


def main(root, export):
    users = credentials(json.loads(export.read_bytes()))['clients']
    auth = ''.join('basic_auth ' + json.dumps(u['username']) + ' ' + json.dumps(u['password']) + '\n'
                   for u in users)
    original = json.loads((root/'master_user.sfa.json').read_bytes())
    revoked = json.loads((root/'vpn-Legacy.Name.json').read_bytes())
    account, = [o for o in revoked['outbounds'] if o['type'] == 'naive']
    result = perform(dict(profile=original, auth=auth, revoked=account['password'], revoked_login=account['username']))
    if result['revoked_TCP'] != 'BLOCKED' or result['restored_Naive_TCP'] != 'PASS':
        raise RuntimeError('unexpected replay result')


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))
