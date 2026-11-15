"""Maintainer-only deterministic packaging. Explicit allowlist; never packages parent project."""
import hashlib
import json
import base64
import shlex
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def build(panel_root=None, panel_source_sha=None, release_url=None):
    payload = panel_payload(panel_root, panel_source_sha) if panel_root is not None else None
    if (panel_root is None) != (panel_source_sha is None): raise ValueError('Panel staging and source SHA must be supplied together')
    paths = [ROOT / p for p in ['client.py', 'controller.py', 'remote.py', 'render.py', 'verify.py', 'versions.json', 'README.md', 'GUIDE.md', 'CLIENT_EXPORT_V1.md', 'TEST_RESULTS.md', 'MIGRATION_TEST.md']]
    paths.append(ROOT / 'delivery.py')
    template_names = ('caddy.service','Caddyfile','firewall.service','host-entry.nft',
                      'host-exit.nft','namespace.nft','network-entry.sh','network-exit.sh',
                      'network.service','panel-frontend.Caddyfile','relay.service',
                      'relay.socket','sfa-profile.json','singbox.service','vpn-add-user')
    paths += [ROOT / 'templates' / name for name in template_names]
    destination = ROOT / 'dist'
    destination.mkdir(exist_ok=True)
    sample = ROOT / 'examples/site-handoff'
    with zipfile.ZipFile(destination / 'site-handoff-example.zip', 'w') as z:
        for path in sorted(sample.rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo('site-handoff/' + path.relative_to(sample).as_posix())
                z.writestr(info, path.read_bytes().replace(b'\r\n', b'\n'), compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(destination / 'installer.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            data = path.read_bytes().replace(b'\r\n', b'\n')
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 11, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
        if payload is not None:
            info = zipfile.ZipInfo('panel/payload.json', (2026, 11, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    digest = hashlib.sha256((destination / 'installer.zip').read_bytes()).hexdigest()
    (destination / 'installer.sha256').write_text(digest + '  installer.zip\n', encoding='ascii')
    loader = (ROOT / 'server_boot.py.in').read_text().replace('__BUNDLE_SHA256__', digest)
    loader = loader.replace('__BUNDLE_URL__', repr(release_url or 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/dist/installer.zip'))
    encoded = base64.b64encode(loader.encode()).decode()
    command = "python3 -c exec\\(__import__\\(\\'base64\\'\\).b64decode\\(\\'" + encoded + "\\'\\)\\)"
    for name in ['windows.ps1', 'macos.sh']:
        source = (ROOT / 'bootstrap' / ('native-' + name + '.in')).read_text(encoding='utf-8')
        source = source.replace('__BUNDLE_SHA256__', digest)
        source = source.replace('__BOOT_PS__', "'" + command.replace("'", "''") + "'").replace('__BOOT_SH__', shlex.quote(command))
        (ROOT / 'bootstrap' / name).write_text(source, encoding='utf-8', newline='\n')
    print('Release bundle SHA256: ' + digest)




# Panel artifacts come from an independently staged VERIFIED core, not HEAD.
PANEL_CORE_REVISIONS = ('4dd8956', '0c05a61')
PANEL_PATHS = (
    'bin/vpn-control', 'bin/vpnctl', 'vpn-add-user.template',
    'owned_auth.py', 'create_probe.py', 'g3_snapshot.py', 'g3_restore_runtime.py',
    'inspect_legacy.py', 'handoff_legacy.py', 'return_legacy.py', 'render.py',
    'verify.py', 'backup_artifact.py',
    'templates/sfa-profile.json', 'templates/panel-frontend.Caddyfile',
    'controlpanel/systemd/vpn-control-api.service',
    'controlpanel/systemd/vpn-control-panel.service',
    'controlpanel/systemd/vpn-control-worker@.service',
    'controlpanel/systemd/vpn-control-worker@.timer',
)
MAX_PANEL_BYTES = 80 * 1024 * 1024


PANEL_CORE_MANIFESTS = json.loads(r'''{"4dd895600e038ecdfd0e70f5383a8e41500d46b7":{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"9c7da6a54b35e14898c09feb26787d3f7aadf9624fd99b64873d5b405895e9ee","inspect_legacy.py":"b3df61e84414b078eccfecf5587166643809556f82cc76b719e465d27fc1d0a9","handoff_legacy.py":"a2ab3f73ccf67fd12db7d9c0144f6abd7d8cae22af356d94bec59a27a569c9e7","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"f184ab524304cbc8fe5b892cbc84fb9f61f75bc68ed0f1009d28d7bc2087678e","verify.py":"b57472a4836a59ef2dbc0b01e35f6104193c309f8fa57172a0afaee25965ebe1","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"aa0d03c304d6d1729b162fa78b0df0c29d63edeb0ec327ea87558044865fc0cb","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"a98db0b1f6bd023b8ea4ecef929bb3ffa5e7fb236ccf15b031d657c5fd0dfa02","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"},"0c05a6174e254192939227668f9d4947904984d4":{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"9c7da6a54b35e14898c09feb26787d3f7aadf9624fd99b64873d5b405895e9ee","inspect_legacy.py":"b3df61e84414b078eccfecf5587166643809556f82cc76b719e465d27fc1d0a9","handoff_legacy.py":"a2ab3f73ccf67fd12db7d9c0144f6abd7d8cae22af356d94bec59a27a569c9e7","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"f184ab524304cbc8fe5b892cbc84fb9f61f75bc68ed0f1009d28d7bc2087678e","verify.py":"b57472a4836a59ef2dbc0b01e35f6104193c309f8fa57172a0afaee25965ebe1","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"aa0d03c304d6d1729b162fa78b0df0c29d63edeb0ec327ea87558044865fc0cb","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"a98db0b1f6bd023b8ea4ecef929bb3ffa5e7fb236ccf15b031d657c5fd0dfa02","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"}}''')

def panel_destination(name):
    if name.startswith('bin/') or name.startswith('templates/'):
        return name
    if name.startswith('controlpanel/systemd/'):
        return name.removeprefix('controlpanel/')
    return 'helpers/' + name


def panel_payload(staging, source_sha):
    staging = Path(staging)
    expected_files = PANEL_CORE_MANIFESTS.get(source_sha)
    if expected_files is None:
        raise ValueError('Panel source must be an explicitly verified core revision')
    entries = []
    total = 0
    for name in PANEL_PATHS:
        path = staging / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise ValueError('Panel payload requires regular allowlisted files')
        data = path.read_bytes()
        total += len(data)
        if total > MAX_PANEL_BYTES:
            raise ValueError('Panel payload exceeds release limit')
        binary = name.startswith('bin/')
        if binary:
            if not data.startswith(b'\x7fELF') or len(data) < 1024:
                raise ValueError('Linux ELF panel binary required')
        elif hashlib.sha256(data).hexdigest() != expected_files[name]:
            raise ValueError('Panel helper differs from pinned core')
        entries.append(dict(path=panel_destination(name), mode=0o755 if binary else 0o644,
                            sha256=hashlib.sha256(data).hexdigest(),
                            data=base64.b64encode(data).decode('ascii')))
    return json.dumps(dict(format='vpn-control-panel-v1', source_sha=source_sha,
                           files=entries), sort_keys=True, separators=(',', ':')).encode('ascii')


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--panel-root',type=Path)
    parser.add_argument('--panel-source-sha')
    parser.add_argument('--release-url')
    args=parser.parse_args()
    build(args.panel_root,args.panel_source_sha,args.release_url)
