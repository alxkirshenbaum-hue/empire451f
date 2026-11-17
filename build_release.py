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
    loader = loader.replace('__BUNDLE_URL__', repr(release_url or 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.4.0-rc9/dist/installer.zip'))
    encoded = base64.b64encode(loader.encode()).decode()
    command = "python3 -c exec\\(__import__\\(\\'base64\\'\\).b64decode\\(\\'" + encoded + "\\'\\)\\)"
    for name in ['windows.ps1', 'macos.sh']:
        source = (ROOT / 'bootstrap' / ('native-' + name + '.in')).read_text(encoding='utf-8')
        source = source.replace('__BUNDLE_SHA256__', digest)
        source = source.replace('__BOOT_PS__', "'" + command.replace("'", "''") + "'").replace('__BOOT_SH__', shlex.quote(command))
        (ROOT / 'bootstrap' / name).write_text(source, encoding='utf-8', newline='\n')
    print('Release bundle SHA256: ' + digest)




# Panel artifacts come from an independently staged VERIFIED core, not HEAD.
PANEL_CORE_REVISIONS = ('4dd8956', '0c05a61', '8d9b87c', '6bfb74b')
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

# RC2 retains the exact verified schema8 helpers/units. Only the reviewed Go/UI
# changes and a corrected v1-upgrade test fixture differ from the published base.
PANEL_CORE_MANIFESTS['8d9b87c6b4bb9105d21860a2819c372dcc318db2'] = dict(
    PANEL_CORE_MANIFESTS['0c05a6174e254192939227668f9d4947904984d4'])
PANEL_BINARY_MANIFESTS = {
    '8d9b87c6b4bb9105d21860a2819c372dcc318db2': {
        'bin/vpn-control': '7819dac20300d0f424e26656a1eafb98b8e136e8c5776c7d885b228a9e74836a',
        'bin/vpnctl': '98251aab125c2ebdd89339804f39fd756933425a654120214dfcb5f053a59cc9',
    },
}


# RC4 changes only the reviewed cutover/restore helpers; Go/schema/ELF bytes match RC2.
PANEL_CORE_MANIFESTS['6bfb74bfa891071a5b8e316b23178026edd7d19e'] = dict(PANEL_CORE_MANIFESTS['8d9b87c6b4bb9105d21860a2819c372dcc318db2'])
PANEL_CORE_MANIFESTS['6bfb74bfa891071a5b8e316b23178026edd7d19e']['handoff_legacy.py'] = 'd889c9d17021968c7d145811318763fc2e8740dc6c153ef8bcd37905fcdea377'
PANEL_CORE_MANIFESTS['6bfb74bfa891071a5b8e316b23178026edd7d19e']['g3_restore_runtime.py'] = 'b370f86359e46af79d1033136df9c7551902cf224682da672060d820d88d3439'
PANEL_BINARY_MANIFESTS['6bfb74bfa891071a5b8e316b23178026edd7d19e'] = dict(PANEL_BINARY_MANIFESTS['8d9b87c6b4bb9105d21860a2819c372dcc318db2'])



# RC5: reviewed domain/path frontend and exact clean ELF build.
PANEL_CORE_MANIFESTS['c174ba9babba229ee04f3eca4c1f323a06755301'] = json.loads(r'''{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"b370f86359e46af79d1033136df9c7551902cf224682da672060d820d88d3439","inspect_legacy.py":"b3df61e84414b078eccfecf5587166643809556f82cc76b719e465d27fc1d0a9","handoff_legacy.py":"d889c9d17021968c7d145811318763fc2e8740dc6c153ef8bcd37905fcdea377","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"665e78983c9ebf681ddca7cb66cbb5a6f79074379c7d596bf0ebc4208d68dcef","verify.py":"b57472a4836a59ef2dbc0b01e35f6104193c309f8fa57172a0afaee25965ebe1","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"86f2b8346efaa8610d708641fbe8e651dd4dd4178ae417e9d2ebce189782988f","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"6de240b76aa4936b1fa0b56b46e975e3d2f522768599f4b21bbcc2a5d13c2b17","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"}''')
PANEL_BINARY_MANIFESTS['c174ba9babba229ee04f3eca4c1f323a06755301'] = json.loads(r'''{"bin/vpn-control":"32d7aa0bf68e95208d86094fb0673ee965bc997d04d4a578440a4401275c2ae1","bin/vpnctl":"ad6f6c227a237747e1356c69d344a7d221732a603660dfa157bc20d5424b786b"}''')

# RC6 profile404: exact tested clean core and ELF.
PANEL_CORE_MANIFESTS['05f5a239f40bcb238b6debb0a3feb3239ffa4734'] = json.loads(r'''{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"b370f86359e46af79d1033136df9c7551902cf224682da672060d820d88d3439","inspect_legacy.py":"b3df61e84414b078eccfecf5587166643809556f82cc76b719e465d27fc1d0a9","handoff_legacy.py":"d889c9d17021968c7d145811318763fc2e8740dc6c153ef8bcd37905fcdea377","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"665e78983c9ebf681ddca7cb66cbb5a6f79074379c7d596bf0ebc4208d68dcef","verify.py":"b57472a4836a59ef2dbc0b01e35f6104193c309f8fa57172a0afaee25965ebe1","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"86f2b8346efaa8610d708641fbe8e651dd4dd4178ae417e9d2ebce189782988f","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"6de240b76aa4936b1fa0b56b46e975e3d2f522768599f4b21bbcc2a5d13c2b17","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"}''')
PANEL_BINARY_MANIFESTS['05f5a239f40bcb238b6debb0a3feb3239ffa4734'] = json.loads(r'''{"bin/vpn-control":"cd8999c48e0943be458c93e0a9633249087a78de39f5ba19a093a64f4fff16a3","bin/vpnctl":"127d9740f24edced29a874ed76d8c031370482635e60e49a1fdba91d3df65fd5"}''')

# RC7: canonical master/schema9 and checked native handoff.
PANEL_CORE_MANIFESTS['d94a4e7121c41bb9157e7c14d457365c7abd99d6'] = json.loads(r'''{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"b370f86359e46af79d1033136df9c7551902cf224682da672060d820d88d3439","inspect_legacy.py":"56f32a232a8a951df229026272ed4007dcbe0cf756ac86533893b087a2bcc905","handoff_legacy.py":"d889c9d17021968c7d145811318763fc2e8740dc6c153ef8bcd37905fcdea377","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"665e78983c9ebf681ddca7cb66cbb5a6f79074379c7d596bf0ebc4208d68dcef","verify.py":"b57472a4836a59ef2dbc0b01e35f6104193c309f8fa57172a0afaee25965ebe1","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"86f2b8346efaa8610d708641fbe8e651dd4dd4178ae417e9d2ebce189782988f","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"6de240b76aa4936b1fa0b56b46e975e3d2f522768599f4b21bbcc2a5d13c2b17","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"}''')
PANEL_BINARY_MANIFESTS['d94a4e7121c41bb9157e7c14d457365c7abd99d6'] = json.loads(r'''{"bin/vpn-control":"4399d75331cae1f9b496f439eca925f74908ff0fcb7fee098e9f0e8bf5363e4e","bin/vpnctl":"b460f90840a150ce08b791608d0b2d86012089313674b22ef64e1f21e183a708"}''')

# RC9 helper-only child; Go tree and accepted ELF unchanged.
PANEL_CORE_MANIFESTS['55593cb4ac92674631a811c4bc1d1eed91612519'] = json.loads(r'''{"vpn-add-user.template":"0adafe5b445b0b1a3d613e66934531ce945989107e965f1dfc73bf5478f24592","owned_auth.py":"d161f67951f732bf1b671afefb8bf3cf58be16badf7a65514a4f55ba610caadd","create_probe.py":"b6d3f93737e3cf0c950aa46b87515a3b04a0f91a32ce7b196c84c3ecb923c12f","g3_snapshot.py":"85e1c89d2a18cd0612aa351be315e74e7fb06166bb38410bf2ec33d2b57bc4cf","g3_restore_runtime.py":"b370f86359e46af79d1033136df9c7551902cf224682da672060d820d88d3439","inspect_legacy.py":"56f32a232a8a951df229026272ed4007dcbe0cf756ac86533893b087a2bcc905","handoff_legacy.py":"d889c9d17021968c7d145811318763fc2e8740dc6c153ef8bcd37905fcdea377","return_legacy.py":"dae1d6545f1badf24d6c59ad0ae2d84a52b61c3d9dcf600cca155975da5db434","render.py":"7c909b61fc2120aee370a7fc61a95cea7d0c3fb586c5473fbc7b35348a168c18","verify.py":"75ae1dddbdb697f32e31e8e80f1a87dfc7b63f9ae2471fae8b20d6c293c9fc19","backup_artifact.py":"69f3dad25851c8ae5b5b29dcdc327abccb8715a5607f298c834efe09150c582d","templates/sfa-profile.json":"1cea56f365912867563039963cc6fe25c47c1873c10010bcd1916d23c1a9a1b8","templates/panel-frontend.Caddyfile":"86f2b8346efaa8610d708641fbe8e651dd4dd4178ae417e9d2ebce189782988f","controlpanel/systemd/vpn-control-api.service":"1a81334cb0a2210cdc991cf67327dffab891d392b310eea3991d30963fdf7b05","controlpanel/systemd/vpn-control-panel.service":"6de240b76aa4936b1fa0b56b46e975e3d2f522768599f4b21bbcc2a5d13c2b17","controlpanel/systemd/vpn-control-worker@.service":"a885820138213564fe0d271ef5183a921e5bb8c302639fb90b9cd7cf398113ea","controlpanel/systemd/vpn-control-worker@.timer":"e23845370813efd060be6ad9ca5b7a602cb03b993367c108f249b7cdc62f8f02"}''')
PANEL_BINARY_MANIFESTS['55593cb4ac92674631a811c4bc1d1eed91612519'] = json.loads(r'''{"bin/vpn-control":"4399d75331cae1f9b496f439eca925f74908ff0fcb7fee098e9f0e8bf5363e4e","bin/vpnctl":"b460f90840a150ce08b791608d0b2d86012089313674b22ef64e1f21e183a708"}''')

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
            expected_binary = PANEL_BINARY_MANIFESTS.get(source_sha, {}).get(name)
            if expected_binary is not None and hashlib.sha256(data).hexdigest() != expected_binary:
                raise ValueError('Panel binary differs from verified release build')
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
