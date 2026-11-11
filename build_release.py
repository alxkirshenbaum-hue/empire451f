"""Maintainer-only deterministic packaging. Explicit allowlist; never packages parent project."""
import hashlib
import json
import base64
import shlex
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def build():
    paths = [ROOT / p for p in ['client.py', 'controller.py', 'remote.py', 'render.py', 'verify.py', 'versions.json', 'README.md', 'GUIDE.md', 'CLIENT_EXPORT_V1.md', 'TEST_RESULTS.md', 'MIGRATION_TEST.md']]
    paths.append(ROOT / 'delivery.py')
    paths += sorted((ROOT / 'templates').glob('*'))
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
    digest = hashlib.sha256((destination / 'installer.zip').read_bytes()).hexdigest()
    (destination / 'installer.sha256').write_text(digest + '  installer.zip\n', encoding='ascii')
    loader = (ROOT / 'server_boot.py.in').read_text().replace('__BUNDLE_SHA256__', digest)
    encoded = base64.b64encode(loader.encode()).decode()
    command = "python3 -c exec\\(__import__\\(\\'base64\\'\\).b64decode\\(\\'" + encoded + "\\'\\)\\)"
    for name in ['windows.ps1', 'macos.sh']:
        source = (ROOT / 'bootstrap' / ('native-' + name + '.in')).read_text(encoding='utf-8')
        source = source.replace('__BOOT_PS__', "'" + command.replace("'", "''") + "'").replace('__BOOT_SH__', shlex.quote(command))
        (ROOT / 'bootstrap' / name).write_text(source, encoding='utf-8', newline='\n')
    print('Release bundle SHA256: ' + digest)


if __name__ == '__main__':
    build()
