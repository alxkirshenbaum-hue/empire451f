"""Maintainer-only deterministic packaging. Explicit allowlist; never packages parent project."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def build():
    paths = [ROOT / p for p in ['client.py', 'remote.py', 'render.py', 'verify.py', 'versions.json', 'runtime-lock.json', 'Install-Vpn.ps1', 'Install-Vpn.sh', 'README.md', 'GUIDE.md', 'CLIENT_EXPORT_V1.md', 'TEST_RESULTS.md', 'MIGRATION_TEST.md']]
    paths += sorted((ROOT / 'templates').glob('*'))
    paths += sorted((ROOT / 'bootstrap').glob('*.in'))
    paths += sorted((ROOT / 'tests').glob('*.py')) + [ROOT / 'tests/fixture.json']
    destination = ROOT / 'dist'
    destination.mkdir(exist_ok=True)
    with zipfile.ZipFile(destination / 'installer.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            data = path.read_bytes().replace(b'\r\n', b'\n')
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 11, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256((destination / 'installer.zip').read_bytes()).hexdigest()
    (destination / 'installer.sha256').write_text(digest + '  installer.zip\n', encoding='ascii')
    lock = json.loads((ROOT / 'runtime-lock.json').read_text())
    for name in ['windows.ps1', 'macos.sh']:
        source = (ROOT / 'bootstrap' / (name + '.in')).read_text(encoding='utf-8')
        source = source.replace('__BUNDLE_SHA256__', digest).replace('__PYTHON_WINDOWS_SHA256__', lock['windows_sha256']).replace('__PYTHON_MACOS_SHA256__', lock['macos_sha256'])
        (ROOT / 'bootstrap' / name).write_text(source, encoding='utf-8', newline='\n')
    print('Release bundle SHA256: ' + digest)


if __name__ == '__main__':
    build()
