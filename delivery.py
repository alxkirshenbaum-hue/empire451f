"""Client handoff and optional static-site publication on the entry."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import zipfile

from render import require


MASTER = 'master_user'
PANEL = 'https://panel.home.arpa/'
RELEASES = 'https://github.com/SagerNet/sing-box/releases/tag/v1.14.4'
SITE_TYPES = set('html htm css js mjs png jpg jpeg gif svg webp avif ico woff woff2 ttf webm mp4 ogg mp3 txt xml webmanifest'.split())
MAX_ZIP = 200 * 1024 * 1024


def profile(template, config, password):
    result = json.loads(template)
    outbound = next(o for o in result['outbounds'] if o['type'] == 'naive')
    outbound.update(server=config['entry']['address'], username=MASTER, password=password)
    outbound['tls']['server_name'] = config['domain']
    # Reserve the private panel destination before Android's local/direct exceptions.
    result['route']['rules'].insert(1, {'domain': ['panel.home.arpa'], 'action': 'route', 'outbound': 'naive-out'})
    return result


def publish_site(archive, root, current, *, legacy=False):
    """Stage a complete release, then switch the site with one rename."""
    require(archive.stat().st_size <= MAX_ZIP, 'Archive exceeds 200 MiB')
    require(not current.exists() or current.is_symlink(), 'Existing site pointer is not a symlink')
    require(not root.is_symlink(), 'Unexpected releases directory symlink')
    if not root.exists():
        root.mkdir(parents=True, mode=0o755)
        root.chmod(0o755)
    if current.is_symlink():
        require(current.resolve().parent == root.resolve(), 'Unknown site symlink target')
    elif legacy:
        raise ValueError('Existing legacy site pointer missing')
    stage = Path(tempfile.mkdtemp(prefix='release-', dir=root))
    link = stage.parent / (stage.name + '.link')
    try:
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            require(0 < len(entries) <= 4096, 'Too many ZIP entries')
            roots = []
            for item in entries:
                raw = item.orig_filename
                parts = raw.rstrip('/').split('/')
                require(all(x not in ('', '.', '..') for x in parts) and not any(ch in raw for ch in ('\\', ':', '\x00')), 'Unsafe ZIP path')
                require(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR) and not item.flag_bits & 1, 'Unsupported ZIP entry')
                if parts[-2:] == ['site','index.html'] and len(parts) in (2,3):
                    roots.append('/'.join(parts[:-1]) + '/')
            require(len(roots) == 1, 'Expected exactly one site/index.html (optional wrapper directory)')
            total, seen = 0, set()
            for item in entries:
                if not item.filename.startswith(roots[0]) or item.is_dir():
                    continue
                rel = PurePosixPath(item.filename[len(roots[0]):])
                require(all(re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9._ -]*', p) for p in rel.parts), 'Unsupported site filename')
                require(rel.suffix.lower()[1:] in SITE_TYPES, 'Unsupported public file type')
                require(str(rel).casefold() not in seen, 'Duplicate site path')
                seen.add(str(rel).casefold())
                total += item.file_size
                require(total <= 400 * 1024**2, 'Expanded site exceeds 400 MiB')
                target = stage.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(item) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src,dst,256*1024)
                target.chmod(0o644)
        for folder, _, _ in os.walk(stage):
            os.chmod(folder,0o755)
        link.symlink_to(stage)
        os.replace(link,current)
    except BaseException:
        link.unlink(missing_ok=True)
        shutil.rmtree(stage)
        raise
