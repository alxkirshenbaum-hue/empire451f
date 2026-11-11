"""Ubuntu agent, invoked through SSH stdin. Never prints subprocess output/secrets."""
import base64
import contextlib
import datetime
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from render import Invalid, addresses, change_plan, file, names, render, require, validate


def run(args, data=None, check=True, timeout=120, env=None):
    try:
        p = subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise Invalid('Command timed out: ' + str(args[0])) from None
    if check and p.returncode:
        # Do not echo arbitrary command stderr: validators may echo credentials.
        raise Invalid('Command failed: ' + str(args[0]) + ' (exit ' + str(p.returncode) + ')')
    return p


def text(args, **kw):
    return run(args, **kw).stdout.decode().strip()


def digest(path):
    p = Path(path)
    if p.is_symlink():
        raise Invalid('Symlink at managed path: ' + str(p))
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def atomic(path, data, mode=0o600, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.evpn-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if group:
            import grp
            os.fchown(fd, 0, grp.getgrnam(group).gr_gid)
        with os.fdopen(fd, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def readjson(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def units(c, role):
    p = names(c)['prefix']
    result = [p + '-firewall.service', p + '-network.service']
    if role == 'entry':
        result += [p + '-singbox.service', p + '-caddy.service', p + '-http.socket', p + '-https.socket']
    return result


def public_key(path):
    require(Path(path).is_file(), 'WG key is missing')
    return text(['wg', 'pubkey'], data=Path(path).read_bytes())


def wireguard_runtime_key(source, destination, publish=False):
    """Keep the state key for recovery and expose identical bytes in WireGuard's key directory."""
    source, destination = Path(source), Path(destination)
    require(not source.is_symlink() and not destination.is_symlink(), 'Unexpected WireGuard key symlink')
    if destination.exists():
        require(source.is_file() and destination.is_file() and
                destination.stat().st_mode & 0o077 == 0 and destination.stat().st_uid == 0 and
                digest(source) == digest(destination), 'Conflicting WireGuard key file; refusing to replace it')
    elif publish:
        # Install without overwriting an existing key, including across filesystems.
        fd, tmp = tempfile.mkstemp(dir=destination.parent, prefix='.empire-key-')
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(source.read_bytes())
                out.flush()
                os.fsync(out.fileno())
            os.link(tmp, destination)
        finally:
            os.unlink(tmp)


def probe(c, role):
    require(os.geteuid() == 0, 'ROOT_REQUIRED: use root or provider console bootstrap')
    require(sys.version_info >= (3, 12), 'Python3.12+ required on Ubuntu 24.04/26.04')
    osr = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(osr.get('ID', '').strip('"') == 'ubuntu' and osr.get('VERSION_ID', '').strip('"') in ('24.04', '26.04') and os.uname().machine == 'x86_64', 'UNSUPPORTED_PLATFORM: Ubuntu 24.04 or 26.04 amd64 required')
    require(Path('/run/systemd/system').exists(), 'systemd required')
    n = names(c)
    routes = json.loads(text(['ip', '-j', '-4', 'route', 'show', 'default']))
    require(len(routes) == 1 and 'dev' in routes[0], 'Expected one unambiguous IPv4 default route')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    require(len(connection) == 4, 'SSH_CONNECTION missing')
    f = {'interface': routes[0]['dev'], 'ssh_port': int(connection[3]), 'admin_ip': connection[0],
         'legacy': c[role]['kind'] == 'legacy', 'key_path': n['state'] + '/wireguard.key',
         'default_route': routes, 'machine_id': Path('/etc/machine-id').read_text().strip()}
    if not f['legacy']:
        f['runtime_key_path'] = '/etc/wireguard/' + n['prefix'] + '.key'
        wireguard_runtime_key(f['key_path'], f['runtime_key_path'])
    if f['legacy']:
        require(Path('/etc/wireguard/role').read_text().strip() == role, 'Legacy role mismatch')
        f['key_path'] = '/etc/wireguard/personal.key'
        require(Path(f['key_path']).is_file(), 'Legacy WG key missing')
        script = Path('/usr/local/sbin/personal-vpn').read_text()
        require('ip netns' in script and 'wg set wg0' in script, 'Unknown legacy network script')
        nft = Path('/etc/nftables.conf').read_text()
        require('table inet personal_host' in nft and 'chain input {' in nft and 'chain forward {' in nft, 'Unknown legacy firewall')
        f['legacy_hashes'] = {p: digest(p) for p in ['/usr/local/sbin/personal-vpn', '/etc/nftables.conf', '/etc/wireguard/peer.pub']}
        if role == 'entry':
            require('import /etc/naive/auth.caddy' in Path('/etc/naive/Caddyfile').read_text(), 'Unknown legacy authentication layout')
            f['legacy_hashes']['/etc/naive/auth.caddy'] = digest('/etc/naive/auth.caddy')
            ep = re.findall(r'endpoint ([0-9.]+):(\d+)', script)
            require(len(ep) == 1, 'Unknown legacy endpoint')
            f['old_endpoint'] = ep[0][0] + ':' + ep[0][1]
            f['old_peer'] = Path('/etc/wireguard/peer.pub').read_text().strip()
            require(re.fullmatch(r'[A-Za-z0-9+/]{43}=', f['old_peer']), 'Unknown legacy peer')
            f['legacy_hashes']['/etc/wireguard/namespace.nft'] = digest('/etc/wireguard/namespace.nft')
            a = json.loads(text(['ip', '-n', 'naive', '-j', '-4', 'addr', 'show', 'dev', 'wg0']))
            f['tunnel'] = str(ipaddress.ip_interface(a[0]['addr_info'][0]['local'] + '/' + str(a[0]['addr_info'][0]['prefixlen'])).network)
            require(f['tunnel'] == c['tunnel'], 'Set tunnel to preserved entry subnet: ' + f['tunnel'])
    manifest = readjson(n['state'] + '/manifest.json', {})
    if manifest:
        require(manifest.get('role') == role, 'Installed role differs from request')
        require((manifest['config'][role]['kind'] == 'legacy') == f['legacy'], 'Do not change the installed legacy/managed adapter')
        require(Path(f['key_path']).is_file(), 'Installed WG key missing; refusing automatic key rotation')
    f['owned'] = manifest.get('files', {})
    f['pending'] = readjson(n['state'] + '/pending.json')
    if Path(f['key_path']).exists():
        require(shutil.which('wg') is not None, 'wg tool required for existing key')
        f['public_key'] = public_key(f['key_path'])
    # Refuse collisions on new machines; never infer ownership from a filename alone.
    if not f['legacy'] and not manifest:
        if role == 'entry':
            require(not Path('/run/netns/naive').exists(), 'Unknown namespace naive exists')
            require(run(['ip', 'link', 'show', 'wg0'], check=False).returncode != 0, 'Unknown wg0 exists')
            listeners = text(['ss', '-H', '-ltn'])
            require(not re.search(r':(?:80|443)\s', listeners), 'Ports 80/443 already in use')
        require(run(['ip', 'link', 'show', n['exit_if'] if role == 'exit' else n['host_if']], check=False).returncode != 0, 'Interface name collision')
        if shutil.which('nft'):
            rules = json.loads(text(['nft', '-j', 'list', 'ruleset']))
            require(not any('chain' in x or 'rule' in x for x in rules.get('nftables', [])), 'Unknown host firewall: clean node required')
        if shutil.which('ufw'):
            status = text(['ufw', 'status'], env=dict(os.environ, LC_ALL='C'))
            require(status.splitlines()[:1] == ['Status: inactive'], 'Active or unknown UFW configuration is unsupported')
        else:
            require(run(['systemctl', 'is-active', '--quiet', 'ufw'], check=False).returncode != 0, 'Unknown UFW service is active')
    existing_routes = json.loads(text(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
    for r in existing_routes:
        dst = r.get('dst', 'default')
        if dst in ('default', 'broadcast') or r.get('dev') in (n['exit_if'], n['host_if']):
            continue
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if f['legacy'] and role == 'entry' and net.subnet_of(ipaddress.ip_network(c['relay'])):
            continue
        require(not any(net.overlaps(ipaddress.ip_network(c[x])) for x in ('tunnel', 'relay')), 'Chosen subnet overlaps host route: ' + dst)
    return f


def download(url, sha, destination):
    destination = Path(destination)
    if destination.exists() and digest(destination) == sha:
        return
    deadline = time.monotonic() + 600
    data = bytearray()
    with urllib.request.urlopen(url, timeout=60) as response:
        while len(data) <= 200 * 1024 * 1024:
            chunk = response.read1(256 * 1024)
            require(time.monotonic() <= deadline, 'Component download exceeded 10 minutes')
            if not chunk:
                break
            data.extend(chunk)
    require(len(data) <= 200 * 1024 * 1024, 'Download too large')
    require(hashlib.sha256(data).hexdigest() == sha, 'Official download checksum mismatch')
    atomic(destination, bytes(data))


def prepare(c, role, versions):
    f = probe(c, role)
    require(not f['pending'], 'Pending transaction: recover/rollback before prepare')
    n = names(c)
    Path(n['state']).mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(n['state'], 0o700)
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    required = ['wireguard-tools', 'nftables', 'iproute2', 'ca-certificates', 'curl', 'python3']
    if role == 'entry' and not f['legacy']:
        required += ['git', 'build-essential']
    missing = [p for p in required if text(['dpkg-query', '-W', '-f=${db:Status-Status}', p], check=False) != 'installed']
    if missing:
        run(['apt-get', 'update'], timeout=600, env=env)
        run(['apt-get', 'install', '-y', '--no-install-recommends'] + missing, timeout=1200, env=env)
    if not Path(f['key_path']).exists():
        atomic(f['key_path'], run(['wg', 'genkey']).stdout)
    if not f['legacy']:
        wireguard_runtime_key(f['key_path'], f['runtime_key_path'], publish=True)
    if role == 'entry' and not f['legacy']:
        install_components(versions)
        if run(['id', 'evpn'], check=False).returncode:
            run(['useradd', '--system', '--user-group', '--home-dir', '/var/lib/empire-vpn-acme', '--shell', '/usr/sbin/nologin', 'evpn'])
        else:
            import pwd
            account = pwd.getpwnam('evpn')
            require(account.pw_uid != 0 and account.pw_shell == '/usr/sbin/nologin' and account.pw_dir == '/var/lib/empire-vpn-acme', 'Unrecognised evpn service account')
    return {'public_key': public_key(f['key_path'])}


def install_components(v):
    root = Path('/opt/empire-vpn')
    marker = root / 'installed.json'
    pending_marker = root / 'cache/pending-install.json'
    if not marker.exists() and (root / 'bin').exists() and pending_marker.exists():
        pending = readjson(pending_marker)
        require(pending['versions'] == v and all(digest(p) == h for p, h in pending['files'].items()), 'Interrupted component install differs from journal')
        atomic(marker, json.dumps(pending))
    if marker.exists():
        installed = readjson(marker)
        require(installed['versions'] == v, 'Installed component versions differ; explicit upgrade is outside v1')
        for p, h in installed['files'].items():
            require(digest(p) == h, 'Installed component modified: ' + p)
        return
    require(not (root / 'bin').exists(), 'Unowned component directory exists')
    cache = root / 'cache'
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o755)
    go = cache / 'go.tar.gz'
    sb = cache / 'sing-box.tar.gz'
    download('https://go.dev/dl/go' + v['go'] + '.linux-amd64.tar.gz', v['go_sha256'], go)
    download('https://github.com/SagerNet/sing-box/releases/download/v' + v['sing_box'] + '/sing-box-' + v['sing_box'] + '-linux-amd64.tar.gz', v['sing_box_sha256'], sb)
    for archive, folder in [(go, cache / 'toolchain'), (sb, cache / 'sing-box')]:
        folder.mkdir(exist_ok=True)
        with tarfile.open(archive) as tar:
            tar.extractall(folder, filter='data')
    env = dict(os.environ, PATH=str(cache / 'toolchain/go/bin') + ':' + os.environ['PATH'], GOBIN=str(cache / 'gobin'),
               GOMAXPROCS='2', GOMEMLIMIT='400MiB', GOFLAGS='-p=1', GOTOOLCHAIN='local', GOSUMDB='sum.golang.org')
    run([str(cache / 'toolchain/go/bin/go'), 'install', 'github.com/caddyserver/xcaddy/cmd/xcaddy@' + v['xcaddy']], env=env, timeout=1800)
    staging = cache / 'caddy'
    run([str(cache / 'gobin/xcaddy'), 'build', v['caddy'], '--with', 'github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@' + v['forwardproxy'], '--output', str(staging)], env=env, timeout=3600)
    require('http.handlers.forward_proxy' in text([str(staging), 'list-modules']), 'Caddy forwardproxy module missing')
    sbdir = cache / 'sing-box' / ('sing-box-' + v['sing_box'] + '-linux-amd64')
    # Move the complete staged directory atomically: interruption cannot claim a partial install.
    bindir = cache / 'bin-ready'
    bindir.mkdir(exist_ok=True)
    bindir.chmod(0o755)
    atomic(bindir / 'caddy', staging.read_bytes(), 0o755)
    atomic(bindir / 'sing-box', (sbdir / 'sing-box').read_bytes(), 0o755)
    if (sbdir / 'libcronet.so').exists():
        atomic(bindir / 'libcronet.so', (sbdir / 'libcronet.so').read_bytes(), 0o755)
    require(v['sing_box'] in text([str(bindir / 'sing-box'), 'version']), 'sing-box version mismatch')
    manifest = {'versions': v, 'files': {str(root / 'bin' / p.name): digest(p) for p in bindir.iterdir()}}
    atomic(pending_marker, json.dumps(manifest))
    os.replace(bindir, root / 'bin')
    atomic(marker, json.dumps(manifest))


def legacy_exit_rules(c, f):
    n = names(c)
    _, te, _, _ = addresses(c)
    tag = 'evpn:' + c['id']
    return [('input', 'ip saddr ' + c['entry']['address'] + ' udp dport ' + str(c['wg_port']) + ' accept comment "' + tag + ':input"'),
            ('forward', 'iifname "' + n['exit_if'] + '" oifname "' + f['interface'] + '" ip saddr ' + te + ' accept comment "' + tag + ':out"'),
            ('forward', 'oifname "' + n['exit_if'] + '" ip daddr ' + te + ' ct state established,related accept comment "' + tag + ':return"')]


def desired(c, role, f, keys, clients, templates):
    if f['legacy'] and role == 'entry':
        old = f['old_endpoint']
        new = c['exit']['address'] + ':' + str(c['wg_port'])
        script = Path('/usr/local/sbin/personal-vpn').read_text()
        require(script.count('endpoint ' + old) == 1, 'Legacy script changed')
        out = {'/usr/local/sbin/personal-vpn': file(script.replace('endpoint ' + old, 'endpoint ' + new), 0o700),
               '/etc/wireguard/peer.pub': file(keys['exit'], 0o600)}
        old_ip = old.split(':')[0]
        for path in ['/etc/nftables.conf', '/etc/wireguard/namespace.nft']:
            content = Path(path).read_text()
            require(old_ip in content, 'Legacy firewall endpoint absent')
            if path == '/etc/nftables.conf':
                content = re.sub(r'(ip saddr ' + re.escape(old_ip) + r' udp sport )' + old.split(':')[1] + r'\b', lambda m: m[1] + str(c['wg_port']), content)
            out[path] = file(re.sub(r'(?<![\d.])' + re.escape(old_ip) + r'(?![\d.])', c['exit']['address'], content), 0o600 if 'wireguard' in path else 0o644)
        import shlex
        auth = '/etc/naive/auth.caddy'
        original = Path(auth).read_text()
        master = next(u for u in clients['clients'] if u['username'] == 'master_user')
        found = False
        for line in original.splitlines():
            parts = shlex.split(line,comments=True)
            if not parts:
                continue
            require(len(parts)==3 and parts[0]=='basic_auth', 'Unknown legacy authentication syntax')
            if parts[1] == 'master_user':
                require(parts[2]==master['password'], 'Import the existing master_user credentials before migration')
                found = True
        if not found:
            out[auth] = file(original.rstrip('\n')+'\nbasic_auth "master_user" '+json.dumps(master['password']),0o640,'naive')
        elif auth in f['owned']:
            out[auth] = file(original,0o640,'naive')
        return out
    out = render(c, role, f, keys, clients, templates)
    if f['legacy']:
        path = '/etc/nftables.conf'
        content = Path(path).read_text()
        tag = 'evpn:' + c['id']
        content = '\n'.join(line for line in content.splitlines() if 'comment "' + tag + ':' not in line) + '\n'
        for chain, expr in legacy_exit_rules(c, f):
            needle = ' chain ' + chain + ' {\n'
            require(content.count(needle) == 1, 'Ambiguous legacy firewall chain')
            # Base chain declarations must precede ordinary rules. Insert after policy declaration.
            pos = content.index('\n', content.index(needle) + len(needle)) + 1
            require('type filter hook ' + chain in content[content.index(needle):pos], 'Unknown base chain declaration')
            content = content[:pos] + '  ' + expr + '\n' + content[pos:]
        out[path] = file(content)
    return out


def plan(c, role, f, keys, clients, templates):
    out = desired(c, role, f, keys, clients, templates)
    existing = {p: digest(p) for p in out}
    owned = dict(f['owned'])
    if f['legacy']:
        # Only the explicit legacy adapter may adopt these exact observed files.
        for p, h in f['legacy_hashes'].items():
            owned.setdefault(p, h)
    return out, change_plan(out, existing, owned)


def snapshot(path):
    p = Path(path)
    if not p.exists():
        return None
    require(p.is_file() and not p.is_symlink(), 'Cannot snapshot nonregular file')
    s = p.stat()
    return {'data': base64.b64encode(p.read_bytes()).decode(), 'mode': s.st_mode & 0o777,
            'uid': s.st_uid, 'gid': s.st_gid}


def backup_bytes(txdir, saved):
    require(re.fullmatch(r'[a-f0-9]{64}', saved['backup']), 'Invalid backup reference')
    return (Path(txdir) / 'backups' / saved['backup']).read_bytes()


def arm_timer(c, txdir):
    n = names(c)
    timer = n['prefix'] + '-rollback'
    deadline = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    atomic('/etc/systemd/system/' + timer + '.service', '[Unit]\nDescription=Empire transaction rollback\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 ' + str(txdir / 'remote.py') + ' rollback-local ' + str(txdir) + '\n', 0o644)
    atomic('/etc/systemd/system/' + timer + '.timer', '[Unit]\nDescription=Empire rollback deadline\n[Timer]\nOnCalendar=' + deadline.strftime('%Y-%m-%d %H:%M:%S UTC') + '\nPersistent=true\n[Install]\nWantedBy=timers.target\n', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', timer + '.timer'])


def cancel_timer(c):
    timer = names(c)['prefix'] + '-rollback'
    run(['systemctl', 'disable', '--now', timer + '.timer'], check=False)
    for ext in ('timer', 'service'):
        Path('/etc/systemd/system/' + timer + '.' + ext).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])


def legacy_runtime(c, role, f, undo=False):
    if role == 'exit':
        lines = text(['nft', '-a', 'list', 'table', 'inet', 'personal_host']).splitlines()
        chain = None
        for line in lines:
            m = re.search(r'chain (\w+) \{', line)
            if m:
                chain = m[1]
            if 'comment "evpn:' + c['id'] + ':' in line:
                handle = re.search(r'# handle (\d+)', line)
                require(handle is not None, 'Cannot identify migration rule')
                run(['nft', 'delete', 'rule', 'inet', 'personal_host', chain, 'handle', handle[1]])
        rules = legacy_exit_rules(c, f)
        if undo:
            rules = []
            chain = None
            for line in Path('/etc/nftables.conf').read_text().splitlines():
                m = re.search(r'chain (\w+) \{', line)
                if m:
                    chain = m[1]
                if 'comment "evpn:' + c['id'] + ':' in line:
                    rules.append((chain, line.strip()))
        if rules:
            for chain, expr in rules:
                run(['nft', '-f', '-'], data=('insert rule inet personal_host ' + chain + ' ' + expr + '\n').encode())
    else:
        old_ip = f['old_endpoint'].split(':')[0]
        new_ip = c['exit']['address']
        source, dest = (new_ip, old_ip) if undo else (old_ip, new_ip)
        chain = None
        commands = []
        for line in text(['nft', '-a', 'list', 'table', 'inet', 'personal_host']).splitlines():
            m = re.search(r'chain (\w+) \{', line)
            if m:
                chain = m[1]
            if re.search(r'(?<![\d.])' + re.escape(source) + r'(?![\d.])', line) and '# handle' in line:
                expr, handle = line.strip().rsplit(' # handle ', 1)
                sport, dport = (str(c['wg_port']), f['old_endpoint'].split(':')[1]) if undo else (f['old_endpoint'].split(':')[1], str(c['wg_port']))
                expr = re.sub(r'(udp sport )' + sport + r'\b', lambda m: m[1] + dport, expr)
                expr = re.sub(r'(?<![\d.])' + re.escape(source) + r'(?![\d.])', dest, expr)
                commands.append('replace rule inet personal_host ' + chain + ' handle ' + handle + ' ' + expr)
        if commands:
            run(['nft', '-f', '-'], data=('\n'.join(commands) + '\n').encode())
        run(['ip', 'netns', 'exec', 'naive', 'nft', '-f', '/etc/wireguard/namespace.nft'])
        peer = f['old_peer'] if undo else f['new_peer']
        remove = f['new_peer'] if undo else f['old_peer']
        endpoint = f['old_endpoint'] if undo else new_ip + ':' + str(c['wg_port'])
        run(['ip', 'netns', 'exec', 'naive', 'wg', 'set', 'wg0', 'peer', remove, 'remove', 'peer', peer, 'allowed-ips', '0.0.0.0/0', 'endpoint', endpoint, 'persistent-keepalive', '25'])


def apply(c, role, request):
    f = probe(c, role)
    require(not f['pending'], 'Pending transaction: rollback or commit it first')
    require(f['machine_id'] == request['facts']['machine_id'], 'SSH target changed since preview')
    require(f['default_route'] == request['facts']['default_route'], 'Default route changed since preview')
    require(f.get('legacy_hashes') == request['facts'].get('legacy_hashes'), 'Legacy configuration changed since preview')
    out, changes = plan(c, role, f, request['keys'], request.get('clients'), request['templates'])
    if all(x['action'] == 'unchanged' for x in changes):
        return {'status': 'unchanged'}
    n = names(c)
    txdir = Path(n['state']) / 'transactions' / request['transaction']
    require(not txdir.exists(), 'Transaction id already exists')
    txdir.mkdir(parents=True, mode=0o700)
    for source in ('remote.py', 'render.py'):
        atomic(txdir / source, request['sources'][source])
    prior = {u: {'active': run(['systemctl', 'is-active', '--quiet', u], check=False).returncode == 0,
                 'enabled': run(['systemctl', 'is-enabled', '--quiet', u], check=False).returncode == 0} for u in units(c, role)}
    table = run(['nft', 'list', 'table', 'inet', n['table']], check=False)
    f['new_peer'] = request['keys']['exit']
    saved_files = {}
    for p in out:
        saved = snapshot(p)
        if saved:
            backup = hashlib.sha256(p.encode()).hexdigest()
            atomic(txdir / 'backups' / backup, base64.b64decode(saved.pop('data')))
            saved['backup'] = backup
        saved_files[p] = saved
    journal = {'config': c, 'role': role, 'facts': f, 'files': saved_files,
               'manifest': snapshot(n['state'] + '/manifest.json'), 'prior_units': prior,
               'nft': table.stdout.decode() if table.returncode == 0 else None,
               'forward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
               'phase': 'armed', 'new_hashes': {p: hashlib.sha256(v['content'].encode()).hexdigest() for p, v in out.items()}}
    atomic(txdir / 'journal.json', json.dumps(journal))
    atomic(n['state'] + '/pending.json', json.dumps({'transaction': request['transaction'], 'dir': str(txdir)}))
    try:
        arm_timer(c, txdir)
        if not (f['legacy'] and role == 'entry'):
            for directory in ['/etc/empire-vpn', n['base'], n['base'] + '/site']:
                Path(directory).mkdir(parents=True, exist_ok=True)
                os.chmod(directory, 0o755)
        for p, spec in out.items():
            atomic(p, spec['content'], spec['mode'], spec['group'])
        for p in out:
            if p.endswith('.sh'):
                run(['bash', '-n', p])
        if f['legacy']:
            run(['nft', '-c', '-f', '/etc/nftables.conf'])
        else:
            run(['nft', '-c', '-f', n['base'] + '/host.nft'])
        if role == 'entry' and not f['legacy']:
            run(['/opt/empire-vpn/bin/caddy', 'validate', '--config', n['base'] + '/Caddyfile', '--adapter', 'caddyfile'])
            run(['/opt/empire-vpn/bin/sing-box', 'check', '-c', n['base'] + '/sing-box.json'])
        if not (f['legacy'] and role == 'entry'):
            run(['systemd-analyze', 'verify'] + [p for p in out if p.endswith(('.service', '.socket'))])
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'stop', n['prefix'] + '-network.service'], check=False)
            run(['systemctl', 'restart', n['prefix'] + '-firewall.service'])
        if f['legacy']:
            legacy_runtime(c, role, f)
            if any(ch['path']=='/etc/naive/auth.caddy' and ch['action']=='update' for ch in changes):
                run(['systemctl','restart','naive-caddy.service'])
        if not (f['legacy'] and role == 'entry'):
            run(['systemctl', 'enable', '--now'] + units(c, role))
        journal['phase'] = 'applied'
        atomic(txdir / 'journal.json', json.dumps(journal))
        return {'status': 'applied', 'transaction': request['transaction'], 'rollback_minutes': 30}
    except BaseException:
        rollback_local(txdir)
        raise


def rollback_local(txdir):
    txdir = Path(txdir)
    j = readjson(txdir / 'journal.json')
    require(j is not None, 'Rollback journal missing')
    if j['phase'] == 'rolled-back':
        return {'status': 'already-rolled-back'}
    c, role, f = j['config'], j['role'], j['facts']
    n = names(c)
    # A later successful transaction must never be reverted by an older journal.
    pending = readjson(n['state'] + '/pending.json')
    manifest = readjson(n['state'] + '/manifest.json', {})
    require((pending and pending['dir'] == str(txdir)) or manifest.get('transaction') == txdir.name, 'Rollback is not the latest transaction')
    for p, saved in j['files'].items():
        original = hashlib.sha256(backup_bytes(txdir, saved)).hexdigest() if saved else None
        require(digest(p) in (None, original, j['new_hashes'][p]), 'Rollback refuses externally modified file: ' + p)
    if not (f['legacy'] and role == 'entry'):
        run(['systemctl', 'disable', '--now'] + list(reversed(units(c, role))), check=False)
        # socket-activated relays are not listed in enable set.
        if role == 'entry':
            run(['systemctl', 'stop', n['prefix'] + '-http.service', n['prefix'] + '-https.service'], check=False)
    for p, saved in j['files'].items():
        if saved is None:
            Path(p).unlink(missing_ok=True)
        else:
            atomic(p, backup_bytes(txdir, saved), saved['mode'])
            os.chown(p, saved['uid'], saved['gid'])
    if f['legacy']:
        legacy_runtime(c, role, f, undo=True)
        if '/etc/naive/auth.caddy' in j['files']:
            run(['systemctl', 'restart', 'naive-caddy.service'])
    if run(['nft', 'list', 'table', 'inet', n['table']], check=False).returncode == 0:
        run(['nft', 'delete', 'table', 'inet', n['table']])
    if j['nft']:
        run(['nft', '-f', '-'], data=j['nft'].encode())
    if role == 'exit':
        run(['sysctl', '-q', '-w', 'net.ipv4.ip_forward=' + j['forward']])
    mp = n['state'] + '/manifest.json'
    if j['manifest']:
        atomic(mp, base64.b64decode(j['manifest']['data']))
    else:
        Path(mp).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    for u, prior in j['prior_units'].items():
        if prior['enabled']:
            run(['systemctl', 'enable', u])
        if prior['active']:
            run(['systemctl', 'start', u])
    cancel_timer(c)
    Path(n['state'] + '/pending.json').unlink(missing_ok=True)
    j['phase'] = 'rolled-back'
    atomic(txdir / 'journal.json', json.dumps(j))
    return {'status': 'rolled-back'}


def commit(c, expected=None):
    n = names(c)
    pending = readjson(n['state'] + '/pending.json')
    require(pending is not None, 'No pending transaction')
    require(expected is None or pending['transaction'] == expected, 'Refusing to commit a different transaction')
    txdir = Path(pending['dir'])
    j = readjson(txdir / 'journal.json')
    require(j['phase'] == 'applied', 'Transaction did not finish applying')
    require(all(digest(p) == h for p, h in j['new_hashes'].items()), 'Files changed since apply')
    atomic(n['state'] + '/manifest.json', json.dumps({'schema_version': 1, 'files': j['new_hashes'], 'transaction': txdir.name, 'config': c, 'role': j['role']}))
    cancel_timer(c)
    Path(n['state'] + '/pending.json').unlink()
    j['phase'] = 'committed'
    atomic(txdir / 'journal.json', json.dumps(j))
    return {'status': 'committed'}


def dispatch(request):
    c = validate(request['config'])
    role = request['role']
    action = request['action']
    if action == 'network-options':
        routes = json.loads(text(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
        networks = [r['dst'] for r in routes if r.get('dst') not in (None, 'default', '0.0.0.0/0')]
        ports = []
        if role == 'exit':
            for line in text(['ss', '-H', '-lun']).splitlines():
                ports.append(int(line.split()[3].rsplit(':', 1)[1]))
            if shutil.which('wg'):
                ports.extend(int(line.split()[-1]) for line in text(['wg','show','all','listen-port']).splitlines())
        manifest = readjson(Path(names(c)['state']) / 'manifest.json', {})
        keep = {k: manifest['config'][k] for k in ('tunnel','relay','wg_port')} if manifest else {}
        if role == 'entry' and c[role]['kind'] == 'legacy':
            for k, dev in [('tunnel','wg0'), ('relay','vpn-app')]:
                links = json.loads(text(['ip','-n','naive','-j','-4','addr','show','dev',dev]))
                addr, = links[0]['addr_info']
                keep[k] = str(ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}").network)
        return {'networks': networks, 'ports': ports, 'keep': keep}
    if action == 'probe':
        return probe(c, role)
    if action == 'plan':
        f = probe(c, role)
        _, changes = plan(c, role, f, request['keys'], request.get('clients'), request['templates'])
        return {'changes': changes, 'facts': f}
    if action == 'health':
        actual = text(['ip', 'netns', 'exec', 'naive', 'curl', '-4', '-fsS', '--max-time', '25', 'https://api.ipify.org'])
        require(actual == c['exit']['address'], 'Namespace egress differs from expected exit IPv4')
        return {'namespace_egress': 'PASS', 'expected_ip': actual}
    if action == 'verify':
        return verification(c, request)
    if action == 'boot':
        return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'ordering_cycle': bool(re.search(r'ordering cycle|deleted to break', text(['journalctl', '-b', '--no-pager', '-o', 'cat'], check=False), re.I))}
    # Serialize all writes, including a rollback timer firing during a command.
    import fcntl
    os.umask(0o077)
    Path('/run/lock').mkdir(exist_ok=True)
    with open('/run/lock/empire-vpn.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'prepare':
            return prepare(c, role, request['versions'])
        if action == 'apply':
            return apply(c, role, request)
        if action == 'commit':
            return commit(c, request.get('transaction'))
        if action == 'rollback':
            n = names(c)
            pending = readjson(n['state'] + '/pending.json')
            tx = pending['transaction'] if pending else readjson(n['state'] + '/manifest.json', {}).get('transaction')
            require(tx is not None, 'No transaction to roll back')
            require(request.get('transaction') in (None, tx), 'Refusing to roll back a different transaction')
            return rollback_local(Path(n['state']) / 'transactions' / tx)
        if action == 'failure':
            require(role == 'entry', 'Failure test is entry-only')
            require(not readjson(names(c)['state'] + '/pending.json'), 'Commit deployment before failure testing')
            recover = 'ip -n naive link set wg0 up; ip -n naive route replace default dev wg0'
            timer = names(c)['prefix'] + '-test-recovery'
            run(['systemd-run', '--unit=' + timer, '--on-active=120s', '/bin/sh', '-c', recover])
            try:
                verification(c, dict(request, blocked=True), before_block=lambda: run(['ip', '-n', 'naive', 'link', 'set', 'wg0', 'down']))
            finally:
                run(['sh', '-c', recover])
                run(['systemctl', 'stop', timer + '.timer'], check=False)
            return verification(c, dict(request, blocked=False)) | {'fail_closed': 'PASS', 'recovery': 'PASS'}
        if action == 'reboot':
            require(not readjson(names(c)['state'] + '/pending.json'), 'Commit deployment before reboot testing')
            run(['systemd-run', '--unit=' + names(c)['prefix'] + '-reboot-test', '--on-active=3s', '/usr/bin/systemctl', 'reboot'])
            return {'status': 'reboot-scheduled'}
    raise Invalid('Unknown action')


def verification(c, request, before_block=None):
    import types
    module = types.ModuleType('verifier')
    exec(request['verifier'], module.__dict__)
    try:
        return module.verify(c, request['clients'], blocked=request.get('blocked', False), before_block=before_block)
    except RuntimeError as error:
        raise Invalid('Acceptance failed: ' + str(error)) from None


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'rollback-local':
            import fcntl
            with open('/run/lock/empire-vpn.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                result = rollback_local(sys.argv[2])
        else:
            result = dispatch(json.load(sys.stdin))
        print(json.dumps({'ok': True, 'result': result}))
    except (Exception, KeyboardInterrupt) as exc:
        # Deliberately hide third-party exceptions that may embed request/config data.
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}))
        sys.exit(1)
