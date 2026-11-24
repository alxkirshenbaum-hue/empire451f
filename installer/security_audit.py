"""Read-only deployment audit for fresh installer-managed nodes (Ubuntu, root)."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise RuntimeError(args[0] + " exit " + str(result.returncode))
    return result.stdout.strip()


def audit(role, ident):
    state = Path('/var/lib/empire-vpn') / ident
    manifest = json.loads((state / 'manifest.json').read_text())
    c = manifest['config']
    if manifest['role'] != role or c['id'] != ident or c[role]['kind'] == 'legacy':
        raise ValueError('Role, deployment ID or managed layout mismatch')
    base = Path('/etc/empire-vpn') / ident
    prefix = 'evpn-' + ident + '-'
    ns = ('ip', 'netns', 'exec', 'naive')
    failures = []

    def check(label, probe):
        try:
            ok = probe()
            detail = ''
        except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.TimeoutExpired) as error:
            ok, detail = False, ' (could not check: ' + type(error).__name__ + ')'
        print(('PASS' if ok else 'FAIL') + '  ' + role + '  ' + label + detail, flush=True)
        if not ok:
            failures.append(label)

    def routes(*args):
        return json.loads(run('ip', *args))

    def private(path):
        info = path.lstat()
        return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0

    def firewall(table, file, namespace=()):
        # Load a reference solely in an ephemeral, isolated network namespace.
        reference = run('unshare', '--net', 'sh', '-ec',
                        'nft -f "$1"; nft list table inet "$2"', 'audit', str(base / file), table)
        live = run(*namespace, 'nft', 'list', 'table', 'inet', table)
        return live == reference

    source, _, dest, port = os.environ['SSH_CONNECTION'].split()
    check('new public-key SSH session', lambda: True)  # enforced by launcher
    def ssh_policy():
        raw = run('/usr/sbin/sshd', '-T', '-C', f'user=root,addr={source},host={source},laddr={dest},lport={port}')
        settings = dict(row.split(' ', 1) for row in raw.splitlines() if ' ' in row)
        fields = ('passwordauthentication', 'kbdinteractiveauthentication', 'permitrootlogin')
        print('      ' + ' / '.join(key + '=' + settings[key] for key in fields))
        check('password and keyboard-interactive disabled for this connection',lambda: settings[fields[0]] == settings[fields[1]] == 'no')
        return settings[fields[2]] in ('without-password', 'prohibit-password') and settings['pubkeyauthentication'] == 'yes'
    check('root login explicitly restricted as in previous audit', ssh_policy)
    def uplink():
        dev = routes('-j','route','get',source)[0]['dev']
        defaults = routes('-j','route','show','default')
        return bool(defaults) and all(r.get('dev') in interfaces for r in defaults) and dev in interfaces
    interfaces = set(os.listdir('/sys/class/net')) - set(run('wg','show','interfaces').split()) - {'lo','eh'+ident,'ev'+ident}
    check('host default and route to SSH peer outside WireGuard', uplink)
    check('no pending deployment transaction', lambda: not (state/'pending.json').exists())
    check('deployment files match committed hashes', lambda: all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p,h in manifest['files'].items()))
    check('host firewall matches installed rules', lambda: firewall('evpn_'+ident, 'host.nft'))
    check('WireGuard private key root-only', lambda: private(Path('/etc/wireguard') / ('evpn-'+ident+'.key')))
    units = [prefix+'network.service',prefix+'firewall.service']
    if role == 'entry':
        units += [prefix+name for name in ('caddy.service','singbox.service','http.socket','https.socket')]
        check('namespace IPv4 default exclusively through wg0', lambda: [r.get('dev') for r in routes('-n','naive','-j','route','show','default')] == ['wg0'])
        check('namespace IPv6 disabled', lambda: run(*ns,'sysctl','-n','net.ipv6.conf.all.disable_ipv6') == '1')
        check('namespace firewall matches installed isolation rules', lambda: firewall('isolation','namespace.nft',ns))
        check('client export and generated profile root-only', lambda: all(private(state/name) for name in ('clients.json','master_user.sfa.json')))
        caddy = (base/'Caddyfile').read_text().splitlines()
        check('Caddy admin off, probe resistance and loopback upstream configured',lambda:
              set(('admin off','hide_ip','hide_via','probe_resistance','upstream http://127.0.0.1:1081')).issubset(line.strip() for line in caddy))
        def acme():
            keys = list(Path('/var/lib/empire-vpn-acme').rglob('*.key'))
            import pwd
            return bool(keys) and all(k.is_file() and not k.is_symlink() and k.stat().st_uid==pwd.getpwnam('evpn').pw_uid and k.stat().st_mode & 0o077 == 0 for k in keys)
        check('ACME keys accessible only to service owner',acme)
        def local_proxy():
            inside = run(*ns,'ss','-Hlnpt','sport = :1081').splitlines()
            return len(inside)==1 and '127.0.0.1:1081' in inside[0] and not run('ss','-Hlnt','sport = :1081')
        check('HTTP proxy listens only on namespace loopback',local_proxy)
        conf = json.loads((base/'sing-box.json').read_text())
        check('sing-box HTTP loopback, DNS and final outbound bound to WG', lambda:
              conf['inbounds'][0]['listen']=='127.0.0.1' and conf['inbounds'][0]['listen_port']==1081
              and conf['inbounds'][0]['type']=='http' and conf['route']['final']=='wg-only'
              and all(s.get('detour')=='wg-only' for s in conf['dns']['servers'])
              and conf['outbounds']==[{'type':'direct','tag':'wg-only','bind_interface':'wg0'}])
        def verify_live():
            result = verify(c,json.loads((state/'clients.json').read_text()))
            return result == {'TCP':'PASS','UoT_DNS':'PASS','IPv6_private':'BLOCKED','STUN_site_TLS':'PASS'}
        if 'verify' in globals():
            check('live VPN TCP, UoT DNS/STUN, expected egress and blocked private/IPv6 probes', verify_live)
        else:
            raise RuntimeError('Use the audit launcher with the pinned verifier')
        for svc, allowed in [('caddy',1<<10), ('singbox',1<<13)]:
            def process():
                pid = int(run('systemctl','show','-p','MainPID','--value',prefix+svc+'.service'))
                proc = Path('/proc')/str(pid)
                fields = dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
                return (os.stat(proc/'ns/net').st_ino == os.stat('/run/netns/naive').st_ino != os.stat('/proc/1/ns/net').st_ino
                        and all(int(uid)>0 for uid in fields['Uid'].split())
                        and fields['NoNewPrivs'].strip()=='1'
                        and all(int(fields[k],16) & ~allowed == 0 for k in ('CapEff','CapPrm','CapBnd','CapAmb'))
                        and (proc/'root/etc/resolv.conf').read_bytes()==Path('/etc/netns/naive/resolv.conf').read_bytes())
            check(svc+' actual namespace, DNS, UID and capability limits',process)
            check(svc+' restart policy',lambda: run('systemctl','show','--value','-p','Restart',prefix+svc+'.service')=='on-failure')
    else:
        entry_ip = c['entry']['address']
        domain = c['domain']
        def tls(version):
            context = ssl.create_default_context()
            context.minimum_version = context.maximum_version = version
            context.set_alpn_protocols(['h2'])
            with socket.create_connection((entry_ip,443),timeout=8) as raw, context.wrap_socket(raw,server_hostname=domain) as sock:
                return sock.selected_alpn_protocol()=='h2'
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            check(version.name+' trusted certificate and HTTP/2 from exit',lambda: tls(version))
        def refused_name(name):
            context = ssl.create_default_context()
            context.check_hostname = False
            with socket.create_connection((entry_ip,443),timeout=8) as raw:
                try:
                    with context.wrap_socket(raw,server_hostname=name):
                        return False
                except ssl.SSLCertVerificationError:
                    return False
                except ssl.SSLError as error:
                    return 'ALERT' in str(error.reason)
        check('TLS handshake refused without SNI and with unrelated SNI',lambda: all(refused_name(name) for name in (None,'unrelated.invalid')))
        def http_status(path):
            return run('curl','--noproxy','*','--resolve',domain+':443:'+entry_ip,'--max-time','10','-sS','-o','/dev/null','-w','%{http_code}','https://'+domain+path)
        check('site returns 200 and missing path returns 404',lambda: http_status('/')=='200' and http_status('/.audit-missing-'+os.urandom(8).hex())=='404')
        def connect_response(bad):
            headers=run('curl','--noproxy','*','--http1.1','--max-time','8','--resolve',domain+':443:'+entry_ip,
                        '-sS','-D','-','-o','/dev/null','-X','CONNECT','--request-target',entry_ip+':443',
                        *(('-H','Proxy-Authorization: Basic YXVkaXQ6aW52YWxpZA==') if bad else ()), 'https://'+domain+'/').lower()
            return (headers.splitlines()[0].split()[1], 'proxy-authenticate:' in headers, 'padding:' in headers)
        check('anonymous and invalid HTTP/1 CONNECT both concealed',lambda: connect_response(False)==connect_response(True)==('308',False,False))
        def exit_ssh_filter():
            chain=run('nft','-n','list','chain','inet','evpn_'+ident,'input')
            return any(('ip saddr '+entry_ip+' ') in line and ('tcp dport '+port+' accept') in line for line in chain.splitlines()) and not any(line.strip()=='tcp dport '+port+' accept' for line in chain.splitlines())
        check('installer exit firewall restricts SSH to entry IP',exit_ssh_filter)
        check('exit IPv4 forwarding',lambda: run('sysctl','-n','net.ipv4.ip_forward')=='1')
        check('exit WireGuard peer restricted to entry tunnel IP',lambda: run('wg','show','ev'+ident,'allowed-ips').split()[1:] == [str(ipaddress.ip_network(c['tunnel'])[2])+'/32'])
    check('services and sockets active and enabled',lambda: all(run('systemctl',cmd,u)==expected for u in units for cmd,expected in [('is-active','active'),('is-enabled','enabled')]))
    check('systemd dependency graph validates',lambda: run('systemd-analyze','verify',*units)=='')
    check('current boot journal clear of ordering-cycle messages',lambda: not re.search('ordering cycle|deleted to break',run('journalctl','-b','-p','warning','--no-pager','-o','cat'),re.I))
    return bool(failures)


if __name__ == '__main__':
    role, ident = sys.argv[1:]
    if role not in ('entry','exit') or not re.fullmatch('[a-z][a-z0-9]{2,9}',ident):
        sys.exit('Invalid role or deployment ID')
    try:
        sys.exit(int(audit(role, ident)))
    except Exception as error:
        sys.exit('Audit incomplete: '+type(error).__name__)
