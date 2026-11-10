"""Pure, side-effect-free validation and rendering. No keys generated here."""
import copy
import ipaddress
import json
import re
from string import Template

PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3']


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        raise Invalid('Expected an IPv4 address') from None


def validate(config):
    c = copy.deepcopy(config)
    require(c.get('schema_version') == 1, 'Unsupported deployment schema')
    require(c.get('mode') in ('fresh', 'replace-entry', 'replace-exit'), 'Unknown mode')
    require(re.fullmatch(r'[a-z][a-z0-9]{2,9}', c.get('id', '')), 'id: 3-10 lowercase letters/digits')
    require(re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', c.get('domain', '')), 'Invalid domain')
    for role in ('entry', 'exit'):
        n = c[role]
        n['address'] = ipv4(n['address'])
        require(re.fullmatch(r'[A-Za-z0-9_.@:-]+', n['ssh']) and not n['ssh'].startswith('-'), 'Invalid SSH destination')
        require(n.get('kind', 'new') in ('new', 'managed', 'legacy'), 'Invalid node kind')
        n.setdefault('kind', 'new')
    require(c['entry']['address'] != c['exit']['address'], 'Nodes must differ')
    c['protected_addresses'] = [ipv4(x) for x in c.get('protected_addresses', [])]
    require(not any(c[r]['address'] in c['protected_addresses'] for r in ('entry', 'exit')), 'Protected address cannot be a deployment target')
    if c['mode'] == 'fresh':
        require(all(c[r]['kind'] != 'legacy' for r in ('entry', 'exit')), 'fresh cannot adopt legacy nodes')
    if c['mode'] == 'replace-entry':
        require(c['entry']['kind'] != 'legacy', 'Replacement entry must be new or managed')
    if c['mode'] == 'replace-exit':
        require(c['exit']['kind'] != 'legacy', 'Replacement exit must be new or managed')
    for name, default in [('tunnel', '10.203.71.0/30'), ('relay', '10.203.72.0/30')]:
        c.setdefault(name, default)
        try:
            net = ipaddress.IPv4Network(c[name])
            require(net.prefixlen == 30 and net.is_private, name + ' must be private /30')
        except ValueError:
            raise Invalid(name + ' must be a network /30') from None
    require(not ipaddress.ip_network(c['tunnel']).overlaps(ipaddress.ip_network(c['relay'])), 'Subnets overlap')
    c.setdefault('wg_port', 51830)
    require(type(c['wg_port']) is int and 1024 <= c['wg_port'] <= 65535, 'Invalid WG port')
    c.setdefault('mtu', 1380)
    require(type(c['mtu']) is int and 1280 <= c['mtu'] <= 1420, 'Invalid MTU')
    c.setdefault('dns', '1.1.1.1')
    c['dns'] = ipv4(c['dns'])
    require(not any(ipaddress.ip_address(c['dns']) in ipaddress.ip_network(p) for p in PRIVATE), 'DNS must be public')
    c['blocked_ips'] = sorted(set(ipv4(x) for x in c.get('blocked_ips', []) + c['protected_addresses']) | {c['entry']['address'], c['exit']['address']})
    return c


def credentials(value):
    require(value.get('format') == 'empire-vpn-clients' and value.get('schema_version') == 1, 'Unsupported client export format')
    require(isinstance(value.get('clients'), list) and 0 < len(value['clients']) <= 100, 'Expected 1-100 clients')
    names = set()
    for user in value['clients']:
        require(set(user) == {'username', 'password'}, 'Client fields must be username/password')
        require(isinstance(user['username'], str) and re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', user['username']), 'Invalid client username')
        # Caddyfile JSON-style quoted tokens support printable ASCII including spaces.
        require(isinstance(user['password'], str) and 1 <= len(user['password']) <= 256 and all(32 <= ord(x) < 127 for x in user['password']), 'Password must contain 1-256 printable ASCII characters')
        require('{$' not in user['password'], 'Password cannot contain Caddy environment expansion sequence')
        require(user['username'] not in names, 'Duplicate client username')
        names.add(user['username'])
    return copy.deepcopy(value)


def names(c):
    ident = c['id']
    return {'prefix': 'evpn-' + ident, 'table': 'evpn_' + ident,
            'exit_if': 'ev' + ident, 'host_if': 'eh' + ident, 'app_if': 'ea' + ident,
            'base': '/etc/empire-vpn/' + ident,
            'state': '/var/lib/empire-vpn/' + ident}


def addresses(c):
    t = list(ipaddress.ip_network(c['tunnel']).hosts())
    r = list(ipaddress.ip_network(c['relay']).hosts())
    return str(t[0]), str(t[1]), str(r[0]), str(r[1])


def file(content, mode=0o644, group='root'):
    return {'content': content.rstrip() + '\n', 'mode': mode, 'group': group}


def render(c, role, facts, public_keys, clients, templates):
    c = validate(c)
    require(role in ('entry', 'exit'), 'Invalid role')
    n = names(c)
    dev = facts['interface']
    require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', dev), 'Invalid detected interface')
    sshport = int(facts['ssh_port'])
    require(1 <= sshport <= 65535, 'Invalid detected SSH port')
    for key in public_keys.values():
        require(re.fullmatch(r'[A-Za-z0-9+/]{43}=', key), 'Invalid WG public key')
    tx, te, rh, ra = addresses(c)
    deny = PRIVATE + [x + '/32' for x in c['blocked_ips']]
    subst = dict(n, role=role, interface=dev, ssh_port=sshport,
                 exit_addr=c['exit']['address'], entry_addr=c['entry']['address'],
                 wg_port=c['wg_port'], mtu=c['mtu'], tx=tx, te=te, rh=rh, ra=ra,
                 dns=c['dns'], domain=c['domain'], deny=', '.join(deny),
                 peer=public_keys['exit' if role == 'entry' else 'entry'],
                 key_path=facts.get('key_path', n['state'] + '/wireguard.key'))
    def tpl(name, **extra):
        return Template(templates[name]).substitute(subst | extra)
    out = {}
    base = n['base']
    out[base + '/network.sh'] = file(tpl('network-' + role + '.sh'), 0o700)
    out[base + '/host.nft'] = file(tpl('host-' + role + '.nft', policy='accept' if facts.get('legacy') else 'drop'))
    out[base + '/firewall.sh'] = file('#!/bin/bash\nset -euo pipefail\n{\n if nft list table inet ' + n['table'] + ' >/dev/null 2>&1; then echo "delete table inet ' + n['table'] + '"; fi\n cat ' + base + '/host.nft\n} | nft -f -', 0o700)
    out['/etc/systemd/system/' + n['prefix'] + '-firewall.service'] = file(tpl('firewall.service'))
    out['/etc/systemd/system/' + n['prefix'] + '-network.service'] = file(tpl('network.service'))
    if role == 'entry':
        credentials(clients)
        out[base + '/namespace.nft'] = file(tpl('namespace.nft'))
        out['/etc/netns/naive/resolv.conf'] = file('nameserver ' + c['dns'] + '\noptions timeout:2 attempts:2')
        out[base + '/auth.caddy'] = file('\n'.join('basic_auth ' + json.dumps(x['username']) + ' ' + json.dumps(x['password']) for x in clients['clients']), 0o640, 'evpn')
        out[base + '/Caddyfile'] = file(tpl('Caddyfile'), 0o640, 'evpn')
        sb = {'log': {'disabled': True}, 'dns': {'servers': [{'type': 'udp', 'tag': 'resolver', 'server': c['dns'], 'detour': 'wg-only'}], 'strategy': 'ipv4_only'},
              'inbounds': [{'type': 'http', 'tag': 'uot', 'listen': '127.0.0.1', 'listen_port': 1081}],
              'outbounds': [{'type': 'direct', 'tag': 'wg-only', 'bind_interface': 'wg0'}],
              'route': {'default_domain_resolver': 'resolver', 'rules': [{'action': 'resolve', 'strategy': 'ipv4_only'}, {'ip_cidr': deny + ['::/0'], 'action': 'reject'}], 'final': 'wg-only'}}
        out[base + '/sing-box.json'] = file(json.dumps(sb, indent=2), 0o640, 'evpn')
        out[base + '/site/index.html'] = file('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Personal space</title><h1>Personal space</h1><p>Notes and projects.</p></html>')
        for svc in ('caddy', 'singbox'):
            out['/etc/systemd/system/' + n['prefix'] + '-' + svc + '.service'] = file(tpl(svc + '.service'))
        for proto, port in [('http', 80), ('https', 443)]:
            for ext in ('socket', 'service'):
                out['/etc/systemd/system/' + n['prefix'] + '-' + proto + '.' + ext] = file(tpl('relay.' + ext, port=port))
    return out


def change_plan(desired, existing, owned):
    """existing maps paths to fingerprints; owned is last successful manifest."""
    import hashlib
    result = []
    for path, spec in sorted(desired.items()):
        digest = hashlib.sha256(spec['content'].encode()).hexdigest()
        current = existing.get(path)
        if current is not None and (path not in owned or current != owned[path]):
            raise Invalid('Unknown or externally modified file: ' + path)
        result.append({'path': path, 'action': 'unchanged' if current == digest else ('create' if current is None else 'update')})
    return result
