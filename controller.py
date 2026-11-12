"""Runs exclusively on the entry VPS. Exit RPC is carried by two laptop SSH tunnels.

No SSH private key or agent forwarding is used on either VPS. The native launcher
opens a fresh SSH session to both nodes before asking this controller to commit.
"""
import base64
import contextlib
import datetime
import getpass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
import itertools
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
import threading
import urllib.request
import uuid

import remote
import delivery
import secrets
from render import Invalid, credentials, names, require, validate
from client import QUESTIONS, ask

BUNDLE = globals().get('BUNDLE', {})


def request(action, role, c, **extra):
    return {'action': action, 'role': role, 'config': c,
            'sources': {name: BUNDLE[name] for name in ('remote.py', 'render.py')},
            'templates': {name.split('/', 1)[1]: value for name, value in BUNDLE.items() if name.startswith('templates/')},
            'versions': json.loads(BUNDLE['versions.json']), 'verifier': BUNDLE['verify.py'], **extra}


class Nodes:
    def __init__(self, token, port):
        self.token = token
        self.port = int(port)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, role, action, c, **extra):
        label = role + ' / ' + action
        print(label, flush=True)
        done = threading.Event()
        def progress():
            started = time.monotonic()
            while not done.wait(20):
                print(f'{label}: running for {int(time.monotonic() - started)} seconds', flush=True)
        threading.Thread(target=progress, daemon=True).start()
        try:
            return self._execute(role, action, c, **extra)
        finally:
            done.set()

    def _execute(self, role, action, c, **extra):
        if role == 'entry':
            return remote.dispatch(request(action, role, c, **extra))
        payload = {'action': action, 'config': c, **extra}
        payload.pop('clients', None)  # Client passwords never need to reach the exit node.
        req = urllib.request.Request('http://127.0.0.1:' + str(self.port) + '/', data=json.dumps(payload).encode(),
                                     headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        timeout = {'prepare': 2400, 'apply': 1200, 'rollback': 1200, 'boot': 150, 'reboot': 150}.get(action, 300)
        try:
            with self.opener.open(req, timeout=timeout) as response:
                result = json.load(response)
        except OSError:
            raise Invalid('exit/' + action + ': connection lost or timed out. Operation result unconfirmed.') from None
        require(result.get('ok'), 'exit/' + action + ': ' + result.get('error', 'failed'))
        return result['result']


def rpc(port, token):
    require(re.fullmatch(r'[a-f0-9]{64}', token), 'Missing session authentication environment')
    deadline = time.monotonic() + 7200
    stopping = False

    class Handler(BaseHTTPRequestHandler):
        timeout = 15
        def log_message(self, *args):
            pass

        def do_POST(self):
            nonlocal stopping
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
                self.send_error(403)
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                require(0 < size < 100000, 'Request size rejected')
                data = json.loads(self.rfile.read(size))
                require(set(data) <= {'action', 'config', 'keys', 'facts', 'transaction'}, 'RPC fields rejected')
                if data['action'] == 'shutdown':
                    stopping = True
                    result = {'status': 'stopping'}
                else:
                    require(data['action'] in ('check-pair', 'network-options', 'probe', 'plan', 'prepare', 'apply', 'secure-apply', 'commit', 'rollback', 'boot', 'reboot'), 'RPC action rejected')
                    result = remote.dispatch(request(data.pop('action'), 'exit', data.pop('config'), **data))
                reply = {'ok': True, 'result': result}
            except BaseException as error:
                reply = {'ok': False, 'error': str(error) if isinstance(error, Invalid) else type(error).__name__}
            encoded = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    def stop(*args):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    with HTTPServer(('127.0.0.1', int(port)), Handler) as server:
        server.timeout = 1
        print('EVPN_RPC_READY', flush=True)
        while not stopping and time.monotonic() < deadline:
            server.handle_request()
    return 0


def session_path(session):
    require(re.fullmatch(r'[a-f0-9]{32}', session), 'Invalid session identifier')
    return Path('/var/lib/empire-vpn-sessions') / (session + '.json')


def store_session(session, value):
    p = session_path(session)
    p.parent.mkdir(exist_ok=True, mode=0o700)
    p.parent.chmod(0o700)
    remote.atomic(p, json.dumps(value))


def network_defaults(nodes, c, fixed):
    inventory = [nodes.call(r, 'network-options', c) for r in ('entry','exit')]
    keep = {}
    used = []
    for item in inventory:
        for k, value in item['keep'].items():
            require(k not in keep or keep[k] == value, 'Existing nodes disagree on ' + k)
            keep[k] = value
        for dst in item['networks']:
            used.append(ipaddress.IPv4Network(dst, strict=False))
    for k in ('tunnel', 'relay', 'wg_port'):
        if k in keep:
            c[k] = keep[k]
    fixed = set(fixed) | set(keep)
    used.extend(ipaddress.IPv4Network(c[k]) for k in ('tunnel','relay') if k in fixed)
    for k in ('tunnel','relay'):
        if k in fixed:
            continue
        preferred = ipaddress.IPv4Network(c[k])
        candidates = ipaddress.IPv4Network('10.203.0.0/16').subnets(new_prefix=30)
        net = next((n for n in itertools.chain([preferred], candidates) if not any(n.overlaps(u) for u in used)), None)
        require(net is not None, 'No free subnet in the automatic pool. Edit Q10 or Q11.')
        c[k] = str(net)
        used.append(net)
    if 'wg_port' not in fixed:
        busy = set(inventory[1]['ports'])
        port = next((p for p in range(c['wg_port'], 65536) if p not in busy), None)
        require(port is not None, 'No free exit port in the automatic range. Edit Q12.')
        c['wg_port'] = port
    return validate(c)


def configure(saved=None, nodes=None, imported=None):
    saved = saved or {}
    default = {'Q01': saved.get('mode', 'replace-entry'), 'Q02': saved.get('id', 'personal'),
               'Q04': saved.get('entry', {}).get('address', ''), 'Q06': saved.get('exit', {}).get('address', ''),
               'Q07': saved.get('domain', ''), 'Q08': 'legacy', 'Q10': saved.get('tunnel', '10.203.71.0/30'),
               'Q11': saved.get('relay', '10.203.72.0/30'), 'Q12': str(saved.get('wg_port', 51830)),
               'Q14': saved.get('username', delivery.MASTER), 'Q15': ','.join(saved.get('protected_addresses', [])), 'Q16': saved.get('tls', 'defer')}
    for role in ('entry', 'exit'):
        if saved.get(role, {}).get('kind') == 'managed':
            default['Q08'] = 'managed'
    answers = {}
    network_fields = {'Q10':'tunnel','Q11':'relay','Q12':'wg_port'}
    fixed = {k for k in network_fields.values() if k in saved}
    def preserved_kind(previous):
        if answers['Q01'] == 'fresh':
            return 'new'
        keep_exit = answers['Q01'] == 'replace-entry'
        role = 'exit' if keep_exit else 'entry'
        address = answers['Q06' if keep_exit else 'Q04']
        print(f'Keeping the current {role} server ({address}). How was it set up?')
        return ask('Q08', previous if previous in ('legacy', 'managed') else 'legacy')

    for q, value in default.items():
        if q == 'Q02':
            answers[q] = saved['id'] if 'id' in saved else deployment_id()
        elif q == 'Q08':
            answers[q] = preserved_kind(value)
        elif q in network_fields or (q == 'Q14' and imported):
            answers[q] = imported['clients'][0]['username'] if q == 'Q14' else value
        else:
            answers[q] = ask(q, value)
    while True:
        try:
            a = answers
            c = validate({'schema_version': 1, 'mode': a['Q01'], 'id': a['Q02'], 'domain': a['Q07'].lower(),
                          'entry': {'ssh': 'root@' + a['Q04'], 'address': a['Q04'], 'kind': a['Q08'] if a['Q01'] == 'replace-exit' else 'new'},
                          'exit': {'ssh': 'root@' + a['Q06'], 'address': a['Q06'], 'kind': a['Q08'] if a['Q01'] == 'replace-entry' else 'new'},
                          'tunnel': a['Q10'], 'relay': a['Q11'], 'wg_port': int(a['Q12']), 'username': a['Q14'],
                          'protected_addresses': [x.strip() for x in a['Q15'].split(',') if x.strip()], 'tls': a['Q16']})
            require(c['tls'] in ('ready', 'defer'), 'Q16: ready or defer')
            require(re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', c['username']), 'Q14: invalid username')
            if nodes:
                c = network_defaults(nodes, c, fixed)
            for question, field in network_fields.items():
                answers[question] = str(c[field])
            print('Network settings: Q10 tunnel =', c['tunnel'], '/ Q11 service link =', c['relay'], '/ Q12 exit UDP port =', c['wg_port'])
            print(json.dumps(c, ensure_ascii=False, indent=2))
            edit = ask('Q20', 'continue')
            if edit == 'continue':
                return c
        except (ValueError, KeyError) as error:
            print('Check your answers: ' + str(error))
            while True:
                edit = input('[Q20] The plan is not valid yet. Enter a question ID to correct (e.g. Q04), or stop: ').strip().upper()
                if edit == 'STOP':
                    raise Invalid('Stopped before applying changes.')
                if edit in answers:
                    break
                print('Enter one of: ' + ', '.join(answers))
        if edit in answers:
            if edit == 'Q14' and imported:
                print('Using imported client credentials. Q14 only applies when creating a client.')
            elif edit == 'Q08':
                answers[edit] = preserved_kind(answers[edit])
            else:
                previous = answers[edit]
                answers[edit] = deployment_id(previous) if edit == 'Q02' else ask(edit, previous)
                if edit in network_fields:
                    fixed.add(network_fields[edit])
                if edit == 'Q01' and previous != answers[edit]:
                    answers['Q08'] = preserved_kind('legacy')
        else:
            print('Enter a question ID to edit a server setting. SSH destinations, key and import path are selected on your computer.')


@contextlib.contextmanager
def installer_lock():
    import fcntl
    with open('/run/lock/empire-vpn.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


@contextlib.contextmanager
def installer_account_writer(c):
    with installer_lock():
        remote.require_installer_writer(remote.readjson(Path(names(c)['state']) / 'manifest.json') or {})
        yield


def clients(c, imported, create=False):
    if create:
        with installer_account_writer(c):
            return _clients(c, imported, True)
    return _clients(c, imported, False)


def _clients(c, imported, create):
    path = Path(names(c)['state']) / 'clients.json'
    old = remote.readjson(path)
    require(imported is not None or old is not None or not remote.readjson(Path(names(c)['state']) / 'manifest.json'),
            'Saved client export is missing; import existing credentials instead of generating replacements')
    if imported:
        result = credentials(imported)
        if old and not any(u['username'] == delivery.MASTER for u in result['clients']):
            result['clients'].extend(u for u in old['clients'] if u['username'] == delivery.MASTER)
        require(old is None or result == old, 'Imported clients differ; refusing silent credential rotation')
    elif old:
        result = credentials(old)
    elif not create:
        result = {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c['username'], 'password': 'PREVIEW-ONLY-NOT-A-CREDENTIAL'}]}
    else:
        password = '' if c['username'] == delivery.MASTER else getpass.getpass('[Q14-P] Client password (hidden; empty generates one): ')
        result = credentials({'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c['username'], 'password': password or secrets.token_urlsafe(32)}]})
    if not any(u['username'] == delivery.MASTER for u in result['clients']):
        result['clients'].append({'username': delivery.MASTER, 'password': secrets.token_urlsafe(32) if create else 'PREVIEW-ONLY-NOT-A-CREDENTIAL'})
    result = credentials(result)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        remote.atomic(path, json.dumps(result))
        print('Client export saved on entry: ' + str(path))
    return result


def verify(nodes, c, users):
    require(users['clients'][0]['password'] != 'PREVIEW-ONLY-NOT-A-CREDENTIAL', 'Provide existing credentials for verification')
    print(nodes.call('entry', 'verify', c, clients=users))


def abort(nodes, state):
    errors = []
    for role in reversed(state.get('changed', [])):
        try:
            print(role + ': ' + nodes.call(role, 'rollback', state['config'], transaction=state.get('transaction'))['status'])
        except BaseException:
            errors.append(role)
    if errors:
        print('Rollback unconfirmed: ' + ','.join(errors) + '. Check rollback timers in the provider consoles.')


def explain_plan(c, plans):
    print('\nWhat applying this plan means')
    preserved = {'replace-entry': 'exit', 'replace-exit': 'entry'}.get(c['mode'])
    for role in ('entry', 'exit'):
        node = c[role]
        changes = plans[role]['changes']
        label = 'Existing' if role == preserved else 'Target'
        print(f"  {label} {role} ({node['address']}):")
        if all(item['action'] == 'unchanged' for item in changes):
            print('    The reviewed configuration files already match.')
        elif node['kind'] == 'legacy' and role == 'exit':
            print(f"    Add a separate tunnel for the new entry using UDP {c['wg_port']}. Keep the original tunnel, its peer and the exit WireGuard key.")
            if any(i['path'] == '/etc/nftables.conf' and i['action'] == 'update' for i in changes):
                print('    Update the live firewall and /etc/nftables.conf with rules for the additional tunnel. Keep the existing rules.')
        elif node['kind'] == 'legacy':
            print('    Switch the existing WireGuard peer and firewall rules to the new exit. Keep the entry WireGuard key, proxy services and client credentials.')
        elif role == 'entry':
            print(f"    Configure the HTTPS site for {c['domain']}, Caddy, sing-box and isolated VPN routing to the exit.")
        else:
            print(f"    Configure the WireGuard peer, forwarding and firewall for traffic from {c['entry']['address']}.")
        if role == preserved and node['kind'] == 'managed':
            print('    Keep the node key. The file list above shows which installer-managed settings will change.')
    if preserved:
        old = 'entry' if preserved == 'exit' else 'exit'
        print(f'  Only the two addresses above are deployment targets. There is no step to remove files or stop services on a separate former {old}.')
    print('  DNS and client profiles already on your devices stay as they are. Q24 offers a new profile for the reviewed domain after commit.')
    print('  Before commit: open fresh SSH sessions to both nodes and check the VPN exit IP.')
    print('  HTTPS and client traffic checks: ' + ('deferred until you run verify after DNS is ready.' if c['tls'] == 'defer' else 'included before commit.'))


def start(nodes, session, imported, resume_id=None):
    if resume_id:
        require(re.fullmatch('[a-z][a-z0-9]{2,9}',resume_id),'Invalid deployment ID')
        saved = remote.readjson('/var/lib/empire-vpn/' + resume_id + '/deployment.json')
        require(saved and saved.get('id') == resume_id,'Installation not found on entry. Check the entry alias and deployment ID.')
        for role in ('entry','exit'):
            nodes.call(role,'check-pair',saved)
        print('Saved installation:',resume_id,'|',saved['domain'])
    print('Connected. The wizard is running on the entry server.')
    actions = {
        'preview': 'See what would change, then exit without installing',
        'new': 'Set up new servers or replace an entry or exit',
        'apply-saved': 'Apply saved settings (change domain or other settings of existing VPN, retry a previous installation)',
        'verify': 'Check that the site and VPN work (use after switching DNS)',
        'rollback': 'Undo the last installation changes on both servers',
        'acceptance': 'Test that traffic stops if the tunnel fails (briefly disconnects WireGuard)',
        'reboot-test': 'Restart both servers in turn and check that the VPN recovers',
        'ssh-security': 'Secure SSH on an installed VPN (keys only or exit access through entry)',
    }
    print('[Q00] What would you like to do on this run?')
    numbers = {}
    for number, (name, description) in enumerate(actions.items(), 1):
        numbers[str(number)] = name
        print(f'  {number}  {description} ({name})')
    while True:
        answer = input('[Q00] Enter a number or action name [1]: ').removeprefix('\x1b[200~').removesuffix('\x1b[201~').strip().lower() or '1'
        action = numbers.get(answer, answer)
        if action in actions:
            break
        print('Choose a listed number or action name.')
    if action == 'new':
        c = configure(nodes=nodes, imported=imported)
    elif action == 'preview':
        ident = resume_id or deployment_id()
        saved = remote.readjson('/var/lib/empire-vpn/' + ident + '/deployment.json')
        c = configure(saved or {'id': ident}, nodes, imported)
    else:
        while True:
            ident = resume_id or deployment_id()
            saved = remote.readjson('/var/lib/empire-vpn/' + ident + '/deployment.json')
            if saved is not None:
                break
            require(not resume_id, 'Saved deployment disappeared; relaunch with the correct ID')
            print('No saved deployment with this ID on entry. Enter another ID or press Ctrl+C to stop.')
        if action == 'apply-saved':
            print(f"Editing {ident}. Current domain: {saved['domain']}. Press Enter to keep each saved answer.")
            print("To change the domain, enter its new name at Q07. At Q16 choose whether DNS already points here. Review the plan before typing APPLY.")
            c = configure(saved, nodes, imported)
        else:
            c = validate(saved)
    users = clients(c, imported)
    state = {'config': c, 'changed': [], 'action': action}
    if action == 'ssh-security':
        state['committed'] = True
        store_session(session,state)
        return finish(nodes,session,'secure')
    if action == 'rollback':
        require(input('Roll back both nodes? Type ROLLBACK: ') == 'ROLLBACK', 'Cancelled')
        for role in ('entry', 'exit'):
            print(role, nodes.call(role, 'rollback', c))
        return 0
    if action in ('verify', 'acceptance', 'reboot-test'):
        verify(nodes, c, users)
        if action == 'acceptance':
            require(input('Test entry WireGuard failure? Type FAIL-CLOSED: ') == 'FAIL-CLOSED', 'Cancelled')
            print(nodes.call('entry', 'failure', c, clients=users))
        if action == 'reboot-test':
            require(input('Reboot exit and entry in sequence? Type REBOOT: ') == 'REBOOT', 'Cancelled')
            state['boots'] = {r: nodes.call(r, 'boot', c)['boot_id'] for r in ('entry', 'exit')}
            store_session(session, state)
            nodes.call('exit', 'reboot', c)
            return 44
        return 0
    facts = {r: nodes.call(r, 'probe', c) for r in ('entry', 'exit')}
    require(facts['entry']['machine_id'] != facts['exit']['machine_id'], 'Both SSH connections reach the same machine')
    require(not any(f['pending'] for f in facts.values()), 'Pending transaction; run rollback before retry')
    keys = {r: facts[r].get('public_key', ('A' if r == 'entry' else 'B') * 43 + '=') for r in facts}
    plans = {r: nodes.call(r, 'plan', c, keys=keys, clients=users) for r in facts}
    print('Packages: wireguard-tools nftables iproute2 ca-certificates curl python3; entry also uses git, build-essential and pinned Go, Caddy and sing-box.')
    print('Missing WireGuard keys are generated on their nodes. Network rollback timer: 30 minutes.')
    for role, p in plans.items():
        print(f"\nPlanned files on {role} ({c[role]['address']}):")
        for item in p['changes']:
            print('  ' + item['action'] + ' ' + item['path'])
    explain_plan(c, plans)
    print('Entry: enable the master_user VPN login. After commit, the terminal will display its password and offer a private Android profile and an optional static-site ZIP.')
    if action == 'preview':
        print('PREVIEW: no installation changes applied.')
        return 0
    while True:
        confirmation = ask('Q19')
        if confirmation == 'APPLY':
            break
        if confirmation.lower() in ('', 'stop', 'cancel', 'no'):
            print('Stopped before applying changes.')
            return 0
        print('Type APPLY to proceed or stop to leave the wizard.')
    users = clients(c, imported, create=True)
    remote.atomic(Path(names(c)['state']) / 'deployment.json', json.dumps(c))
    for role in ('entry', 'exit'):
        if role == 'entry' and c[role]['kind'] != 'legacy':
            print('entry: checking proxy components; Caddy is built here if needed.', flush=True)
        else:
            print(role + ': checking network packages and the WireGuard key.', flush=True)
        keys[role] = nodes.call(role, 'prepare', c)['public_key']
    transaction = uuid.uuid4().hex
    state['transaction'] = transaction
    try:
        for role in ('exit', 'entry'):
            p = nodes.call(role, 'plan', c, keys=keys, clients=users)
            result = nodes.call(role, 'apply', c, keys=keys, clients=users, facts=p['facts'], transaction=transaction)
            if result['status'] == 'applied':
                state['changed'].append(role)
            store_session(session, state)
            print(role + ': ' + result['status'])
        print('Changes applied. Opening fresh SSH sessions before committing.')
        return 42
    except BaseException:
        abort(nodes, state)
        raise


def deployment_id(default='personal'):
    while True:
        ident = ask('Q02', default)
        if re.fullmatch(r'[a-z][a-z0-9]{2,9}', ident):
            return ident
        if len(ident) > 10:
            reason = f'ID is too long: {len(ident)} characters (maximum 10).'
        elif len(ident) < 3:
            reason = f'ID is too short: {len(ident)} characters (minimum 3).'
        elif not re.match('[a-z]', ident):
            reason = 'ID must start with a lowercase letter (a-z).'
        else:
            reason = 'ID contains an invalid character. Use only a-z and 0-9.'
        print(reason + ' Please enter the deployment ID again.')


def finish(nodes, session, operation):
    state = remote.readjson(session_path(session))
    require(state is not None, 'Session state missing; timers remain armed')
    c = state['config']
    if operation == 'secure':
        require(state.get('committed'), 'Finish deployment first')
        if any(c[r]['kind']=='legacy' for r in ('entry','exit')):
            print('Post-install SSH options apply to installer-managed nodes only.')
            return 0
        def yes(prompt):
            while True:
                answer = input(prompt + ' [y/N]: ').strip().lower()
                if answer in ('','no','n','yes','y'):
                    return answer in ('yes','y')
        if not yes('[Q26] Can you open a recovery console for BOTH servers from their provider panels if SSH fails?'):
            return 0
        policy = {}
        if yes('[Q27] Require public-key SSH on both servers and disable password and keyboard-interactive login for all users?'):
            policy['key_only'] = True
        facts = {r:nodes.call(r,'probe',c) for r in ('entry','exit')}
        require(all(facts[r]['owned'] and not facts[r]['pending'] for r in facts), 'Both roles need committed manifests and no pending transaction')
        if facts['exit']['admin_ip'] == c['entry']['address']:
            if yes('[Q28] Allow new SSH connections on the exit only from entry ' + c['entry']['address'] + '? Future SSH to exit must use this hop.'):
                policy['entry_only'] = True
        else:
            print('Q28 skipped: the current exit SSH connection does not come from this entry. Use ProxyJump via entry to enable this restriction.')
        if not policy:
            return 0
        c = dict(c, security=policy)
        keys = {r:facts[r]['public_key'] for r in facts}
        users = clients(c,None)
        state.update(config=c, changed=[], transaction=uuid.uuid4().hex)
        store_session(session,state)
        try:
            for r in ('exit','entry'):
                result=nodes.call(r,'secure-apply',c,keys=keys,clients=users,facts=facts[r],transaction=state['transaction'])
                if result['status']=='applied':
                    state['changed'].append(r)
                store_session(session,state)
            return 47 if state['changed'] else 0
        except BaseException:
            abort(nodes,state)
            raise
    if operation == 'confirm-security':
        require(state.get('committed'), 'Finish deployment first')
        for r in state['changed']:
            nodes.call(r,'commit',c,transaction=state['transaction'])
        remote.atomic(Path(names(c)['state'])/'deployment.json',json.dumps(c))
        print('SSH policy committed after fresh key logins to both servers.')
        return 0
    if operation == 'publish-site':
        require(state.get('committed'), 'Website upload requires a committed deployment')
        archive = session_path(session).with_suffix('.zip')
        try:
            if c['entry']['kind'] == 'legacy':
                base = Path('/var/www/empire-tomorrow')
                require(str(base / 'current') in Path('/etc/naive/Caddyfile').read_text(), 'Unrecognised legacy site root')
                delivery.publish_site(archive, base/'releases', base/'current', legacy=True)
            else:
                base = Path(names(c)['base'])
                delivery.publish_site(archive, base/'site-releases', base/'site-current')
            print('Site published: https://' + c['domain'] + '/')
            return 0
        except Exception:
            print('Site ZIP rejected or could not be published. The previous site is still active.', file=sys.stderr)
            return 1
        finally:
            archive.unlink(missing_ok=True)
    users = clients(c, None)
    if operation == 'abort':
        abort(nodes, state)
        return 1
    if operation == 'after-exit-reboot':
        boot = nodes.call('exit', 'boot', c)
        require(boot['boot_id'] != state['boots']['exit'] and not boot['ordering_cycle'], 'Exit cold-start check failed')
        verify(nodes, c, users)
        nodes.call('entry', 'reboot', c)
        return 45
    if operation == 'after-entry-reboot':
        boot = nodes.call('entry', 'boot', c)
        require(boot['boot_id'] != state['boots']['entry'] and not boot['ordering_cycle'], 'Entry cold-start check failed')
        verify(nodes, c, users)
        print('REBOOT ACCEPTANCE PASS')
        return 0
    require(operation == 'finish', 'Unknown completion operation')
    try:
        print(nodes.call('entry', 'health', c))
        if c.get('tls') == 'ready':
            verify(nodes, c, users)
        for role in state['changed']:
            print(role + ': ' + nodes.call(role, 'commit', c, transaction=state['transaction'])['status'])
        print('Deployment committed.' + (' TLS verification deferred. Run verify after DNS is ready.' if c.get('tls') == 'defer' else ' HTTPS/TCP/UoT checks passed.'))
    except BaseException:
        abort(nodes, state)
        raise
    state['committed'] = True
    store_session(session,state)
    handoff_profile(c, users, session)
    return 0


def handoff_profile(c, users, session):
    user = next(u for u in users['clients'] if u['username'] == delivery.MASTER)
    content = delivery.profile(BUNDLE['templates/sfa-profile.json'], c, user['password'])
    path = Path(names(c)['state']) / 'master_user.sfa.json'
    with installer_account_writer(c):
        remote.atomic(path,json.dumps(content,indent=2))
    local_copy = session_path(session).with_suffix('.profile.json')
    if local_copy.is_symlink():
        require(local_copy.resolve()==path,'Profile pointer conflict')
    else:
        local_copy.symlink_to(path)
    print('VPN login: master_user')
    if sys.stdout.isatty():
        print('VPN password (private): ' + user['password'])
    print('Private client profile on entry: ' + str(path))
    print('Android: import the JSON in sing-box for Android (SFA), SagerNet releases: ' + delivery.RELEASES)
    print('TUN + TLS/443 + UoT v2. The entry name is resolved via direct HTTPS DNS. Other DNS uses HTTPS via VPN. Russian destinations, local networks and most Android Download Manager traffic go direct; other traffic uses VPN.')
    print('Planned VPN-only management URL: ' + delivery.PANEL + ' (reserved; panel not deployed).')


def main(argv):
    token = os.environ.pop('LC_EVPN_TOKEN', '')
    session = os.environ.pop('LC_EVPN_SESSION', '')
    imported_raw = os.environ.pop('LC_EVPN_CLIENTS', '')
    require(re.fullmatch(r'[a-f0-9]{64}', token), 'Session environment missing; SSH AcceptEnv LC_* required')
    if argv[0] == 'rpc':
        return rpc(int(argv[1]), token)
    require(len(argv) == 3, 'Expected wizard RELAY_PORT OPERATION')
    nodes = Nodes(token, argv[1])
    try:
        try:
            imported = credentials(json.loads(base64.b64decode(imported_raw, validate=True))) if imported_raw else None
        except (Invalid, ValueError, AttributeError, TypeError):
            print('Q13: invalid v1 client export. Select another file.', file=sys.stderr)
            return 46
        if argv[2].startswith('resume-'):
            return start(nodes,session,None,argv[2][7:])
        return start(nodes, session, imported) if argv[2] == 'start' else finish(nodes, session, argv[2])
    except (Invalid, KeyboardInterrupt, EOFError) as error:
        print(str(error) if isinstance(error, Invalid) else 'Interrupted. Check pending transactions if apply had started.', file=sys.stderr)
        return 1
    except ValueError:
        print('Invalid input format.', file=sys.stderr)
        return 1
