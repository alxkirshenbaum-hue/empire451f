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
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
import urllib.request
import uuid

import remote
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
        if role == 'entry':
            return remote.dispatch(request(action, role, c, **extra))
        payload = {'action': action, 'config': c, **extra}
        payload.pop('clients', None)  # Client passwords never need to reach the exit node.
        req = urllib.request.Request('http://127.0.0.1:' + str(self.port) + '/', data=json.dumps(payload).encode(),
                                     headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=5400) as response:
            result = json.load(response)
        require(result.get('ok'), 'exit/' + action + ': ' + result.get('error', 'failed'))
        return result['result']


def rpc(port, token):
    require(re.fullmatch(r'[a-f0-9]{64}', token), 'Missing session authentication environment')
    deadline = time.monotonic() + 7200
    stopping = False

    class Handler(BaseHTTPRequestHandler):
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
                    require(data['action'] in ('probe', 'plan', 'prepare', 'apply', 'commit', 'rollback', 'boot', 'reboot'), 'RPC action rejected')
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


def configure(saved=None):
    saved = saved or {}
    default = {'Q01': saved.get('mode', 'replace-entry'), 'Q02': saved.get('id', 'personal'),
               'Q04': saved.get('entry', {}).get('address', ''), 'Q06': saved.get('exit', {}).get('address', ''),
               'Q07': saved.get('domain', ''), 'Q08': 'legacy', 'Q10': saved.get('tunnel', '10.203.71.0/30'),
               'Q11': saved.get('relay', '10.203.72.0/30'), 'Q12': str(saved.get('wg_port', 51830)),
               'Q14': saved.get('username', 'owner'), 'Q15': ','.join(saved.get('protected_addresses', [])), 'Q16': saved.get('tls', 'defer')}
    for role in ('entry', 'exit'):
        if saved.get(role, {}).get('kind') == 'managed':
            default['Q08'] = 'managed'
    answers = {q: ask(q, value) for q, value in default.items()}
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
            print(json.dumps(c, ensure_ascii=False, indent=2))
            edit = ask('Q20', 'continue')
            if edit == 'continue':
                return c
        except (ValueError, KeyError) as error:
            print('Проверьте ответы: ' + str(error))
            edit = ask('Q20', 'Q01')
        if edit in answers:
            answers[edit] = ask(edit, answers[edit])
        else:
            print('SSH-адреса/ключ/локальный импорт задаются запуском на компьютере; остальные ответы исправьте по Qxx.')


def clients(c, imported, create=False):
    path = Path(names(c)['state']) / 'clients.json'
    old = remote.readjson(path)
    require(imported is not None or old is not None or not remote.readjson(Path(names(c)['state']) / 'manifest.json'),
            'Saved client export is missing; import existing credentials instead of generating replacements')
    if imported:
        result = credentials(imported)
        require(old is None or result == old, 'Imported clients differ; refusing silent credential rotation')
    elif old:
        result = credentials(old)
    elif not create:
        result = {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c['username'], 'password': 'PREVIEW-ONLY-NOT-A-CREDENTIAL'}]}
    else:
        import secrets
        password = getpass.getpass('[Q14-P] Пароль клиента (пусто — случайный): ')
        result = credentials({'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c['username'], 'password': password or secrets.token_urlsafe(32)}]})
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        remote.atomic(path, json.dumps(result))
        print('Экспорт учётных данных сохранён на входной VDS: ' + str(path))
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
        print('Откат не подтверждён: ' + ','.join(errors) + '; остаются серверные таймеры, проверьте консоли.')


def start(nodes, session, imported):
    print('Установщик выполняется на входной VDS. Ключи SSH остаются на компьютере; агент SSH не перенаправляется.')
    action = input('[Q00] new / apply-saved / preview / verify / rollback / acceptance / reboot-test [new]: ').strip() or 'new'
    require(action in ('new', 'apply-saved', 'preview', 'verify', 'rollback', 'acceptance', 'reboot-test'), 'Unknown action')
    if action == 'new':
        c = configure()
    elif action == 'preview':
        ident = ask('Q02', 'personal')
        require(re.fullmatch(r'[a-z][a-z0-9]{2,9}', ident), 'Invalid ID')
        saved = remote.readjson('/var/lib/empire-vpn/' + ident + '/deployment.json')
        c = configure(saved or {'id': ident})
    else:
        ident = ask('Q02', 'personal')
        require(re.fullmatch(r'[a-z][a-z0-9]{2,9}', ident), 'Invalid ID')
        saved = remote.readjson('/var/lib/empire-vpn/' + ident + '/deployment.json')
        require(saved is not None, 'No saved deployment on this entry VPS; choose new')
        c = configure(saved) if action == 'apply-saved' else validate(saved)
    users = clients(c, imported)
    state = {'config': c, 'changed': [], 'action': action}
    if action == 'rollback':
        require(input('Откатить последнюю транзакцию обеих нод? Введите ROLLBACK: ') == 'ROLLBACK', 'Cancelled')
        for role in ('entry', 'exit'):
            print(role, nodes.call(role, 'rollback', c))
        return 0
    if action in ('verify', 'acceptance', 'reboot-test'):
        verify(nodes, c, users)
        if action == 'acceptance':
            require(input('Отказной тест WG входа: введите FAIL-CLOSED: ') == 'FAIL-CLOSED', 'Cancelled')
            print(nodes.call('entry', 'failure', c, clients=users))
        if action == 'reboot-test':
            require(input('Поочерёдный reboot выхода/входа: введите REBOOT: ') == 'REBOOT', 'Cancelled')
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
    print('Пакеты: wireguard-tools nftables iproute2 ca-certificates curl python3; вход также git build-essential и закреплённые Go/Caddy/sing-box.')
    print('Действующая нода сохраняет WG-ключ; новая получает новый. DNS не меняется. Таймер точечного отката — 30 минут.')
    for role, p in plans.items():
        print('\n' + role + ':')
        for item in p['changes']:
            print('  ' + item['action'] + ' ' + item['path'])
    if action == 'preview':
        print('PREVIEW: пакеты, ключи, постоянные файлы и службы не изменены.')
        return 0
    require(ask('Q19') == 'APPLY', 'Cancelled before deployment changes')
    users = clients(c, imported, create=True)
    remote.atomic(Path(names(c)['state']) / 'deployment.json', json.dumps(c))
    for role in ('entry', 'exit'):
        print(role + ': подготовка компонентов на VPS; сборка Caddy может занять несколько минут.', flush=True)
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
        print('Применение завершено. Возврат запускающему терминалу для НОВЫХ SSH-сессий перед фиксацией.')
        return 42
    except BaseException:
        abort(nodes, state)
        raise


def finish(nodes, session, operation):
    state = remote.readjson(session_path(session))
    require(state is not None, 'Session state missing; timers remain armed')
    c = state['config']
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
        print('Установка зафиксирована.' + (' TLS/Naive-приёмка отложена до DNS; выполните verify.' if c.get('tls') == 'defer' else ' HTTPS/TCP/UoT проверены.'))
        return 0
    except BaseException:
        abort(nodes, state)
        raise


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
        imported = credentials(json.loads(base64.b64decode(imported_raw))) if imported_raw else None
        return start(nodes, session, imported) if argv[2] == 'start' else finish(nodes, session, argv[2])
    except (Invalid, KeyboardInterrupt, EOFError) as error:
        print(str(error) if isinstance(error, Invalid) else 'Операция прервана; проверьте таймеры отката.', file=sys.stderr)
        return 1
    except ValueError:
        print('Некорректный JSON импорта учётных данных; проверьте формат v1.', file=sys.stderr)
        return 1
