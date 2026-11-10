"""Shared Windows/macOS CLI. Python 3.12+, standard library only."""
import argparse
import base64
import contextlib
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from render import Invalid, credentials, names, render, require, validate

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True

QUESTIONS = {
 'Q01': ('Режим: fresh / replace-entry / replace-exit', 'fresh — две чистые VDS; replace-entry — новый вход; replace-exit — новый выход.'),
 'Q02': ('Идентификатор установки', '3–10 строчных латинских букв/цифр, первая — буква. При повторе используйте прежний ID.'),
 'Q03': ('SSH входа: root@IP или существующий SSH alias', 'SSH-доступ берётся из панели провайдера. Адрес нового входа, а не старой KVMka.'),
 'Q04': ('Публичный IPv4 входа', 'Выделенный IPv4 новой VDS из панели провайдера.'),
 'Q05': ('SSH выхода: root@IP или SSH alias', 'При переносе входа укажите сохранённый выход.'),
 'Q06': ('Публичный IPv4 выхода', 'Это ожидаемый адрес выхода VPN в Интернет.'),
 'Q07': ('Домен HTTPS', 'Для испытания рекомендуем временный домен, направленный на новый вход. Рабочий DNS установщик не меняет.'),
 'Q08': ('Сохранённая нода: legacy / managed', 'legacy — проверенная схема старого проекта; managed — нода этого установщика с тем же ID.'),
 'Q09': ('Приватный SSH-ключ: путь или new', 'Ключ остаётся на этом компьютере. Для новой пары пароль вводится в ssh-keygen скрыто.'),
 'Q10': ('WG-подсеть /30', 'Для нового входа используйте отдельную подсеть; при замене выхода сохраните подсеть прежнего входа.'),
 'Q11': ('Локальная подсеть реле /30', 'Она не должна пересекаться с WG-подсетью и маршрутами серверов.'),
 'Q12': ('UDP-порт WireGuard выхода', 'Открывается только для IP входа. Для параллельного туннеля нужен свободный порт.'),
 'Q13': ('Импорт учётных данных: путь или пусто', 'Формат empire-vpn-clients v1. Для сохранения клиентского доступа импортируйте прежние логин/пароль.'),
 'Q14': ('Имя нового клиента', 'Используется только без импорта. Пароль будет запрошен скрыто; пустой ответ создаёт случайный.'),
 'Q15': ('Дополнительные запрещённые IP через запятую', 'Например, адрес резервной VDS. Эти адреса также нельзя выбирать целями установки.'),
 'Q16': ('TLS: ready / defer', 'ready — DNS уже указывает на новый вход; defer — установить сеть сейчас, проверить HTTPS позже.'),
 'Q17': ('Первоначальный доступ: password / console / retry', 'password добавит только выбранный публичный ключ; console покажет команду для консоли провайдера.'),
 'Q18': ('ProxyJump: configured / other-node / no', 'configured — прежний ProxyJump из SSH alias (например, старый вход); other-node — другая нода этой установки. Только при сетевой ошибке.'),
 'Q19': ('Подтвердить применение: APPLY', 'Проверьте адреса, список файлов, пакеты и 30-минутный таймер отката.'),
 'Q20': ('Продолжить или исправить: continue / Qxx', 'Номер вопроса возвращает к соответствующему ответу. До APPLY серверы не изменяются.'),
 'Q21': ('Запустить ssh-agent для защищённого ключа? yes / no', 'Windows запросит права администратора для службы; macOS запустит агент только для текущего установщика.'),
 'Q22': ('Установить python3 для инвентаризации VDS? INSTALL-PYTHON', 'Только для минимального образа Ubuntu без Python. Сначала проверяются ОС, архитектура и root; выполняются apt-get update/install python3.'),
}


def ask(q, default='', secret=False):
    title, helptext = QUESTIONS[q]
    print('\n[' + q + '] ' + title + '\n' + helptext)
    prompt = (' [' + default + ']' if default else '') + ': '
    return (getpass.getpass(prompt) if secret else input(prompt)).strip() or default


def private_root(ident):
    return Path.home() / '.config' / 'empire-vpn' / ident


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'nt':
        sid = subprocess.check_output(['powershell.exe', '-NoProfile', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], text=True).strip()
        p = subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'], capture_output=True)
        require(p.returncode == 0, 'Cannot restrict private directory ACL')
    else:
        path.chmod(0o700)


def save_private(path, value):
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if os.name != 'nt':
            path.chmod(0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_clients(path):
    p = Path(path).expanduser().resolve()
    require(not p.is_relative_to(ROOT.parent), 'Credentials must be outside the project')
    require(p.stat().st_size < 100000, 'Credential export too large')
    return credentials(json.loads(p.read_text(encoding='utf-8-sig')))


def clients_for(c, applying):
    saved = private_root(c['id']) / 'clients.json'
    source = c.get('credentials_file')
    if source:
        value = load_clients(source)
        if saved.exists():
            require(value == load_clients(saved), 'Imported credentials differ from saved credentials; refusing silent rotation')
    elif saved.exists():
        value = load_clients(saved)
    elif not applying:
        value = {'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c.get('username', 'owner'), 'password': 'PREVIEW-ONLY-NOT-A-CREDENTIAL'}]}
    else:
        password = getpass.getpass('[Q14-P] Пароль клиента (пусто = случайный; ввод скрыт): ')
        value = credentials({'format': 'empire-vpn-clients', 'schema_version': 1, 'clients': [{'username': c.get('username', 'owner'), 'password': password or secrets.token_urlsafe(32)}]})
    if applying:
        save_private(saved, value)
        print('Учётные данные сохранены вне репозитория: ' + str(saved))
    return value


def wizard():
    defaults = {'Q01': 'replace-entry', 'Q02': 'personal', 'Q08': 'legacy', 'Q09': 'new',
                'Q10': '10.203.71.0/30', 'Q11': '10.203.72.0/30', 'Q12': '51830', 'Q14': 'owner', 'Q16': 'defer'}
    answers = {}
    order = ['Q01', 'Q02', 'Q03', 'Q04', 'Q05', 'Q06', 'Q07', 'Q08', 'Q09', 'Q10', 'Q11', 'Q12', 'Q13', 'Q14', 'Q15', 'Q16']
    def build():
        a = answers
        c = {'schema_version': 1, 'mode': a['Q01'], 'id': a['Q02'], 'domain': a['Q07'].lower(),
             'entry': {'ssh': a['Q03'], 'address': a['Q04'], 'kind': a['Q08'] if a['Q01'] == 'replace-exit' else 'new'},
             'exit': {'ssh': a['Q05'], 'address': a['Q06'], 'kind': a['Q08'] if a['Q01'] == 'replace-entry' else 'new'},
             'identity': a['Q09'], 'tunnel': a['Q10'], 'relay': a['Q11'], 'wg_port': int(a['Q12']),
             'credentials_file': a['Q13'], 'username': a['Q14'], 'protected_addresses': [s.strip() for s in a['Q15'].split(',') if s.strip()], 'tls': a['Q16']}
        require(c['tls'] in ('ready', 'defer'), 'Q16: ready or defer')
        require(re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', c['username']), 'Q14: invalid username')
        if c['credentials_file']:
            try:
                load_clients(c['credentials_file'])
            except (OSError, ValueError) as error:
                raise Invalid('Q13: invalid credential export (' + type(error).__name__ + ')') from None
        return validate(c)
    for q in order:
        answers[q] = ask(q, defaults.get(q, ''))
    while True:
        try:
            c = build()
            print('\n' + json.dumps({k: v for k, v in c.items() if k not in ('credentials_file',)}, ensure_ascii=False, indent=2))
            choice = ask('Q20', 'continue')
            if choice == 'continue':
                return c
        except (ValueError, KeyError) as e:
            print('Проверьте ответы: ' + str(e))
            choice = ask('Q20', 'Q01')
        if choice in order:
            answers[choice] = ask(choice, answers[choice])
        else:
            print('Укажите номер Q01–Q16.')


def key_setup(c, applying):
    identity = c.get('identity', 'new')
    if identity == 'new':
        identity = str(Path.home() / '.ssh' / ('empire-' + c['id']))
        if not Path(identity).exists():
            require(applying, 'Preview: key does not exist. Use offline preview or select an existing key; preview never generates keys.')
            Path(identity).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            print('ssh-keygen запросит необязательный пароль новой пары. Для защищённого ключа нужен ssh-agent.')
            require(subprocess.call(['ssh-keygen', '-t', 'ed25519', '-a', '100', '-f', identity]) == 0, 'SSH key generation failed')
    identity = str(Path(identity).expanduser().resolve())
    require(Path(identity).is_file(), 'SSH private key not found')
    require('"' not in identity and '\n' not in identity, 'Unsupported identity path')
    c['identity'] = identity
    if applying:
        probe = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', identity], capture_output=True)
        if probe.returncode:
            agent = subprocess.run(['ssh-add', '-l'], capture_output=True)
            if agent.returncode == 2:
                require(ask('Q21', 'yes') == 'yes', 'Encrypted SSH key requires ssh-agent')
                if os.name == 'nt':
                    cmd = "Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -Command \"Set-Service ssh-agent -StartupType Manual; Start-Service ssh-agent\"'"
                    require(subprocess.call(['powershell.exe', '-NoProfile', '-Command', cmd]) == 0, 'Cannot start ssh-agent')
                else:
                    output = subprocess.check_output(['ssh-agent', '-s'], text=True)
                    for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID'):
                        found = re.search(name + r'=([^;]+);', output)
                        require(found is not None, 'Cannot parse ssh-agent environment')
                        os.environ[name] = found[1]
            require(subprocess.call(['ssh-add', identity]) == 0, 'Cannot unlock SSH key')


def ssh_error(stderr):
    s = stderr.lower()
    if any(x in s for x in ['host key verification failed', 'remote host identification has changed', 'no host key is known']):
        return 'identity'
    if any(x in s for x in ['permission denied', 'authentication failed', 'sign_and_send_pubkey', 'no mutual signature']):
        return 'authentication'
    if any(x in s for x in ['timed out', 'no route to host', 'network is unreachable', 'connection refused', 'could not resolve hostname', 'connection reset', 'connection closed']):
        return 'network'
    return 'other'


class SSH:
    def __init__(self, c, interactive=True):
        self.c = c
        self.interactive = interactive
        self.tmp = None
        self.jumps = {}
        self.resolved = {}

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='empire-ssh-')
        self.path = Path(self.tmp.name) / 'config'
        for role in ('entry', 'exit'):
            p = subprocess.run(['ssh', '-G', self.c[role]['ssh']], capture_output=True, text=True)
            require(p.returncode == 0, 'Cannot resolve SSH alias: ' + role)
            pairs = {}
            for line in p.stdout.splitlines():
                parts = line.split(' ', 1)
                if len(parts) == 2 and parts[0] not in pairs:
                    pairs[parts[0]] = parts[1]
            require(pairs.get('user') == 'root', 'Use root@host or a root SSH alias (sudo bootstrap is not implicit)')
            require(re.fullmatch(r'[A-Za-z0-9_.:-]+', pairs['hostname']), 'Invalid resolved SSH hostname')
            self.resolved[role] = pairs
        self.write_config()
        return self

    def __exit__(self, *args):
        self.tmp.cleanup()

    def write_config(self):
        lines = ['Host *', '  StrictHostKeyChecking yes', '  ConnectTimeout 12', '  ServerAliveInterval 10', '  ServerAliveCountMax 2', '  IdentitiesOnly yes', '  ControlMaster no', '  ControlPath none']
        for role, p in self.resolved.items():
            identity = p.get('identity_override', self.c['identity'])
            require('"' not in identity and '\n' not in identity, 'Invalid SSH identity path')
            lines += ['Host ' + role, '  HostName ' + p['hostname'], '  User ' + p['user'], '  Port ' + str(int(p['port'])), '  IdentityFile "' + identity.replace('\\', '/') + '"']
            if p.get('hostkeyalias', 'none') != 'none':
                require(re.fullmatch(r'[A-Za-z0-9_.:-]+', p['hostkeyalias']), 'Invalid HostKeyAlias')
                lines += ['  HostKeyAlias ' + p['hostkeyalias']]
            if role in self.jumps:
                lines += ['  ProxyJump ' + self.jumps[role]]
        self.path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        if os.name != 'nt':
            self.path.chmod(0o600)

    def command(self, role, batch=True):
        return ['ssh', '-F', str(self.path), '-o', 'BatchMode=' + ('yes' if batch else 'no'), role]

    def ping(self, role):
        try:
            p = subprocess.run(self.command(role) + ['true'], capture_output=True, text=True, timeout=50)
        except subprocess.TimeoutExpired:
            return 'network'
        return None if p.returncode == 0 else ssh_error(p.stderr)

    def establish(self, applying):
        failures = {}
        for role in ('entry', 'exit'):
            error = self.ping(role)
            if error == 'identity' and self.interactive and applying:
                print('[' + role + '] Сверьте fingerprint SSH с консолью провайдера. Изменённый host key автоматически не принимается.')
                subprocess.call(['ssh', '-F', str(self.path), '-o', 'StrictHostKeyChecking=ask', role, 'true'])
                error = self.ping(role)
            if error == 'authentication' and self.interactive and applying:
                print('[' + role + '] Если ключ защищён паролем, сначала добавьте его в ssh-agent: ssh-add "' + self.c['identity'] + '"')
                action = ask('Q17', 'retry')
                if action in ('password', 'console'):
                    pub = Path(self.c['identity'] + '.pub')
                    require(pub.is_file(), 'Public .pub key missing; export it using ssh-keygen -y')
                    public = pub.read_text().strip()
                    require(re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+(?: [^\r\n]*)?', public), 'Invalid public SSH key')
                    cmd = 'set -eu; . /etc/os-release; test "$ID:$VERSION_ID:$(uname -m)" = ubuntu:24.04:x86_64 || exit 41; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; grep -qxF ' + shlex.quote(public) + ' ~/.ssh/authorized_keys || printf "%s\\n" ' + shlex.quote(public) + ' >> ~/.ssh/authorized_keys'
                    if action == 'console':
                        print('Выполните в консоли провайдера (только публичный ключ):\n' + cmd)
                        input('После выполнения нажмите Enter: ')
                    else:
                        subprocess.call(['ssh', '-F', str(self.path), '-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive', role, cmd])
                elif action == 'retry':
                    subprocess.call(['ssh-add', self.c['identity']])
                error = self.ping(role)
            if error:
                failures[role] = error
        for role, error in list(failures.items()):
            other = 'exit' if role == 'entry' else 'entry'
            if error == 'network' and self.interactive:
                print('Прямое SSH к ' + role + ' недоступно по сети.')
                configured = self.resolved[role].get('proxyjump', 'none')
                choice = ask('Q18', 'configured' if configured != 'none' else ('other-node' if other not in failures else 'no'))
                if choice == 'configured':
                    require(configured != 'none' and ',' not in configured and re.fullmatch(r'[A-Za-z0-9_.@:-]+', configured) and not configured.startswith('-'), 'Configured single-hop ProxyJump unavailable')
                    p = subprocess.run(['ssh', '-G', configured], capture_output=True, text=True)
                    require(p.returncode == 0, 'Cannot resolve configured ProxyJump')
                    resolved = {}
                    for line in p.stdout.splitlines():
                        parts = line.split(' ', 1)
                        if len(parts) == 2 and parts[0] not in resolved:
                            resolved[parts[0]] = parts[1]
                    require(re.fullmatch(r'[A-Za-z0-9_.:-]+', resolved['hostname']), 'Invalid jump host')
                    require(re.fullmatch(r'[A-Za-z0-9_-]+', resolved['user']), 'Invalid jump user')
                    require(resolved['hostname'] not in self.c['protected_addresses'], 'Protected host cannot be used as jump')
                    candidate = Path(resolved.get('identityfile', '')).expanduser()
                    if candidate.is_file():
                        resolved['identity_override'] = str(candidate.resolve())
                    self.resolved['transit'] = resolved
                    self.jumps[role] = 'transit'
                    self.write_config()
                    error = self.ping(role)
                elif choice == 'other-node':
                    require(other not in failures, 'Other node is not reachable directly')
                    self.jumps[role] = other
                    self.write_config()
                    error = self.ping(role)
                if error == 'identity' and applying:
                    print('Сверьте fingerprint целевой VDS в соединении через ProxyJump.')
                    subprocess.call(['ssh', '-F', str(self.path), '-o', 'StrictHostKeyChecking=ask', role, 'true'])
                    error = self.ping(role)
            require(error is None, 'SSH ' + role + ': ' + str(error) + '. identity = проверка host key; authentication = ключ/пароль; network = сеть. Изменения не начаты.')
        print('Новые ключевые SSH-сессии обеих нод проверены; маршрут: ' + json.dumps(self.jumps))

    def ensure_runtime(self, applying):
        probe = 'set -eu; . /etc/os-release; test "$ID:$VERSION_ID:$(uname -m):$(id -u)" = ubuntu:24.04:x86_64:0 || exit 41; if command -v python3 >/dev/null; then echo PYTHON_PRESENT; else echo PYTHON_MISSING; fi'
        for role in ('entry', 'exit'):
            p = subprocess.run(self.command(role) + [probe], capture_output=True, timeout=45)
            require(p.returncode == 0, role + ': Ubuntu24.04 amd64/root check failed before modifications')
            if b'PYTHON_MISSING' in p.stdout:
                require(applying, role + ': Python3 absent; preview cannot install prerequisites')
                print(role + ': минимальный образ без Python3.')
                require(ask('Q22') == 'INSTALL-PYTHON', 'Python bootstrap declined')
                install = 'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; apt-get update && apt-get install -y --no-install-recommends python3'
                result = subprocess.run(self.command(role) + [install], capture_output=True, timeout=900)
                require(result.returncode == 0, role + ': python3 bootstrap failed')

    def call(self, role, action, **extra):
        source = {p: (ROOT / p).read_text(encoding='utf-8') for p in ('remote.py', 'render.py')}
        request = {'action': action, 'role': role, 'config': self.c, 'sources': source, **extra}
        # Source travels on stdin, never through a command-line secret argument.
        bootstrap = "import sys,json,types; r=json.load(sys.stdin); m=types.ModuleType('render'); sys.modules['render']=m; exec(r['sources']['render.py'],m.__dict__); a=types.ModuleType('agent'); exec(r['sources']['remote.py'],a.__dict__);\ntry:\n print(json.dumps({'ok':True,'result':a.dispatch(r)}))\nexcept BaseException as e:\n print(json.dumps({'ok':False,'error':str(e) if isinstance(e,m.Invalid) else type(e).__name__})); sys.exit(1)"
        cmd = 'python3 -B -c ' + shlex.quote(bootstrap)
        p = subprocess.run(self.command(role) + [cmd], input=json.dumps(request).encode(), capture_output=True, timeout=5400 if action == 'prepare' else 600)
        try:
            response = json.loads(p.stdout)
        except (ValueError, UnicodeDecodeError):
            raise Invalid('Remote response missing: ' + role + '/' + action + ', SSH=' + ssh_error(p.stderr.decode(errors='replace'))) from None
        require(response.get('ok'), role + '/' + action + ': ' + response.get('error', 'failed'))
        require(p.returncode == 0, 'SSH process failed after remote response')
        return response['result']


def bundle():
    return {p.name: p.read_text(encoding='utf-8') for p in (ROOT / 'templates').iterdir() if p.is_file()}


def offline_preview(c, clients):
    keys = {'entry': 'A' * 43 + '=', 'exit': 'B' * 43 + '='}
    for role in ('entry', 'exit'):
        if c[role]['kind'] == 'legacy':
            print(role + ': legacy adapter requires read-only online inventory; no guessed legacy files')
            continue
        files = render(c, role, {'interface': 'ens3', 'ssh_port': 22}, keys, clients, bundle())
        print(role + ': ' + str(len(files)) + ' files (example interface only; discovered online before apply)')
        for path in sorted(files):
            print('  create/check ' + path)
    print('OFFLINE PREVIEW: no SSH, no keys, no persistent writes.')


def online(c, action):
    applying = action == 'apply'
    key_setup(c, applying)
    with SSH(c) as ssh:
        ssh.establish(applying)
        ssh.ensure_runtime(applying)
        if action == 'rollback':
            require(input('Откатить последнюю транзакцию обеих нод? Введите ROLLBACK: ') == 'ROLLBACK', 'Cancelled')
            for role in ('entry', 'exit'):
                print(role, ssh.call(role, 'rollback'))
            return
        if action == 'verify':
            return verify(ssh, c)
        if action == 'acceptance':
            verify(ssh, c)
            require(input('Остановить WG входа на время отказного теста? Введите FAIL-CLOSED: ') == 'FAIL-CLOSED', 'Cancelled')
            print(ssh.call('entry', 'failure', clients=clients_for(c, False), verifier=(ROOT / 'verify.py').read_text()))
            return
        if action == 'reboot-test':
            require(input('Перезагрузить выход и вход по очереди? Введите REBOOT: ') == 'REBOOT', 'Cancelled')
            for role in ('exit', 'entry'):
                old = ssh.call(role, 'boot')['boot_id']
                ssh.call(role, 'reboot')
                deadline = time.monotonic() + 240
                while time.monotonic() < deadline:
                    time.sleep(5)
                    try:
                        new = ssh.call(role, 'boot')
                        if new['boot_id'] != old:
                            require(not new['ordering_cycle'], 'Ordering cycle found after reboot')
                            break
                    except (Invalid, subprocess.SubprocessError):
                        continue
                else:
                    raise Invalid('Reboot did not recover in 240 seconds: ' + role)
                time.sleep(5)
                verify(ssh, c)
            return
        clients = clients_for(c, False)
        facts = {r: ssh.call(r, 'probe') for r in ('entry', 'exit')}
        require(facts['entry']['machine_id'] != facts['exit']['machine_id'], 'Both SSH targets resolve to the same machine')
        for role in ('entry', 'exit'):
            require(not facts[role]['pending'], 'Pending remote transaction on ' + role + ': use rollback action before retry')
        keys = {r: facts[r].get('public_key', ('A' if r == 'entry' else 'B') * 43 + '=') for r in facts}
        templates = bundle()
        plans = {r: ssh.call(r, 'plan', keys=keys, clients=clients, templates=templates) for r in facts}
        print('\nПараметры: ' + c['mode'] + ', ' + c['entry']['address'] + ' → ' + c['exit']['address'] + ', HTTPS ' + c['domain'])
        print('Пакеты Ubuntu: wireguard-tools nftables iproute2 ca-certificates curl python3; сборка входа: git build-essential.')
        print('На новой ноде создаётся WG-ключ; сохранённая нода использует существующий ключ. Зависимости и ключи при откате сохраняются.')
        print('Сеть/файлы защищает постоянный таймер отката 30 минут. DNS переключается отдельно.')
        for role in plans:
            print('\n' + role + ': ' + json.dumps(ssh.jumps.get(role, 'direct')))
            for change in plans[role]['changes']:
                print('  ' + change['action'] + ' ' + change['path'])
        if not applying:
            print('PREVIEW: no persistent local or remote changes.')
            return
        require(ask('Q19') == 'APPLY', 'Cancelled before changes')
        clients = clients_for(c, True)
        save_private(private_root(c['id']) / 'deployment.json', c)
        versions = json.loads((ROOT / 'versions.json').read_text())
        for role in ('entry', 'exit'):
            print(role + ': installing prerequisites/components; build can take several minutes... ', flush=True)
            keys[role] = ssh.call(role, 'prepare', versions=versions)['public_key']
        tx = uuid.uuid4().hex
        changed = []
        try:
            for role in ('exit', 'entry'):
                fresh_plan = ssh.call(role, 'plan', keys=keys, clients=clients, templates=templates)
                result = ssh.call(role, 'apply', keys=keys, clients=clients, templates=templates, facts=fresh_plan['facts'], transaction=tx)
                if result['status'] == 'applied':
                    changed.append(role)
                print(role + ': ' + result['status'])
                require(ssh.ping(role) is None, 'New SSH session failed after changes: ' + role)
            # Internal egress is always mandatory; TLS may intentionally await DNS.
            health(ssh, c)
            if c.get('tls', 'ready') == 'ready':
                verify(ssh, c)
            for role in changed:
                print(role + ': ' + ssh.call(role, 'commit')['status'])
            print('Установка сохранена. ' + ('TLS/полный Naive-тест отложены до DNS; выполните verify.' if c.get('tls') == 'defer' else 'Проверки HTTPS/TCP/UoT пройдены.'))
        except BaseException:
            for role in reversed(changed):
                try:
                    print(role + ': ' + ssh.call(role, 'rollback')['status'])
                except BaseException:
                    print(role + ': откат по SSH не подтверждён; действует серверный таймер. Используйте консоль провайдера.')
            raise


def health(ssh, c):
    print(ssh.call('entry', 'health'))


def verify(ssh, c):
    clients = clients_for(c, False)
    require(clients['clients'][0]['password'] != 'PREVIEW-ONLY-NOT-A-CREDENTIAL', 'Import credentials or use saved deployment for verify')
    print(ssh.call('entry', 'verify', clients=clients, verifier=(ROOT / 'verify.py').read_text()))
    for role in ('entry', 'exit'):
        require(ssh.ping(role) is None, 'New SSH session failed: ' + role)


def main(argv=None):
    p = argparse.ArgumentParser(description='Empire personal VPN installer')
    p.add_argument('action', choices=['wizard', 'preview', 'apply', 'verify', 'rollback', 'acceptance', 'reboot-test', 'test'], nargs='?', default='wizard')
    p.add_argument('--config', type=Path)
    p.add_argument('--offline', action='store_true')
    args = p.parse_args(argv)
    if args.action == 'test':
        import unittest
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT / 'tests'))).wasSuccessful() else 1
    for exe in ('ssh', 'ssh-keygen'):
        require(shutil.which(exe), 'Missing ' + exe + ': see README environment preparation')
    c = validate(json.loads(args.config.read_text(encoding='utf-8-sig'))) if args.config else wizard()
    if args.offline:
        require(args.action in ('preview', 'wizard'), '--offline is preview only')
        offline_preview(c, clients_for(c, False))
    else:
        online(c, 'apply' if args.action == 'wizard' else args.action)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Invalid, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, Invalid) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('Прервано. Если применение уже началось, проверьте серверный таймер/rollback перед повтором.', file=sys.stderr)
        sys.exit(130)
