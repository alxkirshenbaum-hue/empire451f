"""Coordinate the synthetic create/download test with a loopback Caddy instance."""
import json
from pathlib import Path
import secrets
import sys

from recovery_probe import BIN, attempt, perform


def auth_line(login, password):
    return 'basic_auth ' + json.dumps(login) + ' ' + json.dumps(password) + '\n'


def blocked(port):
    try:
        return not attempt(port)
    except (EOFError, OSError):
        return True


def main():
    login, password = json.loads(sys.stdin.readline())
    canary = secrets.token_hex(24)
    original = auth_line('canary', canary)

    def issue(client, run, admin):
        def outbound(name, secret):
            return dict(type='naive', username=name, password=secret, tls=dict(enabled=True))

        client(19085, outbound('canary', canary))
        client(19086, outbound(login, password))
        assert attempt(19085) and blocked(19086)
        candidate = Path('auth.next')
        candidate.write_text(original + auth_line(login, password))
        candidate.replace('auth.caddy')
        run([BIN/'caddy', 'validate', '--config', 'Caddyfile', '--adapter', 'caddyfile'])
        run([BIN/'caddy', 'reload', '--config', 'Caddyfile', '--adapter', 'caddyfile', '--address', admin])
        client(19087, outbound(login, secrets.token_hex(24)))
        assert attempt(19086) and blocked(19087) and attempt(19085)
        print('verified', flush=True)
        return json.loads(sys.stdin.readline())

    perform(dict(auth=original, revoked_login=login, revoked=secrets.token_hex(24)), issue)


if __name__ == '__main__':
    main()
