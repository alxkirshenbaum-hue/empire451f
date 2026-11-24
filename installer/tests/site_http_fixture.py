"""Optional isolated Caddy integration check. Uses an ephemeral loopback port."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import delivery


def check(binary, template, sample):
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        (base/'sample.zip').write_bytes(sample)
        (base/'auth.caddy').write_text('basic_auth fixture synthetic-example')
        (base/'site').mkdir()
        (base/'site/index.html').write_text('default-fixture')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            url = 'http://127.0.0.1:' + str(sock.getsockname()[1])
        (base/'Caddyfile').write_text(template.replace('${base}',td).replace(':443, ${domain}',url))
        env = dict(os.environ,XDG_DATA_HOME=td,XDG_CONFIG_HOME=td)
        process = subprocess.Popen([binary,'run','--config',str(base/'Caddyfile'),'--adapter','caddyfile'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            for _ in range(40):
                try:
                    first = op.open(url,timeout=2).read()
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Fixture did not start')
            assert first == b'default-fixture', 'initial site'
            delivery.publish_site(base/'sample.zip',base/'site-releases',base/'site-current')
            assert op.open(url,timeout=2).read() == (base/'site-current/index.html').read_bytes(), 'published site'
            assert op.open(url+'/assets/style.css',timeout=2).status == 200
            try:
                op.open(url+'/SITE-BRIEF.md',timeout=2)
            except urllib.error.HTTPError as error:
                assert error.code == 404
            else:
                raise RuntimeError('Brief was exposed')
        finally:
            process.terminate()
            process.wait(timeout=10)
