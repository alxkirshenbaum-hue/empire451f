"""Pure policy/transport mocks; no socket listener or runtime is started."""
import email.message
import importlib.util
import io
from pathlib import Path
import stat
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('frontend_rehearsal', Path(__file__).parents[1]/'pilot/panel_frontend_rehearsal.py')
frontend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frontend)

class BrowserAdapterTests(unittest.TestCase):
    def headers(self, **values):
        headers=email.message.Message();headers['Host']='127.0.0.1:18900'
        for key,value in values.items(): headers[key.replace('_','-')]=value
        return headers

    def test_exact_paths_and_methods(self):
        for target in frontend.BROWSER_PATHS:
            for method in ('GET','HEAD'):
                self.assertTrue(frontend.browser_request_allowed(method,target,self.headers(),18900))
        for target in ('http://127.0.0.1:18900/','//localhost/','/%2e%2e/config','/api/v1/users',
                       '/api/v1/users?limit=100&search=secret&status=', '/api/v1/users/id',
                       '/api/v1/users/id/profile','/api/v1/backups/id/download','/config/','/?x=1'):
            self.assertFalse(frontend.browser_request_allowed('GET',target,self.headers(),18900))
        for method in ('POST','PATCH','PUT','DELETE','CONNECT','OPTIONS','TRACE','BREW'):
            self.assertFalse(frontend.browser_request_allowed(method,'/',self.headers(),18900))

    def test_origin_host_and_request_framing(self):
        for key,value in (('Host','localhost:18900'),('Host','127.0.0.1:80'),('Origin','https://evil.invalid'),
                          ('Sec-Fetch-Site','cross-site'),('Upgrade','websocket'),('Content-Length','1'),('Transfer-Encoding','chunked')):
            headers=self.headers();headers.replace_header(key,value) if key in headers else headers.__setitem__(key,value)
            self.assertFalse(frontend.browser_request_allowed('GET','/',headers,18900),(key,value))
        headers=self.headers();headers['Host']='127.0.0.1:18900'
        self.assertFalse(frontend.browser_request_allowed('GET','/',headers,18900))
        self.assertTrue(frontend.browser_request_allowed('GET','/',self.headers(Origin='http://127.0.0.1:18900',Sec_Fetch_Site='same-origin'),18900))

    def upstream(self, status=200, body=b'public metadata', headers=None):
        response=mock.Mock(status=status);response.read.return_value=body
        response.getheader.side_effect=lambda key:(headers or {}).get(key)
        connection=mock.Mock();connection.getresponse.return_value=response
        return connection,response

    def test_upstream_fixed_socket_private_cookie_selected_headers(self):
        connection,response=self.upstream(headers={'Content-Type':'application/json','Set-Cookie':'session=secret','Location':'https://evil.invalid'})
        with mock.patch('http.client.HTTPConnection',return_value=connection),mock.patch('socket.socket') as socket_factory:
            status,headers,body=frontend.browser_upstream(Path('/synthetic/rehearsal-root-9'),'private-token','/api/v1/auth/me')
        socket_factory.return_value.connect.assert_called_once_with('/synthetic/rehearsal-root-9/run/vpn-control/api/api.sock')
        connection.request.assert_called_once_with('GET','/api/v1/auth/me',headers={'Cookie':'session=private-token','Accept':'*/*'})
        self.assertEqual((status,body),(200,b'public metadata'));self.assertEqual(headers,[('Content-Type','application/json')])
        connection.close.assert_called_once();response.read.assert_called_once_with(frontend.BROWSER_LIMIT+1)

    def test_upstream_size_and_redirects_rejected(self):
        for status,body in ((302,b''),(200,b'x'*(frontend.BROWSER_LIMIT+1))):
            connection,_=self.upstream(status,body)
            with mock.patch('http.client.HTTPConnection',return_value=connection),mock.patch('socket.socket'):
                with self.assertRaises(RuntimeError): frontend.browser_upstream(Path('/synthetic'),'token','/')
            connection.close.assert_called_once()

    def test_private_session_rejects_bad_file_without_exposing_token(self):
        root=Path('/synthetic/rehearsal-root-9');parent=root/'root';path=parent/'ui-owner-session'
        for mode,uid,size in ((stat.S_IFREG|0o644,0,10),(stat.S_IFREG|0o600,1,10),(stat.S_IFIFO|0o600,0,10),(stat.S_IFREG|0o600,0,514)):
            with mock.patch.object(Path,'resolve',lambda self:self),mock.patch.object(Path,'lstat',return_value=mock.Mock(st_mode=stat.S_IFDIR|0o700,st_uid=0)),mock.patch('os.open',return_value=4),mock.patch('os.fstat',return_value=mock.Mock(st_mode=mode,st_uid=uid,st_size=size)),mock.patch('os.close'),mock.patch('os.read') as read:
                with self.assertRaisesRegex(RuntimeError,'private synthetic session required'):frontend.browser_session(root)
                read.assert_not_called()

    def test_listener_bounds_lifetime_and_signal_cleanup_without_network(self):
        captured = {}
        class FakeServer:
            def __init__(self, address, handler): captured.update(server=self,address=address,handler=handler)
            def __enter__(self): return self
            def __exit__(self,*args): captured['closed']=True
            def handle_request(self): raise AssertionError('lifetime should already have ended')
        with mock.patch('http.server.ThreadingHTTPServer',FakeServer),mock.patch.object(frontend,'browser_session',return_value='private-token'),mock.patch('signal.signal',return_value='old-handler') as signals,mock.patch.object(frontend.time,'monotonic',side_effect=[0,2]),mock.patch('builtins.print'):
            frontend.serve_browser(Path('/synthetic'),18900,lifetime=1)
        self.assertEqual(captured['address'],('127.0.0.1',18900));self.assertTrue(captured['closed'])
        self.assertEqual(signals.call_count,4)
        handler=captured['handler'].__new__(captured['handler']);handler.request_version='HTTP/1.0';handler.wfile=io.BytesIO();handler._headers_buffer=[b'HTTP/1.0 403 Forbidden\r\n']
        handler.end_headers();self.assertEqual(handler.wfile.getvalue().count(b'Cache-Control: no-store\r\n'),1)
        self.assertEqual([captured['server'].slots.acquire(False) for _ in range(5)],[True,True,True,True,False])
        self.assertEqual(captured['server'].request_queue_size,4)
        self.assertTrue(captured['server'].daemon_threads)
        for port,lifetime in ((80,1),(65536,1),(18900,0),(18900,901)):
            with self.assertRaisesRegex(RuntimeError,'invalid browser adapter bounds'):
                frontend.serve_browser(Path('/synthetic'),port,lifetime)

    def test_fixed_socket_rejects_symlink_and_non_socket(self):
        root=Path('/synthetic/rehearsal-root-9')
        path=root/'run/vpn-control/api/api.sock'
        for resolved,mode in ((Path('/outside/api.sock'),stat.S_IFSOCK|0o600),(path,stat.S_IFREG|0o600)):
            with mock.patch.object(Path,'resolve',return_value=resolved),mock.patch.object(Path,'lstat',return_value=mock.Mock(st_mode=mode)):
                with self.assertRaisesRegex(RuntimeError,'fixed synthetic API socket required'):
                    frontend.require_fixed_socket(root)
        with mock.patch.object(Path,'resolve',return_value=path),mock.patch.object(Path,'lstat',return_value=mock.Mock(st_mode=stat.S_IFSOCK|0o600)):
            frontend.require_fixed_socket(root)

    def test_browser_start_revalidates_owned_unit(self):
        root=Path('/synthetic/rehearsal-root-9')
        for results in (['inactive'],['active','99'],['active','42','/outside']):
            with mock.patch.object(frontend,'command',side_effect=results),mock.patch.object(frontend,'require_fixed_socket') as socket_check:
                with self.assertRaisesRegex(RuntimeError,'active owned synthetic unit required'):
                    frontend.validate_browser_root(root,9,42)
                socket_check.assert_not_called()
        with mock.patch.object(frontend,'command',side_effect=['active','42',str(root)]),mock.patch.object(Path,'is_file',return_value=True),mock.patch.object(frontend,'require_fixed_socket') as socket_check:
            frontend.validate_browser_root(root,9,42)
            socket_check.assert_called_once_with(root)

    def test_canonical_security_properties_preserved(self):
        project=Path('/synthetic/source');root=project/'rehearsal-root-916041'
        repo=Path(__file__).parents[1]
        for kind,name in (('api','vpn-control-api.service'),('panel','vpn-control-panel.service')):
            entries=frontend.canonical_service(repo/'controlpanel/systemd'/name)
            unit,props,executable=frontend.canonical_lab_service(entries,kind,root,project,916041,42,'owner-run')
            self.assertEqual(unit,'vpn-w9u-'+kind+'-916041')
            for key,value in entries:
                if key in ('User','Group','RuntimeDirectory','ExecStart','EnvironmentFile','ReadWritePaths','NetworkNamespacePath','Environment','InaccessiblePaths','LoadCredential'):continue
                self.assertIn(key+'='+value,props)
            self.assertIn('RootDirectory='+str(root),props)
            self.assertIn('RuntimeDirectoryMode=0700',props)
            self.assertIn('Restart=on-failure',props)
            self.assertIn('NoNewPrivileges=yes',props)
            self.assertIn('CapabilityBoundingSet=',props)
            self.assertFalse(any('systemd/private' in item or ':/run' in item for item in props))
            if kind=='api':
                self.assertIn('/run/vpn-w9u-api-916041/api.sock',executable)
                self.assertIn('--owner-run',executable)
            else:self.assertIn('BindReadOnlyPaths=/run/vpn-w9u-api-916041:/api',props)

    def test_bootstrap_stopped_rejects_live_only_accepts_gone_or_zombie(self):
        for state,expected in (('S (sleeping)',False),('R (running)',False),('Z (zombie)',True),('D (disk sleep)',False)):
            with mock.patch.object(Path,'read_text',return_value='State:\t'+state+'\n'):
                self.assertEqual(frontend.bootstrap_stopped(42),expected)
        with mock.patch.object(Path,'read_text',side_effect=FileNotFoundError):
            self.assertTrue(frontend.bootstrap_stopped(42))

if __name__=='__main__':unittest.main()
