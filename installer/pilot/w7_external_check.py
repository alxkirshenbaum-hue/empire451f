import socket,ssl,http.client
address="85.155.185.169"
try:
    s=socket.create_connection((address,18650),timeout=4)
except OSError:pass
else:
    s.close();raise RuntimeError("Private frontend public port reachable")
for path in ("/","/api/v1/users"):
    raw=socket.create_connection((address,443),timeout=5)
    ctx=ssl.create_default_context()
    connection=http.client.HTTPConnection("empire451f.duckdns.org",timeout=5)
    connection.sock=ctx.wrap_socket(raw,server_hostname="empire451f.duckdns.org")
    connection.request("GET",path,headers={"Host":"panel.home.arpa"})
    response=connection.getresponse();body=response.read(131072);content=response.getheader("Content-Type","")
    assert b"Owner sign in" not in body and b"Personal VPN</h1>" not in body
    assert not(response.status==401 and content.startswith("application/json"))
    print("External forged Host:",path,response.status,"private panel not exposed")
    connection.close()
print("External private-port/forged-Host checks PASS")
