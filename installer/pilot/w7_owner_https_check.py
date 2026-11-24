"""Owner HTTPS read checks only; password on stdin, session kept root-only."""
import http.client,json,os,socket,ssl,sys
from pathlib import Path
mode=sys.argv[1]
password=sys.stdin.read().rstrip("\r\n")
assert password and mode in ("readonly","enabled")
root=Path(json.loads(Path("/root/vpn-control-w7/current.json").read_text())["directory"])
ctx=ssl.create_default_context(cafile="/root/nh1-panel-pilot/panel-ca.crt")
def call(path,method="GET",body=None,cookie=None,origin="https://panel.home.arpa"):
    raw=socket.create_connection(("127.0.0.1",18650),timeout=8)
    connection=http.client.HTTPConnection("panel.home.arpa",timeout=8)
    connection.sock=ctx.wrap_socket(raw,server_hostname="panel.home.arpa")
    headers={}
    if method!="GET":headers.update(Origin=origin,**{"Content-Type":"application/json"})
    if cookie:headers["Cookie"]=cookie
    connection.request(method,path,json.dumps(body).encode() if body is not None else None,headers)
    response=connection.getresponse();data=response.read();result=(response.status,response.getheader("Set-Cookie"),response.getheader("Cache-Control"),response.getheader("Referrer-Policy"),data)
    connection.close();return result
status,_,cache,referrer,body=call("/")
assert status==200 and b"Owner sign in" in body and set(part.strip() for part in cache.split(","))=={"no-store"} and referrer=="same-origin"
assert call("/api/v1/users")[0]==401
assert call("/config/")[0]==404
status,cookie,_,_,body=call("/api/v1/auth/login","POST",dict(username="owner",password=password))
password=""
assert status==200 and cookie,"existing owner login failed"
cookie=cookie.split(";",1)[0]
csrf=json.loads(body)["csrf_token"]
status,_,_,_,home=call("/",cookie=cookie)
assert status==200 and b"Personal VPN" in home and cookie.split("=",1)[1].encode() not in home
status,_,_,_,body=call("/api/v1/capabilities",cookie=cookie)
assert status==200
cap=json.loads(body)["data"]
assert cap["mutations_enabled"]==(mode=="enabled"),"unexpected mutation mode"
for route in ("/api/v1/users","/api/v1/templates","/api/v1/operations","/api/v1/dashboard","/api/v1/audits","/api/v1/backups"):
    status,_,cache,_,data=call(route,cookie=cookie)
    assert status==200 and set(part.strip() for part in cache.split(","))=={"no-store"} and "data" in json.loads(data)
assert call("/api/v1/auth/logout","POST",{},cookie,origin="https://outside.invalid")[0]==403
session=root/("owner-"+mode+".session");session.write_text(cookie.split("=",1)[1]+"\n");session.chmod(0o600)
marker=root/("readonly-verified" if mode=="readonly" else "enabled-verified");marker.write_text("HTTPS owner/read/secret boundaries verified\n");marker.chmod(0o600)
print("Existing owner HTTPS login/read routes/no-store/Origin/unauthorized/admin PASS; mode="+mode)
