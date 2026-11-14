"""Owner CLI -> real copy API -> canonical worker -> private profile file."""
import argparse, contextlib, copy, hashlib, json, os, sqlite3, subprocess, sys, time, uuid
from pathlib import Path

def require(value,label):
    if not value: raise RuntimeError(label)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("project",type=Path);parser.add_argument("run",type=int)
    args=parser.parse_args();project=args.project.resolve()
    root=project/("rehearsal-root-"+str(args.run))
    require((root/".vpn-control-rehearsal").is_file() and (root/"run/ui-hold").is_file(),"active synthetic copy required")
    context=json.loads((root/"run/ui-context.json").read_text())
    require(context["synthetic"],"synthetic fixture required")
    pid=int(subprocess.check_output(["systemctl","show","vpn-full-worker-root-"+str(args.run),"-p","MainPID","--value"]))
    require(pid>1,"copy unit inactive")
    env=os.environ.copy();env.update(VPNCTL_SOCKET=str(root/context["api_socket"].lstrip("/")),VPNCTL_SESSION_FILE=str(root/"root/ui-owner-session"))
    cli=project/"rehearsal-bin/vpnctl"
    suffix=uuid.uuid4().hex[:8];login="CLI-ExactCase-"+suffix
    private=root/("root/owner-cli-check-"+suffix);private.mkdir(mode=0o700,exist_ok=True)
    session=private/"session";session.write_bytes((root/"root/ui-owner-session").read_bytes());session.chmod(0o600)
    env["VPNCTL_SESSION_FILE"]=str(session)
    captured=[]
    def call(*argv,code=0):
        result=subprocess.run([str(cli),*map(str,argv)],env=env,capture_output=True,timeout=20)
        captured.extend((result.stdout,result.stderr))
        require(result.returncode==code,"owner CLI failed: "+"/".join(argv[:2])+" exit="+str(result.returncode))
        return json.loads(result.stdout)["data"] if result.returncode==0 and result.stdout and argv[0]!="profile" else None
    def wait(receipt):
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            op=call("operation","show",receipt["operation_id"],"--json")
            if op["status"]=="succeeded":return
            require(op["status"] in ("queued","running","verifying"),"operation requires inspection")
            time.sleep(1)
        raise RuntimeError("copy worker timeout")
    templates=call("template","list","--json");require(templates,"approved base template missing")
    key=str(uuid.uuid4())
    create=("user","create","--login",login,"--display-name","CLI copy test","--template",templates[0]["id"],"--idempotency-key",key,"--json")
    receipt=call(*create);wait(receipt)
    require(call(*create)==receipt,"create replay changed receipt")
    user=receipt["user_id"]
    detail=call("user","show",user,"--json")
    require(detail["user"]["status"]=="active" and detail["user"]["login"]==login,"confirmed state/case mismatch")
    protected=next(x for x in call("user","list","--json")["users"] if x["protected"])
    call("user","disable",protected["id"],"--expected-version",protected["row_version"],"--idempotency-key",str(uuid.uuid4()),"--reason","synthetic protection check","--json",code=3)
    renamed=call("user","rename",user,"--display-name","Renamed copy user","--expected-version",detail["user"]["row_version"],"--idempotency-key",str(uuid.uuid4()),"--json")
    wait(renamed)
    call("user","rename",user,"--display-name","Stale change","--expected-version",detail["user"]["row_version"],"--idempotency-key",str(uuid.uuid4()),"--json",code=4)
    secrets=[];files=[]
    for name,version,optional in (("base1144","sfa-1.14.4",False),("baseAlpha13","sfa-1.15-alpha13",False),("optionalAlpha13","sfa-1.15-alpha13",True)):
        target=private/(name+".json")
        argv=["profile","download",user,"--output",str(target),"--client",version,"--quiet"]
        if optional:argv.extend(("--ru-dm","--acknowledge"))
        call(*argv)
        require(target.stat().st_mode&0o777==0o600,"profile mode")
        raw=target.read_bytes();profile=json.loads(raw)
        outbound=next(x for x in profile["outbounds"] if x["type"]=="naive")
        require(outbound["username"]==login,"profile login mismatch")
        secrets.append(outbound["password"].encode())
        packages=[r for r in profile["route"]["rules"] if "package_name" in json.dumps(r)]
        require(bool(packages)==optional,"base/optional rules mismatch")
        require(any(s.get("type")=="hosts" and s.get("predefined",{}).get("panel.home.arpa")=="192.0.2.119" for s in profile["dns"]["servers"]),"exact panel hosts missing")
        files.append((target,hashlib.sha256(raw).hexdigest()))
    require(len(set(secrets))==1,"issuing routing variants changed credential")
    target,digest=files[0]
    call("profile","download",user,"--output",str(target),"--quiet",code=3)
    require(hashlib.sha256(target.read_bytes()).hexdigest()==digest,"existing profile overwritten")
    rejected=private/"rejected.json"
    call("profile","download",user,"--output",str(rejected),"--ru-dm","--acknowledge","--quiet",code=2)
    require(not rejected.exists(),"unsupported profile written")
    for secret in secrets:
        require(all(secret not in stream for stream in captured),"VPN secret in CLI output")
    token=(root/"root/ui-owner-session").read_bytes().strip()
    require(all(token not in stream for stream in captured),"session in CLI output")
    # Validate a freshly issued profile against the live synthetic Naive stack.
    child_code=r"""
import contextlib, copy, json, secrets, socket, sys
from pathlib import Path
project,root,filename=map(Path,sys.argv[1:])
sys.path[:0]=[str(project),str(project/'pilot')]
from recovery_probe import start,attempt
from verify import udp
import os
assert [name for _,name in socket.if_nameindex()]==['lo']
profile=json.loads(filename.read_text())
outbound=next(x for x in profile['outbounds'] if x['type']=='naive')
outbound=copy.deepcopy(outbound);outbound.update(server='127.0.0.1',server_port=18443);outbound.pop('domain_resolver',None)
outbound['tls'].update(server_name='lab.example',certificate_path=str(root/'etc/vpn-control/lab-ca.pem'))
client=dict(log=dict(disabled=True),inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=19095)],outbounds=[outbound])
path=filename.parent/'fresh-client.json';path.write_text(json.dumps(client));path.chmod(0o600)
with contextlib.ExitStack() as stack:
    start(stack,['/opt/empire-vpn/bin/sing-box','run','-c',str(path)],19095)
    assert attempt(19095)
    nonce=secrets.token_bytes(24)
    assert udp(19095,'192.0.2.119',19877,nonce)==nonce
print('Issued profile fresh TCP/UoT PASS')
"""
    result=subprocess.run(["nsenter","-t",str(pid),"-n","python3","-B","-c",child_code,str(project),str(root),str(files[0][0])],capture_output=True,text=True,timeout=30)
    require(result.returncode==0,"fresh issued profile connection failed")
    print(result.stdout.strip())
    for group,action in (("user","history"),("cred","status")):call(group,action,user,"--json")
    for group,action in (("operation","list"),("audit","list"),("backup","list"),("system","show")):call(group,action,"--json")
    print("Owner CLI real API/create/replay/rename/CAS/protection/three private profiles/no-overwrite/no output secrets PASS")
if __name__=="__main__":main()
