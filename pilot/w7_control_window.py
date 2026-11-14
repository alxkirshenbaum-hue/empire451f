"""Approved W7 control-plane window. Never touches transport/network/users."""
import contextlib,hashlib,json,os,shutil,sqlite3,subprocess,sys,tarfile,time,uuid
from pathlib import Path
BUNDLE=Path("/opt/empire-vpn/cache/w7-pinned-ad6b653/upgrade-bundle-clean")
BASE=Path("/root/vpn-control-w7")
MANIFEST="e512a536a57256dbaff7025991621551cda11687b14423ebb9ce5abb281b6ba0"
def require(value,label):
    if not value:raise RuntimeError(label)
def run(args,check=True):
    result=subprocess.run(list(map(str,args)),capture_output=True,text=True)
    if check and result.returncode:raise RuntimeError("Control command failed: "+" ".join(map(str,args))+": "+result.stderr.strip())
    return result.stdout.strip()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def atomic(p,data,mode=0o600,uid=0,gid=0):
    p=Path(p);p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    require(not p.is_symlink(),"symlink target refused")
    temp=p.with_name(p.name+".w7-new")
    with temp.open("xb") as f:
        f.write(data);f.flush();os.fchmod(f.fileno(),mode);os.fchown(f.fileno(),uid,gid);os.fsync(f.fileno())
    os.replace(temp,p)
    fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def save(w,state):atomic(w/"window.json",(json.dumps(state,sort_keys=True,indent=2)+"\n").encode())
def dbstate():
    with sqlite3.connect("file:/var/lib/vpn-control/state.db?mode=ro",uri=True) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()==("ok",),"SQLite integrity")
        pending=db.execute("SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back')").fetchone()[0]
        result={}
        for table in ("users","credentials","user_current_credentials","user_profiles"):
            rows=db.execute("SELECT * FROM "+table).fetchall()
            encoded=sorted(json.dumps(row,default=lambda value:hashlib.sha256(value).hexdigest(),sort_keys=True) for row in rows)
            result[table]=hashlib.sha256(json.dumps(encoded).encode()).hexdigest()
        result["owner"]=db.execute("SELECT id,username,password_hash,disabled FROM admin_accounts ORDER BY id").fetchall()
        result["owner"]=hashlib.sha256(json.dumps(result["owner"]).encode()).hexdigest()
        return result,pending
def observed():
    result={}
    for unit in ("evpn-nh1-caddy.service","evpn-nh1-singbox.service"):
        result[unit]=run(["systemctl","show",unit,"-p","MainPID","-p","NRestarts"])
    for p in ("/etc/empire-vpn/nh1/auth.caddy","/etc/empire-vpn/nh1/Caddyfile","/etc/empire-vpn/nh1/sing-box.json","/var/lib/vpn-control/vault.key","/run/nh1-panel-pilot/tls.key"):
        result[p]=sha(p)
    result["generation"]=json.loads(Path("/var/lib/empire-vpn/nh1/manifest.json").read_text())["panel_generation"]
    return result
def quiet():
    current,pending=dbstate();require(pending==0,"unfinished operations")
    directory=Path("/var/lib/empire-vpn/nh1")
    require(not any((directory/n).exists() for n in ("pending.json","user-rollback.json","return-intent.json","panel-auth-pending.json")),"unfinished file journal")
    return current
def backup_db(target):
    with sqlite3.connect("file:/var/lib/vpn-control/state.db?mode=ro",uri=True) as src,sqlite3.connect(target) as dst:
        src.backup(dst);require(dst.execute("PRAGMA integrity_check").fetchone()==("ok",),"backup integrity")
        dst.execute("PRAGMA journal_mode=DELETE")
    target.chmod(0o600)
def prepare():
    require(os.geteuid()==0,"root required")
    require(sha(BUNDLE/"manifest.json")==MANIFEST,"package manifest changed")
    sys.path.insert(0,"/opt/empire-vpn/cache/w7-pinned-ad6b653/pilot")
    from prepare_panel_upgrade import verify
    verify(BUNDLE)
    baseline=quiet()
    require(not Path("/etc/systemd/system/vpn-control-panel.service").exists(),"new frontend unit already exists")
    require(not Path("/etc/vpn-control/private-panel").exists(),"new TLS path already exists")
    require(not Path("/etc/systemd/system/vpn-control-api.service.d/20-owner-run.conf").exists(),"API override exists")
    old=Path("/run/systemd/transient/nh1-panel-readonly.service")
    require(old.is_file(),"current readonly transient unit missing")
    text=old.read_text()
    for value in ("DynamicUser=yes","NetworkNamespacePath=/run/netns/naive","RuntimeDirectory=nh1-panel-caddy"):
        require(value in text.replace(chr(34),""),"readonly unit drift")
    wid=str(uuid.uuid4());w=BASE/wid;w.mkdir(mode=0o700,parents=True);BASE.chmod(0o700)
    control=w/"control";control.mkdir(mode=0o700)
    paths=["/usr/local/bin/vpnctl","/usr/local/bin/vpn-control",
       "/etc/systemd/system/vpn-control-api.service","/etc/systemd/system/vpn-control-worker@.service",
       "/etc/systemd/system/vpn-control-worker@.timer","/etc/vpn-control/api.env",
       "/etc/vpn-control/worker-nh1.env","/etc/vpn-control/worker-nh1.json",
       str(old),"/run/nh1-panel-pilot/Caddyfile.runtime","/run/nh1-panel-pilot/tls.key","/run/nh1-panel-pilot/leaf.crt"]
    for directory in (Path("/etc/systemd/system/vpn-control-api.service.d"),Path("/etc/systemd/system/vpn-control-worker@nh1.service.d")):
        if directory.exists():paths.extend(str(p) for p in directory.rglob("*") if p.is_file())
    metadata={}
    for name in paths:
        source=Path(name);require(source.is_file() and not source.is_symlink(),"unsafe old control file")
        destination=control/name.lstrip("/");destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,destination)
        info=source.stat();os.chown(destination,info.st_uid,info.st_gid)
        metadata[name]=dict(mode=info.st_mode&0o777,uid=info.st_uid,gid=info.st_gid,sha256=sha(source))
    sys.path.insert(0,str(BUNDLE/"helpers"))
    from g3_snapshot import snapshot
    core=snapshot("nh1",wid,"pre")
    state=dict(window=wid,phase="prepared",package_manifest=MANIFEST,baseline=baseline,observed=observed(),files=metadata,core=core,
       old_policy=json.loads(Path("/etc/vpn-control/worker-nh1.json").read_text()))
    save(w,state)
    atomic(w/"replay-readonly-frontend.sh",(BUNDLE/"replay-readonly-frontend.sh").read_bytes(),0o700)
    metadata=dict(format="vpn-control-g3-snapshot-v1",kind="w7-control-supplement",installation="nh1",window=wid,phase="pre",generation=state["observed"]["generation"])
    (control/"G3-SNAPSHOT.json").write_text(json.dumps(metadata))
    with tarfile.open(w/"control-pre.tar","w",format=tarfile.PAX_FORMAT) as archive:
        archive.add(control,arcname=".")
    (w/"control-pre.tar").chmod(0o600)
    require((w/"control-pre.tar").stat().st_size<=32*1024*1024,"control archive limit")
    result=dict(window=wid,directory=str(w),core_archive=core["archive"],core_sha256=core["sha256"],
                control_archive=str(w/"control-pre.tar"),control_sha256=sha(w/"control-pre.tar"))
    atomic(BASE/"current.json",json.dumps(result).encode())
    print(json.dumps(result))
def load():
    receipt=json.loads((BASE/"current.json").read_text());w=Path(receipt["directory"])
    if len(sys.argv)>2:w=BASE/str(uuid.UUID(sys.argv[2]))
    require(w.parent==BASE and str(uuid.UUID(w.name))==w.name,"unsafe window path")
    return w,json.loads((w/"window.json").read_text())
def switch():
    w,s=load();require((w/"backup-verified").is_file() and s["phase"] in ("prepared","switching"),"verified backup required")
    require(quiet()==s["baseline"] and observed()==s["observed"],"pre-switch drift")
    run(["systemctl","stop","vpn-control-worker@nh1.timer"])
    deadline=time.monotonic()+190
    while run(["systemctl","is-active","vpn-control-worker@nh1.service"],False) in ("active","activating"):
        require(time.monotonic()<deadline,"worker did not drain");time.sleep(1)
    require(quiet()==s["baseline"],"writer drift")
    # Root-only guard invokes this same rollback; no transport unit is stopped.
    guard="vpn-w7-guard-"+s["window"]
    if s["phase"]=="prepared":run(["systemd-run","--quiet","--unit="+guard,"--on-active=20min","/usr/bin/python3","-B",str(Path(__file__).resolve()),"rollback",s["window"]])
    s["guard"]=guard;s["phase"]="switching";save(w,s)
    run(["systemctl","stop","vpn-control-api.service","nh1-panel-readonly.service"],False)
    require(run(["systemctl","is-active","vpn-control-api.service"],False)!="active","API still active")
    require(run(["systemctl","is-active","nh1-panel-readonly.service"],False)!="active","readonly frontend still active")
    if not (w/"state-before-switch.db").exists():backup_db(w/"state-before-switch.db")
    m=json.loads((BUNDLE/"manifest.json").read_text())
    helper=Path(m["helper_destination"]);require(not helper.is_symlink(),"helper symlink refused")
    helper.mkdir(mode=0o755,exist_ok=True)
    for entry in m["files"]:
        if entry["path"].startswith("helpers/"):
            p=BUNDLE/entry["path"];require(sha(p)==entry["sha256"],"helper digest mismatch");atomic(helper/p.name,p.read_bytes(),0o644)
    for name in ("vpn-control","vpnctl"):atomic(Path("/usr/local/bin")/name,(BUNDLE/"bin"/name).read_bytes(),0o755)
    policy=s["old_policy"];oldprefix=str(Path(policy["helper"]).parent)
    def update(value):
        if isinstance(value,str) and (value==oldprefix or value.startswith(oldprefix+"/")):return str(helper)+value[len(oldprefix):]
        if isinstance(value,list):return [update(v) for v in value]
        if isinstance(value,dict):return {k:update(v) for k,v in value.items()}
        return value
    atomic("/etc/vpn-control/worker-nh1.json",json.dumps(update(policy)).encode())
    run(["/usr/local/bin/vpnctl","registry","init","--installation","nh1","--sfa-template",str(BUNDLE/"sfa-template.json"),"--approve-sha256",m["source_template_sha256"]])
    require(quiet()==s["baseline"] and observed()==s["observed"],"migration changed protected state")
    # registry init creates WAL as root; restore only the existing API's ownership.
    for name in ("state.db","state.db-wal","state.db-shm"):
        p=Path("/var/lib/vpn-control")/name
        if p.exists():os.chown(p,981,981);p.chmod(0o600)
    tls=Path("/etc/vpn-control/private-panel");tls.mkdir(mode=0o700)
    for name,source in (("leaf.crt","leaf.crt"),("tls.key","tls.key")):
        atomic(tls/name,(w/"control/run/nh1-panel-pilot"/source).read_bytes())
    atomic(tls/"Caddyfile",(BUNDLE/"private-panel.Caddyfile").read_bytes())
    atomic("/etc/systemd/system/vpn-control-panel.service",(BUNDLE/"systemd/vpn-control-panel.service").read_bytes(),0o644)
    run(["systemctl","daemon-reload"]);run(["systemctl","start","vpn-control-api.service","vpn-control-panel.service"])
    s["phase"]="readonly";save(w,s);print("W7 control-plane started read only; guard armed")
def enable():
    w,s=load();require(s["phase"]=="readonly","readonly verification required")
    require(quiet()==s["baseline"] and observed()==s["observed"],"pre-enable drift")
    require((w/"readonly-verified").is_file(),"readonly verification missing")
    atomic("/etc/systemd/system/vpn-control-api.service.d/20-owner-run.conf",(BUNDLE/"systemd/20-owner-run.conf").read_bytes(),0o644)
    run(["systemctl","daemon-reload"]);run(["systemctl","restart","vpn-control-api.service"])
    run(["systemctl","enable","vpn-control-panel.service"])
    run(["systemctl","start","vpn-control-worker@nh1.timer"])
    s["phase"]="enabled";save(w,s);print("W7 owner capability enabled; no user mutation performed")
def rollback(force=False):
    w,s=load()
    if s["phase"] in ("prepared","rolled_back") or (s["phase"]=="complete" and not force):print("Control rollback idle");return
    run(["systemctl","stop","vpn-control-worker@nh1.timer"])
    # A running auth operation is not interrupted.
    deadline=time.monotonic()+190
    while run(["systemctl","is-active","vpn-control-worker@nh1.service"],False) in ("active","activating"):
        require(time.monotonic()<deadline,"reconcile active worker through SSH");time.sleep(1)
    current,pending=dbstate()
    same=current==s["baseline"] and pending==0 and observed()==s["observed"]
    run(["systemctl","stop","vpn-control-panel.service","vpn-control-api.service"],False)
    backup_db(w/("state-at-rollback-"+str(time.time_ns())+".db"))
    override=Path("/etc/systemd/system/vpn-control-api.service.d/20-owner-run.conf")
    if override.exists():override.unlink()
    if same:
        for name,info in s["files"].items():
            if name.startswith("/run/systemd/transient/") or name.startswith("/run/nh1-panel-pilot/"):continue
            atomic(name,(w/"control"/name.lstrip("/")).read_bytes(),info["mode"],info["uid"],info["gid"])
        for name in ("state.db-wal","state.db-shm"):
            p=Path("/var/lib/vpn-control")/name
            if p.exists():p.unlink()
        source=w/"state-before-switch.db"
        if not source.exists():source=Path(s["core"]["directory"])/"files/var/lib/vpn-control/state.db"
        atomic("/var/lib/vpn-control/state.db",source.read_bytes(),0o600,981,981)
    run(["systemctl","disable","vpn-control-panel.service"],False)
    unit=Path("/etc/systemd/system/vpn-control-panel.service")
    if unit.exists():unit.unlink()
    run(["systemctl","daemon-reload"])
    run(["systemctl","start","vpn-control-api.service"])
    replay=w/"replay-readonly-frontend.sh"
    require(replay.is_file() and not replay.is_symlink(),"saved readonly replay missing")
    run(["/bin/sh",str(replay)])
    if same:run(["systemctl","start","vpn-control-worker@nh1.timer"])
    s["phase"]="rolled_back";s["rollback_mode"]="old_code" if same else "frontend_current_state_preserved";save(w,s)
    print("Control rollback completed; transport unchanged; mode="+s["rollback_mode"])
def complete():
    w,s=load();require(s["phase"]=="enabled","enabled state required")
    require(quiet()==s["baseline"] and observed()==s["observed"],"final protected state drift")
    require((w/"enabled-verified").is_file(),"enabled verification required")
    run(["systemctl","stop",s["guard"]+".timer"])
    s["phase"]="complete";save(w,s);print("W7 window complete; protected state and transport unchanged")
if __name__=="__main__":
    try:
        require(os.geteuid()==0,"root required")
        {"prepare":prepare,"switch":switch,"enable":enable,"rollback":rollback,"recover":lambda:rollback(True),"complete":complete}[sys.argv[1]]()
    except Exception as error:
        print("Control window stopped: "+str(error),file=sys.stderr);sys.exit(1)
