"""Prepare/verify a secret-free pinned package; never install or restart."""
import argparse, hashlib, json, re
from pathlib import Path
HELPERS=("owned_auth.py","create_probe.py","inspect_legacy.py","handoff_legacy.py","return_legacy.py","render.py","verify.py")
def require(value,label):
    if not value:raise ValueError(label)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(output):
    require(output.is_dir() and not output.is_symlink(),"regular bundle directory required")
    path=output/"manifest.json";require(path.is_file() and not path.is_symlink(),"manifest missing")
    manifest=json.loads(path.read_text())
    require(manifest.get("format")==1 and re.fullmatch("[0-9a-f]{40}",manifest.get("revision","")),"invalid format/revision")
    expected={"manifest.json"}
    for item in manifest["files"]:
        relative=Path(item["path"]);require(not relative.is_absolute() and ".." not in relative.parts,"unsafe path")
        path=output/relative
        require(path.is_file() and path.resolve()==path.absolute(),"missing/symlinked bundle file")
        require(digest(path)==item["sha256"] and path.stat().st_size==item["size"],"digest mismatch: "+str(relative))
        require(path.stat().st_mode&0o777==item["mode"],"mode mismatch: "+str(relative))
        expected.add(relative.as_posix())
    require({p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}==expected,"unexpected file")
    return manifest
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--project",type=Path);parser.add_argument("--revision")
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--verify",action="store_true")
    args=parser.parse_args();output=args.output.absolute()
    if args.verify:
        print("Upgrade bundle verified: "+verify(output)["revision"]);return
    require(args.project and args.revision and re.fullmatch("[0-9a-f]{40}",args.revision),"pinned project/revision required")
    project=args.project.resolve()
    require(not output.exists() and output.parent.is_dir() and output.parent.resolve()==output.parent,"new canonical output directory required")
    output.mkdir(mode=0o700);records=[]
    def put(name,body,mode=0o644):
        path=output/name;path.parent.mkdir(mode=0o755,parents=True,exist_ok=True);path.write_bytes(body);path.chmod(mode)
        records.append(dict(path=name,sha256=digest(path),size=path.stat().st_size,mode=mode))
    def source(name,relative,mode=0o644):
        path=project/relative;require(path.is_file() and not path.is_symlink(),"missing reviewed source: "+str(relative))
        put(name,path.read_bytes(),mode)
    for name in ("vpn-control","vpnctl"):source("bin/"+name,"rehearsal-bin/"+name,0o755)
    for name in HELPERS:source("helpers/"+name,name)
    for name in ("vpn-control-panel.service","vpn-control-worker@.service","vpn-control-worker@.timer"):
        source("systemd/"+name,"controlpanel/systemd/"+name)
    source("WINDOW.md","controlpanel/W7_UPGRADE_WINDOW.md")
    source("replay-readonly-frontend.sh","pilot/replay_readonly_frontend.sh",0o700)
    config=(project/"templates/panel-frontend.Caddyfile").read_text()
    require(config.count("@API_SOCKET@")==1,"unexpected frontend template")
    put("private-panel.Caddyfile",config.replace("@API_SOCKET@","/run/vpn-control-api/api.sock").encode())
    put("systemd/20-owner-run.conf",b"""[Service]
EnvironmentFile=/etc/vpn-control/worker-nh1.env
ExecStart=
ExecStart=/usr/local/bin/vpn-control --db /var/lib/vpn-control/state.db --socket /run/vpn-control-api/api.sock --profile-domain ${PROFILE_DOMAIN} --vault-key-file /var/lib/vpn-control/vault.key --owner-run ${OWNER_RUN}
""")
    source("sfa-template.json","templates/sfa-profile.json")
    manifest=dict(format=1,revision=args.revision,files=records,source_template_sha256=digest(output/"sfa-template.json"),
                  helper_destination="/opt/empire-vpn/controlpanel/"+args.revision,api_socket="/run/vpn-control-api/api.sock",
                  installation="nh1",requires_production_approval=True)
    path=output/"manifest.json";path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n");path.chmod(0o600)
    verify(output)
    print("Upgrade bundle prepared; installation NOT performed: "+args.revision)
    print("Payload bytes: "+str(sum(x["size"] for x in records)))
if __name__=="__main__":main()
