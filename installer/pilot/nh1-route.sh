#!/bin/bash
# Temporary nh1 route pilot. Run as root on the managed entry.
set -euo pipefail
umask 077
work=/run/nh1-panel-pilot
drop=/run/systemd/system/evpn-nh1-singbox.service.d
unit=evpn-nh1-singbox.service
src=/etc/empire-vpn/nh1/sing-box.json
bin=/opt/empire-vpn/bin
dest=/root/nh1-panel-pilot
exec 9>/run/lock/empire-vpn.lock
flock -n 9
test ! -e "$work" && test ! -e "$dest" && test ! -e "$drop/90-panel-pilot.conf" || exit 1
test ! -e /var/lib/empire-vpn/nh1/pending.json
systemctl is-active --quiet "$unit"
mkdir -m700 "$dest"
mkdir -m755 "$work"
cd "$work"
cat > rollback.sh <<'SH'
#!/bin/bash
set -eu
p=/run/systemd/system/evpn-nh1-singbox.service.d/90-panel-pilot.conf
if test -f "$p"; then
 rm -- "$p"
 systemctl daemon-reload
 systemctl restart evpn-nh1-singbox.service
fi
systemctl stop nh1-panel-readonly.service || true
SH
chmod 700 rollback.sh
trap 'bash "$work/rollback.sh"' ERR
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 14 -subj '/CN=nh1 temporary panel test CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign' -keyout ca.key -out "$dest/panel-ca.crt" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=panel.home.arpa' -keyout tls.key -out leaf.csr 2>/dev/null
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'subjectAltName=DNS:panel.home.arpa' 'extendedKeyUsage=serverAuth' 'keyUsage=digitalSignature,keyEncipherment' > extensions
openssl x509 -req -in leaf.csr -CA "$dest/panel-ca.crt" -CAkey ca.key -set_serial 1 -days 13 -sha256 -extfile extensions -out leaf.crt 2>/dev/null
rm -- ca.key
openssl rand -hex 24 > "$dest/owner-password.txt"
hash=$("$bin/caddy" hash-password < "$dest/owner-password.txt")
cat > Caddyfile <<EOF
{
 admin off
 auto_https off
 persist_config off
 log {
  output discard
 }
}
https://panel.home.arpa:18650 {
 bind 127.0.0.1
 tls $work/leaf.crt $work/tls.key
 basic_auth {
  owner $hash
 }
 header Cache-Control no-store
 respond "VPN Control: private pilot OK" 200
}
EOF
python3 - "$src" "$dest" <<'PY'
import json,sys,pathlib
src,dest=map(pathlib.Path,sys.argv[1:])
sb=json.loads(src.read_text())
assert sb['route']['final']=='wg-only'
assert sb['inbounds'][0]['tag']=='uot'
sb['outbounds'].append(dict(type='direct',tag='panel-only',bind_interface='lo'))
base=dict(inbound=['uot'],network='tcp',port=443,action='route',outbound='panel-only',override_address='127.0.0.1',override_port=18650)
sb['route']['rules'][:0]=[dict(base,domain=['panel.home.arpa']),dict(base,ip_cidr=['192.0.2.119/32'])]
pathlib.Path('candidate.json').write_text(json.dumps(sb))
p=json.loads(pathlib.Path('/var/lib/empire-vpn/nh1/master_user.sfa.json').read_bytes())
p['dns']['servers'].insert(0,dict(type='hosts',tag='pilot-dns',predefined={'panel.home.arpa':'192.0.2.119'}))
p['dns'].setdefault('rules',[]).insert(0,dict(domain=['panel.home.arpa'],server='pilot-dns',action='route'))
p['route']['rules'].insert(1,dict(ip_cidr=['192.0.2.119/32'],action='route',outbound='naive-out'))
(dest/'panel-test.json').write_text(json.dumps(p,indent=2))
PY
"$bin/sing-box" check -c candidate.json
"$bin/sing-box" check -c "$dest/panel-test.json" >/dev/null
chgrp evpn candidate.json
chmod 640 candidate.json
chmod 644 leaf.crt
sed 's|/run/nh1-panel-pilot/tls.key|{$CREDENTIALS_DIRECTORY}/key|' Caddyfile > Caddyfile.runtime
systemd-run --unit=nh1-panel-readonly --property=Type=exec --property=DynamicUser=yes --property=NoNewPrivileges=yes --property=ProtectSystem=strict --property=ProtectHome=yes --property=NetworkNamespacePath=/run/netns/naive --property=RuntimeDirectory=nh1-panel-caddy --setenv=HOME=/run/nh1-panel-caddy --property="LoadCredential=key:$work/tls.key" --property="LoadCredential=cfg:$work/Caddyfile.runtime" "$bin/caddy" run --adapter caddyfile --config /run/credentials/nh1-panel-readonly.service/cfg
code=$(ip netns exec naive curl --retry 5 --retry-connrefused -sS --resolve panel.home.arpa:18650:127.0.0.1 --cacert "$dest/panel-ca.crt" -o /dev/null -w '%{http_code}' https://panel.home.arpa:18650/)
test "$code" = 401
systemd-run --unit=nh1-panel-guard --on-active=15min /bin/bash "$work/rollback.sh"
mkdir -p "$drop"
cat > "$drop/90-panel-pilot.conf" <<EOF
[Service]
ExecStart=
ExecStart=$bin/sing-box run -c $work/candidate.json
EOF
systemctl daemon-reload
systemctl restart "$unit"
systemctl is-active --quiet "$unit"
openssl x509 -in "$dest/panel-ca.crt" -noout -fingerprint -sha256
