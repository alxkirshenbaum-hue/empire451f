#!/bin/sh
# Approved-window rollback of the readonly endpoint only; no transport changes.
set -eu
test "$(id -u)" = 0
test -S /run/netns/naive || test -f /run/netns/naive
test -f /run/nh1-panel-pilot/Caddyfile.runtime
test -f /run/nh1-panel-pilot/tls.key
test -f /run/nh1-panel-pilot/leaf.crt
if systemctl is-active --quiet nh1-panel-readonly.service; then
 echo "Readonly frontend is already active" >&2
 exit 1
fi
# Stop the new endpoint separately within the approved window first.
# Deliberately never stop a unit, regenerate TLS or touch the relay here.
systemd-run --unit=nh1-panel-readonly --property=Type=exec \
 --property=DynamicUser=yes --property=NoNewPrivileges=yes \
 --property=ProtectSystem=strict --property=ProtectHome=yes \
 --property=NetworkNamespacePath=/run/netns/naive \
 --property=RuntimeDirectory=nh1-panel-caddy --setenv=HOME=/run/nh1-panel-caddy \
 --property=LoadCredential=key:/run/nh1-panel-pilot/tls.key \
 --property=LoadCredential=cfg:/run/nh1-panel-pilot/Caddyfile.runtime \
 /opt/empire-vpn/bin/caddy run --adapter caddyfile \
 --config /run/credentials/nh1-panel-readonly.service/cfg