#!/bin/bash
set -euo pipefail
if [[ $${1:-start} == stop ]]; then
 ip link del ${exit_if} 2>/dev/null || true
 exit 0
fi
ip link add ${exit_if} type wireguard
wg set ${exit_if} private-key ${key_path} listen-port ${wg_port} peer ${peer} allowed-ips ${te}/32
ip addr add ${tx}/30 dev ${exit_if}
ip link set ${exit_if} mtu ${mtu} up
sysctl -q -w net.ipv4.ip_forward=1
