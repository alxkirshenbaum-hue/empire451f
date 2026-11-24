#!/bin/bash
set -euo pipefail
if [[ $${1:-start} == stop ]]; then
 ip netns del naive 2>/dev/null || true
 ip link del ${host_if} 2>/dev/null || true
 exit 0
fi
ip netns add naive
ip netns exec naive sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip netns exec naive sysctl -q -w net.ipv6.conf.default.disable_ipv6=1
ip netns exec naive nft -f ${base}/namespace.nft
ip -n naive link set lo up
ip link add ${host_if} type veth peer name ${app_if}
ip link set ${app_if} netns naive
ip addr add ${rh}/30 dev ${host_if}
ip -n naive addr add ${ra}/30 dev ${app_if}
ip link set ${host_if} up
ip -n naive link set ${app_if} up
# Create the UDP socket in the host namespace, then move the interface.
ip link add wg0 type wireguard
ip link set wg0 netns naive
ip netns exec naive wg set wg0 private-key ${key_path} peer ${peer} allowed-ips 0.0.0.0/0 endpoint ${exit_addr}:${wg_port} persistent-keepalive 25
ip -n naive addr add ${te}/30 dev wg0
ip -n naive link set wg0 mtu ${mtu} up
ip -n naive route add default dev wg0
