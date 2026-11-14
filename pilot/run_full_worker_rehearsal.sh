#!/bin/sh
# Root-only synthetic runner; never invokes a production unit or deployment.
set -eu
case "${1:-}" in normal|return_before|create_sqlite|lost_response|cutover_probe|cutover_sqlite|cutover_source|cutover_abort) ;; *) exit 2;; esac
case "${2:-}" in ''|*[!0-9]*) exit 2;; esac
test "$(id -u)" = 0
project=${VPN_REHEARSAL_PROJECT:-/run/vpn-w3-worker-tests}
root=$project/rehearsal-root-$2
python3 -B "$project/pilot/prepare_rehearsal_root.py" "$root"
case "$1" in
 return_before) option=VPN_REHEARSAL_RETURN_BEFORE=1;;
 create_sqlite) option=VPN_REHEARSAL_FAILURE=sqlite;;
 lost_response) option=VPN_REHEARSAL_FAILURE=lost_response;;
 cutover_*) option=VPN_REHEARSAL_CUTOVER_FAILURE=${1#cutover_};;
 *) option=VPN_REHEARSAL_FAILURE=none;;
esac
if [ "${VPN_REHEARSAL_UI:-0}" = 1 ]; then
 run_flags="--quiet"
else
 run_flags="--quiet --wait --pipe"
fi
systemd-run $run_flags --unit="vpn-full-worker-root-$2" \
 -p "RootDirectory=$root" -p MountAPIVFS=yes -p PrivateNetwork=yes \
 -p PrivateDevices=yes -p NoNewPrivileges=yes -p ProtectSystem=strict \
 -p ReadWritePaths=+/etc -p ReadWritePaths=+/var/lib -p ReadWritePaths=+/run \
 -p ReadWritePaths=+/tmp -p ReadWritePaths=+/root -p "Environment=$option" -p "Environment=VPN_REHEARSAL_MUTATIONS=${VPN_REHEARSAL_MUTATIONS:-0}" -p "Environment=VPN_REHEARSAL_UI=${VPN_REHEARSAL_UI:-0}" \
 -p BindReadOnlyPaths=/usr -p BindReadOnlyPaths="$project/rehearsal-source/local:/usr/local" \
 -p BindReadOnlyPaths=/opt/empire-vpn/bin -p BindReadOnlyPaths=/etc/ssl \
 -p BindReadOnlyPaths="$project/rehearsal-source:/work" -p WorkingDirectory=/work \
 /usr/bin/python3 -B /work/pilot/full_worker_rehearsal.py
