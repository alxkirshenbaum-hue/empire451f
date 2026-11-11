#!/bin/bash
# Bash 3.2 / standard macOS tools; no local Python or downloaded module bundle.
set +x
set -eu
BOOT='python3 -c exec\(__import__\(\'"'"'base64\'"'"'\).b64decode\(\'"'"'aW1wb3J0IHNpZ25hbCxoYXNobGliLGlvLGpzb24sb3Msc3lzLHR5cGVzLHVybGxpYi5yZXF1ZXN0LHppcGZpbGUKdHJ5OgogICAgaWYgb3MuZ2V0ZXVpZCgpIT0wOiByYWlzZSBSdW50aW1lRXJyb3IoJ3Jvb3QgcmVxdWlyZWQnKQogICAgcmVsZWFzZT1kaWN0KGxpbmUuc3BsaXQoJz0nLDEpIGZvciBsaW5lIGluIG9wZW4oJy9ldGMvb3MtcmVsZWFzZScpIGlmICc9JyBpbiBsaW5lKQogICAgaWYgcmVsZWFzZS5nZXQoJ0lEJywnJykuc3RyaXAoKS5zdHJpcCgnIicpIT0ndWJ1bnR1JyBvciByZWxlYXNlLmdldCgnVkVSU0lPTl9JRCcsJycpLnN0cmlwKCkuc3RyaXAoJyInKSBub3QgaW4gKCcyNC4wNCcsJzI2LjA0Jykgb3Igb3MudW5hbWUoKS5tYWNoaW5lIT0neDg2XzY0JzogcmFpc2UgUnVudGltZUVycm9yKCdVYnVudHUgMjQuMDQgb3IgMjYuMDQgYW1kNjQgcmVxdWlyZWQnKQogICAgZGVmIGV4cGlyZWQoKmFyZ3MpOiByYWlzZSBUaW1lb3V0RXJyb3IoIkJ1bmRsZSBkb3dubG9hZCB0aW1lZCBvdXQiKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQUxSTSxleHBpcmVkKQogICAgc2lnbmFsLmFsYXJtKDY1KQogICAgZGF0YT11cmxsaWIucmVxdWVzdC51cmxvcGVuKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vYWx4a2lyc2hlbmJhdW0taHVlL2VtcGlyZTQ1MWYvdjAuMi44L2Rpc3QvaW5zdGFsbGVyLnppcCcsdGltZW91dD02MCkucmVhZCgyKjEwMjQqMTAyNCkKICAgIHNpZ25hbC5hbGFybSgwKQogICAgaWYgaGFzaGxpYi5zaGEyNTYoZGF0YSkuaGV4ZGlnZXN0KCkhPSc2MTY0YjE2NGNlNWVjYmQ2MjJlYjk0YjFkYTcwN2YyM2U3MDViOWE1ZDMyZDlmMjE5OThjMjc5NDUzYzA2YjI1JzogcmFpc2UgUnVudGltZUVycm9yKCdJbnN0YWxsZXIgU0hBMjU2IG1pc21hdGNoJykKICAgIGFyY2hpdmU9emlwZmlsZS5aaXBGaWxlKGlvLkJ5dGVzSU8oZGF0YSkpCiAgICBidW5kbGU9e25hbWU6YXJjaGl2ZS5yZWFkKG5hbWUpLmRlY29kZSgndXRmLTgnKSBmb3IgbmFtZSBpbiBhcmNoaXZlLm5hbWVsaXN0KCl9CiAgICBmb3IgbmFtZSBpbiAoJ3JlbmRlcicsJ3JlbW90ZScsJ2NsaWVudCcsJ2NvbnRyb2xsZXInKToKICAgICAgICBtb2R1bGU9dHlwZXMuTW9kdWxlVHlwZShuYW1lKTsgbW9kdWxlLl9fZmlsZV9fPScvcnVuL2VtcGlyZS1zb3VyY2UvJytuYW1lKycucHknCiAgICAgICAgc3lzLm1vZHVsZXNbbmFtZV09bW9kdWxlCiAgICAgICAgaWYgbmFtZT09J2NvbnRyb2xsZXInOiBtb2R1bGUuQlVORExFPWJ1bmRsZQogICAgICAgIGV4ZWMoY29tcGlsZShidW5kbGVbbmFtZSsnLnB5J10sbmFtZSsnLnB5JywnZXhlYycpLG1vZHVsZS5fX2RpY3RfXykKICAgIHN5cy5leGl0KHN5cy5tb2R1bGVzWydjb250cm9sbGVyJ10ubWFpbihzeXMuYXJndlsxOl0pKQpleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICBwcmludCgnSW5zdGFsbGVyIGJvb3RzdHJhcCBmYWlsZWQ6ICcrdHlwZShlKS5fX25hbWVfXyxmaWxlPXN5cy5zdGRlcnIpCiAgICBzeXMuZXhpdCgxKQo=\'"'"'\)\)'
ask() {
 printf '[%s] %s [%s]: ' "$1" "$2" "${3:-}" >&2
 IFS= read -r answer || exit 130
 printf '%s' "${answer:-${3:-}}"
}
die() { printf '%s\n' "$*" >&2; exit 1; }
for tool in ssh ssh-keygen ssh-add openssl curl awk base64; do command -v "$tool" >/dev/null 2>&1 || die "Missing standard macOS tool: $tool"; done
resolve_target() {
 local prefix="$1" target="$2" output key value
 case "$target" in ''|-*|*[!A-Za-z0-9_.@:-]*) return 1;; esac
 case "$target" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) target="root@$target";; esac
 output=$(ssh -G "$target" 2>/dev/null) || return 1
 for key in hostname user port proxyjump hostkeyalias identityfile; do
  value=$(printf '%s\n' "$output" | awk -v k="$key" '$1==k{sub(/^[^ ]+ /,""); print; exit}')
  printf -v "${prefix}_${key}" '%s' "$value"
 done
}
for prefix in E X; do
 while :; do
  if [ "$prefix" = E ]; then target=$(ask Q03 'Entry root@IP or existing SSH alias'); else target=$(ask Q05 'Exit root@IP or existing SSH alias'); fi
  if resolve_target "$prefix" "$target"; then
   user_name="${prefix}_user"
   if [ "${!user_name}" = root ]; then break; fi
  fi
  printf '%s\n' 'Enter a valid root destination or SSH alias for root.' >&2
 done
 if [ "$prefix" = E ]; then ENTRY="$target"; else EXIT_NODE="$target"; fi
done
OWN_AGENT=0
trap 'if [ "$OWN_AGENT" = 1 ]; then ssh-agent -k >/dev/null 2>&1 || true; fi' EXIT
key_default=new
while :; do
while :; do
 IDENTITY=$(ask Q09 'Private SSH key path, new, or stop' "$key_default")
 [ "$IDENTITY" != stop ] || exit 0
 case "$IDENTITY" in
  new) break;;
  *.[pP][uU][bB]) printf '%s\n' 'This is a public key. Enter the private key path, usually the same name without .pub.' >&2; continue;;
  '~'*) IDENTITY="$HOME${IDENTITY#\~}";;
 esac
 [ -f "$IDENTITY" ] && break
 printf '%s\n' 'SSH key file not found. Enter an existing private key path.' >&2
done
if [ "$IDENTITY" = new ]; then
 IDENTITY="$HOME/.ssh/empire-install"
 if [ ! -f "$IDENTITY" ]; then mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; ssh-keygen -t ed25519 -a 100 -f "$IDENTITY"; fi
fi
case "$IDENTITY" in '~'*) IDENTITY="$HOME${IDENTITY#\~}";; esac
[ -f "$IDENTITY" ] || die 'SSH key file missing'
case "$IDENTITY" in *'"'*|*'\'*) die 'Unsupported SSH key path character';; esac
if ! ssh-keygen -y -P '' -f "$IDENTITY" >/dev/null 2>&1; then
 agent_code=0; ssh-add -l >/dev/null 2>&1 || agent_code=$?
 if [ "$agent_code" -eq 2 ]; then
  [ "$(ask Q21 'Start ssh-agent for this installer session? yes/no' yes)" = yes ] || continue
  eval "$(ssh-agent -s)" >/dev/null
  OWN_AGENT=1
 fi
 if ! ssh-add "$IDENTITY"; then
  printf '%s\n' 'Key was not unlocked. Press Enter at Q09 to retry, enter a different path, or type stop.' >&2
  key_default="$IDENTITY"; continue
 fi
fi
break
done
WORK=$(mktemp -d "${TMPDIR:-/tmp}/empire-launch.XXXXXX")
chmod 700 "$WORK"
CONFIG="$WORK/ssh-config"
RPC_PID=''
TOKEN=''
LOCAL_PORT=0
cleanup() {
 if [ -n "$RPC_PID" ]; then
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl --silent --noproxy '*' --max-time 2 --config - --data '{"action":"shutdown"}' "http://127.0.0.1:$LOCAL_PORT/" >/dev/null 2>&1 || true
  kill "$RPC_PID" 2>/dev/null || true
  wait "$RPC_PID" 2>/dev/null || true
 fi
 rm -f "$WORK/ssh-config" "$WORK/ready" "$WORK/rpc.err" "$WORK/check.out"
 rmdir "$WORK" 2>/dev/null || true
 if [ "$OWN_AGENT" = 1 ]; then ssh-agent -k >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
E_jump=''; X_jump=''; T_hostname=''; T_key="$IDENTITY"
write_node() {
 local name="$1" prefix="$2" key="$3" h="${2}_hostname" u="${2}_user" p="${2}_port" a="${2}_hostkeyalias"
 case "${!h}" in ''|*[!A-Za-z0-9_.:-]*) die 'Invalid resolved hostname';; esac
 printf 'Host %s\n HostName %s\n User %s\n Port %s\n IdentityFile "%s"\n' "$name" "${!h}" "${!u}" "${!p}" "$key"
 local target='' configured="${2}_identityfile" extra
 case "$name" in entry) target="$ENTRY";; exit) target="$EXIT_NODE";; esac
 case "$target" in ''|*@*|*:*|"${!h}") ;; *)
  extra="${!configured}"
  case "$extra" in '~/'*) extra="$HOME/${extra#\~/}";; esac
  if [ -f "$extra" ] && [ "$extra" != "$key" ]; then
   case "$extra" in *'"'*|*'\'*|*$'\n'*|*$'\r'*) die 'Unsupported alias SSH key path';; esac
   printf ' IdentityFile "%s"\n' "$extra"
  fi;;
 esac
 if [ -n "${!a}" ] && [ "${!a}" != none ]; then printf ' HostKeyAlias %s\n' "${!a}"; fi
}
write_config() {
 {
  printf '%s\n' 'Host *' ' StrictHostKeyChecking yes' ' BatchMode yes' ' ForwardAgent no' ' ExitOnForwardFailure yes' ' ConnectTimeout 12' ' ServerAliveInterval 10' ' ServerAliveCountMax 2' ' IdentitiesOnly yes' ' ControlMaster no' ' ControlPath none'
  write_node entry E "$IDENTITY"; [ -z "$E_jump" ] || printf ' ProxyJump %s\n' "$E_jump"
  write_node exit X "$IDENTITY"; [ -z "$X_jump" ] || printf ' ProxyJump %s\n' "$X_jump"
  [ -z "$T_hostname" ] || write_node transit T "$T_key"
 } > "$CONFIG"
 chmod 600 "$CONFIG"
}
bounded_check() {
 local pid result limit=$((SECONDS+25))
 ssh -n -T -F "$CONFIG" "$@" >"$WORK/check.out" 2>&1 &
 pid=$!
 while kill -0 "$pid" 2>/dev/null; do
  if [ "$SECONDS" -ge "$limit" ]; then kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; return 124; fi
  sleep 1
 done
 result=0; wait "$pid" || result=$?
 cat "$WORK/check.out"; return "$result"
}
probe() {
 local output
 printf 'Checking SSH: %s (up to 25 seconds)...\n' "$1" >&2
 if output=$(bounded_check "$1" true); then printf ok; return; fi
 case "$output" in
  *'REMOTE HOST IDENTIFICATION HAS CHANGED'*) printf changed-key;;
  *'Host key verification failed'*|*'host key is known'*) printf identity;;
  *'Permission denied'*|*'authentication failed'*|*'sign_and_send_pubkey'*) printf authentication;;
  *) printf network;;
 esac
}
authenticate() {
 local role="$1" status choice public cmd
 status=$(probe "$role")
 [ "$status" != changed-key ] || die 'SSH host identity changed; check provider console. No automatic replacement.'
 if [ "$status" = identity ]; then
  printf 'Compare %s SSH fingerprint with provider console.\n' "$role" >&2
  ssh -F "$CONFIG" -o BatchMode=no -o StrictHostKeyChecking=ask "$role" true >&2 || true
  status=$(probe "$role")
 fi
 while [ "$status" = authentication ]; do
  choice=$(ask Q17 "$role: password / console / retry / stop" retry)
  if [ "$choice" = retry ]; then
   local retry_key="$IDENTITY" candidate='' target=''
   case "$role" in entry) candidate="$E_identityfile"; target="$ENTRY";; exit) candidate="$X_identityfile"; target="$EXIT_NODE";; esac
   case "$candidate" in '~/'*) candidate="$HOME/${candidate#\~/}";; esac
   case "$target" in *@*|*:*) ;; *) [ ! -f "$candidate" ] || retry_key="$candidate";; esac
   ssh-add "$retry_key" >&2 || true
  elif [ "$choice" = password ] || [ "$choice" = console ]; then
   public=$(ssh-keygen -y -f "$IDENTITY" | awk '{print $1" "$2}')
   case "$public" in *[!A-Za-z0-9+/=._\ -]*) die 'Invalid public key';; esac
   cmd="set -eu; . /etc/os-release; case \$ID:\$VERSION_ID:\$(uname -m) in ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;; *) exit 41;; esac; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; grep -qxF '$public' ~/.ssh/authorized_keys || printf '%s\\n' '$public' >> ~/.ssh/authorized_keys"
   if [ "$choice" = console ]; then printf '%s\n' "$cmd" >&2; [ -n "$(ask Q17 'Run PUBLIC-key command in provider console, then type done' done)" ];
   else ssh -F "$CONFIG" -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive "$role" "$cmd" >&2; fi
  elif [ "$choice" = stop ]; then die 'Stopped at SSH authorization.'; else continue; fi
  status=$(probe "$role")
 done
 printf '%s' "$status"
}
write_config
E_status=$(authenticate entry); X_status=$(authenticate exit)
for role in entry exit; do
 if [ "$role" = entry ]; then prefix=E; other=exit; other_status="$X_status"; else prefix=X; other=entry; other_status="$E_status"; fi
 status_name="${prefix}_status"; jump_name="${prefix}_proxyjump"
 while [ "${!status_name}" = network ]; do
  host_name="${prefix}_hostname"; choices=0; default=0
  printf 'Direct SSH to %s (%s) failed. Choose how this computer should reach it.\n' "$role" "${!host_name}" >&2
  case "${!jump_name}" in ''|none|*,*) ;; *)
   printf '  1  Connect via %s (from your SSH settings)\n' "${!jump_name}" >&2
   choices="$choices/1"; default=1;;
  esac
  if [ "$other" = entry ]; then other_host="$E_hostname"; other_jump="$E_jump"; else other_host="$X_hostname"; other_jump="$X_jump"; fi
  if [ "$other_status" = ok ] && [ -z "$other_jump" ]; then
   printf '  2  Connect via the %s server (%s)\n' "$other" "$other_host" >&2
   choices="$choices/2"; [ "$default" != 0 ] || default=2
  fi
  printf '  0  Stop setup\n' >&2
  while :; do
   choice=$(ask Q18 "Enter $choices" "$default")
   case "$choice" in 0) die 'Setup stopped at SSH route selection.';; 1|2) case "/$choices/" in *"/$choice/"*) break;; esac;; esac
  done
  if [ "$choice" = 1 ]; then
   case "${!jump_name}" in ''|none|*,*) die 'Single-hop configured ProxyJump unavailable';; esac
   resolve_target T "${!jump_name}" || { printf '%s\n' 'Cannot resolve saved jump host; choose another route.' >&2; continue; }
   case "$T_identityfile" in '~'*) T_identityfile="$HOME${T_identityfile#\~}";; esac
   [ ! -f "$T_identityfile" ] || T_key="$T_identityfile"
   printf -v "${prefix}_jump" '%s' transit
  elif [ "$choice" = 2 ]; then printf -v "${prefix}_jump" '%s' "$other"
  else die 'No reachable SSH route selected'; fi
  write_config
  route_status=$(authenticate "$role") || exit 1
  printf -v "$status_name" '%s' "$route_status"
  if [ "$route_status" = network ]; then
   printf 'Route %s did not reach %s. Choose another route, retry, or enter 0 to stop.\n' "$choice" "$role" >&2
   printf -v "${prefix}_jump" '%s' ''
  fi
 done
 [ "${!status_name}" = ok ] || die "$role: SSH ${!status_name}; no deployment changes"
done
export LC_EVPN_PROBE=1
for role in entry exit; do
 while :; do
  printf 'Checking Ubuntu, Python and SSH environment: %s (up to 25 seconds)...\n' "$role" >&2
  status=0
 result=$(bounded_check -o SendEnv=LC_EVPN_PROBE "$role" 'set -eu; . /etc/os-release; case $ID:$VERSION_ID:$(uname -m):$(id -u) in ubuntu:24.04:x86_64:0|ubuntu:26.04:x86_64:0) ;; *) exit 41;; esac; test x${LC_EVPN_PROBE:-} = x1 || exit 43; if command -v python3 >/dev/null; then echo READY; else echo MISSING_PYTHON; fi') || status=$?
  case "$status:$result" in 0:READY|0:MISSING_PYTHON) break;; esac
  printf 'Platform check failed on %s (code %s; 41=platform, 43=SSH environment, 124=timeout).\n' "$role" "$status" >&2
  [ "$(ask Platform 'Retry this check or stop?' retry)" != stop ] || exit 1
 done
 if [ "$result" = MISSING_PYTHON ]; then
  [ "$(ask Q22 "$role: install python3 on VPS? Type INSTALL-PYTHON")" = INSTALL-PYTHON ] || die 'VPS Python bootstrap declined'
  ssh -F "$CONFIG" "$role" 'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; timeout -k 15s 600 apt-get update && timeout -k 15s 1200 apt-get install -y --no-install-recommends python3'
 fi
done
read_client_export() {
while :; do
IMPORT=$(ask Q13 'Optional LOCAL client export path; empty = existing/new credentials on entry')
LC_EVPN_CLIENTS=''
if [ -n "$IMPORT" ]; then
 case "$IMPORT" in '~'*) IMPORT="$HOME${IMPORT#\~}";; esac
 if [ ! -r "$IMPORT" ] || [ ! -f "$IMPORT" ] || [ "$(wc -c < "$IMPORT" | tr -d ' ')" -gt 64000 ]; then printf '%s\n' 'Enter a readable export path (maximum 64000 bytes).' >&2; continue; fi
 LC_EVPN_CLIENTS=$(base64 < "$IMPORT" | tr -d '\n')
fi
break
done
}
read_client_export
TOKEN=$(openssl rand -hex 32)
export LC_EVPN_TOKEN="$TOKEN" LC_EVPN_SESSION="$(openssl rand -hex 16)" LC_EVPN_CLIENTS
random_port() { local hex; hex=$(openssl rand -hex 2); printf '%s' "$((30000 + 16#$hex % 29000))"; }
LOCAL_PORT=$(random_port); RPC_PORT=$(random_port); RELAY_PORT=$(random_port)
start_rpc() {
 printf '%s\n' 'Opening exit SSH tunnel and loading installer on exit (up to 90 seconds)...' >&2
 rm -f "$WORK/ready"; mkfifo "$WORK/ready"
 (unset LC_EVPN_CLIENTS; exec ssh -n -F "$CONFIG" -o SendEnv=LC_EVPN_TOKEN -L "127.0.0.1:$LOCAL_PORT:127.0.0.1:$RPC_PORT" exit "$BOOT rpc $RPC_PORT") > "$WORK/ready" 2> "$WORK/rpc.err" &
 RPC_PID=$!
 IFS= read -r -t 90 ready < "$WORK/ready" || die 'Exit RPC bootstrap failed: check VPS Git HTTPS access and AcceptEnv LC_*'
 [ "$ready" = EVPN_RPC_READY ] || die 'Unexpected RPC handshake'
}
run_wizard() {
 printf 'Opening interactive wizard on entry: %s ...\n' "$1" >&2
 ssh -F "$CONFIG" -tt -o SendEnv=LC_EVPN_TOKEN -o SendEnv=LC_EVPN_SESSION -o SendEnv=LC_EVPN_CLIENTS -R "127.0.0.1:$RELAY_PORT:127.0.0.1:$LOCAL_PORT" entry "$BOOT wizard $RELAY_PORT $1"
}
fresh_sessions() { [ "$(probe entry)" = ok ] && [ "$(probe exit)" = ok ]; }
wait_reboot() {
 sleep 8
 local deadline=$((SECONDS+240))
 while [ "$SECONDS" -lt "$deadline" ]; do [ "$(probe "$1")" != ok ] || return 0; sleep 5; done
 die "$1: SSH did not recover; use provider console"
}
start_rpc
while :; do
 code=0; run_wizard start || code=$?
 [ "$code" = 46 ] || break
 read_client_export
done
if [ "$code" -eq 42 ]; then
 if fresh_sessions; then code=0; run_wizard finish || code=$?; else run_wizard abort || true; die 'New SSH session failed; rollback requested'; fi
fi
if [ "$code" -eq 44 ]; then
 wait_reboot exit
 kill "$RPC_PID" 2>/dev/null || true; wait "$RPC_PID" 2>/dev/null || true
 start_rpc
 code=0; run_wizard after-exit-reboot || code=$?
fi
if [ "$code" -eq 45 ]; then wait_reboot entry; fresh_sessions || die 'SSH did not recover'; code=0; run_wizard after-entry-reboot || code=$?; fi
[ "$code" -eq 0 ] || die "Installer exited $code; if apply started, check server rollback timers"
fresh_sessions || die 'Final SSH check failed'
printf 'New key-authenticated SSH sessions to both nodes: PASS\n'
