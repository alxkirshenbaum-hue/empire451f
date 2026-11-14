# Verified user-operation worker

User changes use the verified Unix reload strategy; the runtime has no automatic service-restart fallback. The shared English `caddy.ApplyNotice` is emitted to stderr before CLI queue submission and must also be used by W5 mutation commands and W7 previews. It warns that uninterrupted service is not guaranteed, revocation affects new connections while existing tunnels may remain open, and a service restart interrupts VPN traffic and needs separate approval. The shared notice and W5 operations are deployed in the approved W7 control-plane window; see W7_PRODUCTION_WINDOW_2026-11-14.md.

`vpnctl worker once --installation nh1 --owner-run APPROVED_RUN_UUID` processes one operation or its recovery. It reports only an operation ID and `completed`/`idle`. It does not perform migration cutover or enable a Caddy socket. The nh1 worker/API were installed and enabled in the approved [G3 window](G3_ACCEPTANCE_2026-11-13.md); this is not an instruction to rerun that window.

The root-owned, mode 0600 policy is `/etc/vpn-control/worker-nh1.json`. It contains `installation`, `owner_run`, `socket`, `helper`, `validate_command`, and `probe_command`. Commands are argument arrays with absolute canonical executable paths; absolute file arguments and the helper must be root-owned and not group/world writable. Symlink policy/executable paths and unknown policy fields are rejected. Requests cannot supply policy paths or commands.

The approved validation command must enter the existing `naive` namespace and drop to the dedicated Caddy UID/GID with an empty capability bounding set before running the installed Caddy `validate --config -`. Resolve actual `ip`, `setpriv`, Python and binary paths during G3 preparation. The dedicated account, readable certificate/storage paths and protected admin directory must be rehearsed before approval; this document does not authorize their creation.

`probe_command` runs the installed `create_probe.py --policy /etc/vpn-control/probe-nh1.json`. Candidate login/password travel only on stdin. Its root-owned mode 0600 policy contains:

| Field | Meaning |
|---|---|
| `address`, `port`, `domain` | Entry IP, HTTPS port and TLS server name |
| `binary` | Absolute installed sing-box binary |
| `auth_file`, `canary_login` | Managed auth path and unchanged independent control login |
| `scratch_dir` | Existing root-owned 0700 probe directory under `/run/vpn-control` |
| `site_sha256` | Reviewed SHA-256 of the site's response body |
| `tcp_mode` | `exit_https` for the real pair; requires `expected_exit` |
| `udp_mode`, `udp_host`, `udp_port` | `dns` and the configured IPv4 resolver/53 for the real pair |
| `ca_file` | Optional trusted CA for isolated staging; never disables TLS verification |

Staging also supports `tcp_mode=echo` with `tcp_host`/`tcp_port` and `udp_mode=echo`. Probe clients use only the Naive outbound with UoT v2. Each check creates fresh clients, verifies the site before/after, checks TCP/UoT for candidate and canary, rejects a random wrong password, and rechecks the canary after the negative trial. It does not change WG, routes or firewall and does not test failure injection on the live pair. `verify.py` supplies the existing SOCKS/TCP/UoT helpers.

Install the scripts together in a root-owned directory: `owned_auth.py`, `create_probe.py`, `inspect_legacy.py`, `handoff_legacy.py`, `return_legacy.py`, `render.py`, `verify.py`. Deployment must pin their reviewed hashes. The Caddy socket permits owner access only (no group/other bits, owner-write required), in a mode 0700 directory owned by the dedicated Caddy account. Record the actual socket mode from the installed Caddy; Web UI and sing-box must have different identities and no access.

`systemd/vpn-control-worker@.service` and `.timer` are deployment templates. The timer polls every two seconds. The environment file supplies only `OWNER_RUN`; it is root-owned mode 0600. The service uses systemd's default root identity: the observed target systemd drops effective CAP_SETUID with explicit User=root, preventing validator setpriv. The child validator still drops to the dedicated Caddy UID with an empty bounding set. The service needs the protected files and scratch paths declared by `ReadWritePaths`. Installation/enabling, account/ACL changes and the initial Caddy restart were performed in G3. No auto-restart/redeployment is performed by the CLI.

Isolated probe regression: `python3 -B pilot/worker_probe_check.py` under `systemd-run` with `PrivateNetwork=yes`; it refuses any interface other than loopback. It reuses `pilot/recovery_probe.py` and installed Caddy/sing-box. This checks the shipped probe through stdin, TLS/site, new/control TCP/UoT, wrong-password rejection, changed-site rejection and a synthetic profile in the shared harness. It does not replace the full queue/download/return-to-installer rehearsal or phone acceptance.

## Explicit SSH reconciliation

Use the same fixed policy, installation lock, Prepared and file journal:
vpnctl worker reconcile --installation ID --owner-run RUN --operation OP --decision complete
vpnctl worker reconcile --installation ID --owner-run RUN --operation OP --decision rollback

These root-only commands are explicit recovery decisions, never scheduled by the
timer or callable via the HTTP client. Complete requires the exact candidate plus
fresh operation-specific probes before CAS completion; it does not repeat load.
Rollback refuses third-party live drift, restores only the bound preimage,
checks previous credentials/control/TLS/site and restores both files before
recording rolled_back. Staged ciphertext is retained; no fresh password is
generated. Failed proof leaves the queue blocked. Missing/damaged snapshots
require manual SSH inspection rather than guessed reconstruction.
A repeated completed decision checks registry/files and the full live baseline.
These commands are now deployed with the W7 package. Explicit production recovery still requires an administrator decision and live evidence; the timer never chooses an ambiguous recovery decision.

## Current nh1 deployment — W7, 2026-11-14

The same executor handles create/disable/enable/rotate/delete; revoke aliases
disable. No second adapter/journal/daemon was introduced.
Binaries are the tested cd3de10 build; helpers are installed under
/opt/empire-vpn/controlpanel/ad6b6532ae75ec0720f692314f626e97524cc44d.
The existing worker unit6621689/default root identity was preserved.
Actual API socket: /run/vpn-control-api/api.sock; set VPNCTL_SOCKET for owner CLI.
Owner-run is supplied by the existing protected env/policy, never request input.
New private frontend is vpn-control-panel.service. Original TLS/CA and owner
credentials were reused. No transport reload/restart or agent user mutation
occurred during this control-plane window. G6/G7 remain open pending phone.