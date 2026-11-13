# Verified create worker

`vpnctl worker once --installation nh1 --owner-run APPROVED_RUN_UUID` processes one operation or its recovery. It reports only an operation ID and `completed`/`idle`. It does not perform migration cutover or enable a Caddy socket. No production worker is enabled by this change.

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

Install the scripts together in a root-owned directory: `owned_auth.py`, `create_probe.py`, `inspect_legacy.py`, `handoff_legacy.py`, `return_legacy.py`, `render.py`, `verify.py`. Deployment must pin their reviewed hashes. The Caddy socket is mode 0600 in a private directory owned by the dedicated Caddy account; Web UI and sing-box must have different identities and no access.

`systemd/vpn-control-worker@.service` and `.timer` are uninstalled templates. The timer polls every two seconds. The environment file supplies only `OWNER_RUN`; it is root-owned mode 0600. The service needs the protected files and scratch paths declared by `ReadWritePaths`. First installation/enabling, account/ACL changes and the initial Caddy restart belong to the single G3 approval package. No auto-restart/redeployment is performed by the CLI.

Isolated probe regression: `python3 -B pilot/worker_probe_check.py` under `systemd-run` with `PrivateNetwork=yes`; it refuses any interface other than loopback. It reuses `pilot/recovery_probe.py` and installed Caddy/sing-box. This checks the shipped probe through stdin, TLS/site, new/control TCP/UoT, wrong-password rejection, changed-site rejection and a synthetic profile in the shared harness. It does not replace the full queue/download/return-to-installer rehearsal or phone acceptance.
