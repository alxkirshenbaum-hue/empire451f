# W7 upgrade window — prepared procedure, not authorization

Scope for a future approval: nh1 API/worker/control-plane maintenance and the
private HTTPS frontend. No production command below was run during preparation.
Transport Caddy/relay/WG/firewall/routes/SSH/reboot are outside this switch.
Production user CRUD requires a separate scope; no agent-created canary by default.
G6/G7 remain open until the actual required observations.

## Pinned package

prepare_panel_upgrade.py creates a NEW private directory containing binaries,
versioned helper sources, frontend Caddyfile, API drop-in, worker units, public
template and this procedure. manifest.json binds source revision and each file
SHA256/size/mode; verify again before installation and capture its digest in a
root-only window receipt. The package contains no production DB/vault/profile,
TLS key/certificate, owner password or policy secrets.

Install bin/* atomically to /usr/local/bin; helpers/* root-owned into the
versioned manifest.helper_destination. Never replace files under the old
69e4708 version label. Actual private API socket is /run/vpn-control-api/api.sock,
0600 UID981, parent0700; generic CLI default requires VPNCTL_SOCKET override.

## Before any stop

1. Verify fresh entry/exit SSH sessions, keep an independent entry session.
   Confirm live generation/current users/current credential versions, registry
   integrity, no unfinished operations or prepared/file journals. Recheck
   versions/identities/capabilities and available disk for both versions.
2. Coordinate no concurrent installer/vpn-add-user/root CLI writer for the
   window; inspect active writers/shared lock and abort on unfinished work.
   Do not hold an external flock while invoking a command that takes it.
3. Reuse g3_snapshot.snapshot with a NEW window UUID/pre phase. It performs
   SQLite online backup under the existing shared lock. Encrypt/decrypt/hash
   verify off-node through the existing owner snapshot workflow BEFORE switch.
   Preserve owner keys/passwords and CURRENT active users.
4. Save root-only exact old binaries, helper policy, API/worker units/drop-ins/
   env, modes/ACL/identity and enabled/active state. Capture the OLD transient
   nh1-panel-readonly unit and its credential sources BEFORE stopping it.
   A stopped transient unit cannot simply be assumed restartable. Capture and
   rehearse its replayable invocation with the exact existing paths/properties.
5. Preserve existing leaf/key byte-for-byte. Existing leaf expires
   2026-11-25 11:19:54 UTC. Never regenerate owner's private CA or credentials.
6. Verify the package template checksum matches the already approved source
   revision. Mismatch aborts for review; do not replace an immutable source.

## Approved switch

Pause worker timer, wait for its oneshot, recheck no pending auth state.
Stop API and old readonly frontend ONLY in the approved control-plane window.
Save final fresh SQLite backup and baseline generation/user/credential digests
with administrative writers quiesced.

Install pinned binaries/helpers with fsync/atomic rename and prescribed modes.
In the root-only worker policy replace ONLY the old reviewed helper-directory
prefix with manifest.helper_destination (helper/probe argument paths included).
Preserve owner_run, admin socket and validator identity/capability restrictions.
Do not add explicit User=root to the worker: it broke effective CAP_SETUID.

Run the existing canonical command against the reviewed existing source/hash:
vpnctl registry init --installation nh1 --sfa-template SOURCE --approve-sha256 SHA256
This reuses vault.key/owner, migrates schema and installs immutable policy2
variants. No owner bootstrap, key generation, import or repeated cutover.
Assert original users/logins/credential versions/digests/source IDs/bindings
and live generation unchanged, only intended immutable variants/mappings added.

Copy EXISTING leaf.crt/tls.key to /etc/vpn-control/private-panel, root-only,
and install the package Caddyfile there. Do not print the key.
Start new API initially WITHOUT the owner-run override: writes remain disabled.
Start candidate private TLS frontend in naive with UID981/empty capabilities.
Prove TLS/trust/SNI, no-store/same-origin, owner login, unauthorized401/admin404,
API socket access and vault/proc-root/admin denial. Ordinary VPN credentials
do not confer admin rights. External IP/Host/SNI spoof must fail. Check new SSH.

Only after checks and approval scope allowing mutation capability, activate
20-owner-run.conf and restart API, then start existing worker timer and verify
idle/no-reconcile. Enabling owner features is not authorization for agent
production CRUD. Carry out separately agreed phone/profile observations.

## Rollback

After ANY new user/credential change, default to FRONTEND rollback:
freeze new owner writes by removing the API owner-run override/restarting API
within approved recovery scope; resolve/reconcile any current operation before
pausing worker; recreate the captured readonly HTTPS frontend. Preserve CURRENT
SQLite/vault/auth/generation/profiles and new binaries/helpers. This keeps new
users and credentials. Capture a fresh encrypted current-state snapshot.

Full old-code/database rollback is allowed ONLY before any user mutation and
only when exact current user/credential/generation checks still match the fresh
window baseline. Preserve new DB/audit/session/issuance evidence root-only,
stop new control plane, restore fresh window SQLite and old binaries/policy/
units atomically, recreate captured transient frontend, restore prior states,
verify fresh known-user connections. Never restore historical G3 pre-auth.

After user changes, full return needs the existing CURRENT active-user reverse
export and journaled G3 return mechanism, with fresh snapshot and verification.
Do not improvise a schema downgrade. Unknown live/SQLite/file result remains
reconcile_required for explicit SSH recovery; no automatic restart fallback.

## Verification limits

Bundle hash/mode checks, systemd syntax and real copy API/CLI/browser/TLS tests
are separately recorded. They do not prove an unexecuted production switch.
The exact captured transient replay, fresh encrypted window receipts and phone
observations must be finalized before/inside the separately approved window.
G6/G7/E1 must not be accepted merely because a package exists.

The package includes replay-readonly-frontend.sh, the isolated frontend command
from pilot/nh1-route.sh (only the systemd-run line, never the deploy/switch
script). It creates no TLS/owner credential and never stops a unit or touches
the relay. It requires existing pilot certificate/config/key paths. Compare
it with the captured CURRENT transient unit before approval; drift aborts.
Its shell syntax is checked during package validation; production replay has
not been executed.