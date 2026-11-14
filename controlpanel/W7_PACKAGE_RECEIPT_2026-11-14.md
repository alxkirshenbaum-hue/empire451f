# W7 package receipt — 2026-11-14

Prepared and verified on copies, NOT deployed. W7 3/4/G7 OPEN; W6 3/4/G6 OPEN.

## Exact payload and provenance

Source/package: ad6b6532ae75ec0720f692314f626e97524cc44d.
Directory: /opt/empire-vpn/cache/w7-pinned-ad6b653/upgrade-bundle.
[Public manifest](W7_PACKAGE_MANIFEST_ad6b653.json):19files/33,306,900bytes.
This is package size, not full E1 disk-budget/resource acceptance.

Manifest SHA256:
e512a536a57256dbaff7025991621551cda11687b14423ebb9ce5abb281b6ba0.
vpnctl SHA256:
fc9c04642431149860b6c16f1aca997c8871ebdbefb409169462d1c988b6513d.
vpn-control SHA256:
3a0aace4b2adf1fdd78361564042f0ee59428bb0df5a16eaf727abc21e95be68.

Binaries are byte-identical copies of the tested build cd3de10.
Product cmd/internal/migrations/systemd/go.mod/go.sum, templates, shipped
Python helpers and Python tests have an empty diff cd3de10..ad6b653.
ad6b653 only adds existing compatible snapshot/return helpers to the package
and records documentation. The package contains no production DB/vault/profile,
TLS material or owner password. No private archive was added to Git.

## Evidence and limits

Full pinnedcd3de10: Go -count=1, both Caddy/Naive flags, both exact SFA checker
flags and DNS flag PASS; Python69/4skip PASS; go mod verify PASS; repository
go.sum SHA256 unchanged:
d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825.

Root7202 built oncd3de10: real CLI/API/worker create/replay/rename/CAS/protection,
three private0600 profiles/no-overwrite/version rejection/no output secrets,
fresh TCP/UoT PASS. Corrected af63ab0 frontend: vault/proc-root/admin denial,
private API connect, UID981/CapEff0/copy netns, trusted TLS/exact SNI,
login200/no-store/same-origin/unauthenticated401/admin404 PASS.

Browser7201: all3 files downloaded, default/warning/alpha13 option/1144 reset
and protected master_user verified. JSON variants and real API issuance
client/variant/hash matched; integrityok. Product diff8fc03c7..cd3de10 empty:
evidence reused with original revision/environment. HTTP bridge is not a
phone/production TLS proof. Synthetic Downloads files/helpers cleaned up.

Final package assemble/verify, hash/modes, tamper/symlink/unlisted-file rejection
and restored integrity PASS. Public template placeholders checked.
systemd-analyze verify/replay-only shell sh-n PASS; unrelated CPUAccounting
deprecation warnings emitted. Full Go not repeated for packaging-only changes:
the tested binaries were reused byte-for-byte with source equivalence above.

Both7201/7202 ended through their own hold marker; inactive/MainPID0 observed.
7202 Result=success. Do not assume a running copy.
Read-only production preflight: approved source matches, integrityok,
unfinished operations0, panel_generation2. No production mutation/restart/deploy.

## Approval boundary

Review [W7_UPGRADE_WINDOW.md](W7_UPGRADE_WINDOW.md).
Next scope: API/worker/private-frontend window; fresh encrypted/decrypt/hash
verified snapshots and current transient frontend capture before any stop.
Main transport Caddy/relay/WG/routes/firewall/SSH/reserve and existing profiles/
passwords remain outside changes. Start API read only before enabling owner-run;
this is not permission for agent production CRUD.

After user changes, default rollback freezes writes/returns readonly frontend
while preserving CURRENT registry/auth/users/credentials and new backend.
Full old-code rollback requires baseline equality; otherwise current-user
reverse export and existing journaled return. Never restore stale pre-auth.

The entire production switch/rollback has NOT been executed or claimed tested.
Before approved stop, capture/compare current transient unit/credential sources
with replay-only script and verify fresh snapshot receipts. Actual OnePlus12
import/routes/TLS/owner/nonadmin/external and Android RU/DM observations remain
mandatory. G6/G7/E1 are not accepted.

A full legacy writer/runtime return is outside this UI-only window and needs separate approval if transport configuration or a restart is required.
