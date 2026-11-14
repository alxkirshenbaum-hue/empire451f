# W8 local harness portability review

Baseline: original installer PLAN 0e98e9b context read. Qualification package
3/3 complete (inventory, adaptation proposal, independent Lead patch review). No heavy lab tests, SSH or production actions. Failed fixes0.

## Blocking assumptions / minimal adaptations

- pilot/run_full_worker_rehearsal.sh:30 and
  pilot/panel_frontend_rehearsal.py:96 hardcode /usr/bin/python3.14 while the
  Ubuntu24.04 lab has Python3.12. Use /usr/bin/python3 consistently (already
  covered by read-only /usr bind), or one explicitly validated interpreter
  selection. Never remove denial checks or change UID to obtain execution.
- run_full_worker_rehearsal.sh:27–29 requires prepared rehearsal-source/local,
  /opt/empire-vpn/bin and /etc/ssl. prepare_rehearsal_root.py:10–11 requires new
  root parent exactly equal to the script project. Keep project/source placement
  consistent; arbitrary VPN_REHEARSAL_PROJECT does not relocate that invariant.
- prepare_rehearsal_root.py:29–34 requires rehearsal-bin/vpnctl and template
  subtree. full_worker_rehearsal.py:95 also requires rehearsal-bin/vpn-control;
  :57 requires real pinned sing-box. Stage pinned binaries and compiler/module
  inputs explicitly; missing inputs are setup failures, never reasons to skip.
- prepare_rehearsal_root.py:21–22 defines synthetic passwd/group identities
  981/982/999:986 inside the copy. Preserve them and root755/secret0700 layout;
  do not create production users or rely on Ubuntu host account name matches.
- panel_frontend_rehearsal.py:35 root-relative + masks and :37 narrow /api bind
  are essential with LoadCredential's private /run. Keep masks, empty caps,
  NoNewPrivileges, syscall denial and exact UID assertions at :29–35,:58,:81–90.
- controlpanel/systemd/vpn-control-panel.service has installation-specific
  evpn-nh1 names and host namespace/API paths; do not install it verbatim as a
  lab unit. Existing transient harness intentionally targets copy paths and
  namespace. Product unit fidelity and transient-copy proof remain distinct.
- controlpanel/systemd/vpn-control-worker@.service intentionally retains systemd
  default root identity to preserve setuid capability; do not add User=root as
  a portability guess. Validators still drop identity/capabilities.

## Runtime qualification checklist (not executed here)

1. Record pinned source, Go/module verification, binary hashes and Python3.12
   import compatibility; source/state on Linux filesystem and synthetic only.
2. Prepare unique root; inspect required executable/loader/CA/helper paths in
   that root, no bind of an ancestor containing the root; no Windows mounts.
3. Run ordinary copy worker first; confirm private netns loopback only, working
   API Unix socket, expected identities and zero API/frontend capabilities.
4. Qualify LoadCredential/private-run plus narrow /api bind: frontend real HTTPS
   with trusted synthetic CA and exact SNI; login page200/no-store/same-origin,
   unauthenticated users401, admin route404.
5. Assert actual denied listdir for vault/config trees and proc-root access;
   only hidden admin socket may yield ENOENT. API socket connect must succeed.
   Missing secret directories must fail, not masquerade as access denial.
6. Preserve same netns assertion, service cleanup limited to named test units,
   no public listeners/host routes/prod files. Capture systemd journal and exact
   failed boundary on failure, count failed corrections centrally.
7. Then pinned full suites and bounded heavy restore/resource scenarios under
   Lead sequencing. This checklist is not G6/G7/G8 or production-fidelity PASS.

Lead common patch review remains pending; no shared harness edits by SOL-B.
## Independent Lead patch review — completed

Reviewed original installer working diff against 0e98e9b. Exactly two command
paths changed: run_full_worker_rehearsal.sh:30 and panel_frontend_rehearsal.py:96,
/usr/bin/python3.14 -> /usr/bin/python3. Both commands execute with read-only
/usr bind, hence the lab's system Python and its corresponding /usr libraries.
The /usr/local overlay does not replace /usr/bin/python3. No identity, mask,
capability, syscall policy, socket bind or denial assertion changed. APPROVE
limited portability patch; runtime qualification and pinned full suites remain
Lead work, not implied PASS from this review.

Windows bundled Python AST parse of the changed frontend module PASS. Shell
change inspected as single executable path substitution; no shell execution or
heavy WSL tests by SOL-B. Failed corrective attempts0. Package progress3/3.
## Pinned full-suite environment and safety inventory — 2/2

Read-only source inventory, no new execution or PASS. Lead staging target
03f627a; baseline e263338 Go ./... -count=1 PASS does not cover opt-ins below.

Exact flags:
- VPN_TEST_CADDY_ADAPTER=1, internal/caddy/live_linux_test.go:22; requires
  loopback-only sysfs interfaces and /opt/empire-vpn/bin/caddy (:65) with the
  forward_proxy plugin. Missing flag explicitly skips installed adapter test.
- VPN_TEST_NAIVE_PROBE=1, cmd/vpnctl/migration_test.go:281 invokes
  ../../../pilot/reverse_probe.py and cmd/vpn-control/download_test.go:115
  invokes ../../../pilot/issue_probe.py. Otherwise probe branches omitted.
- VPN_TEST_SFA_CHECK_1144 and VPN_TEST_SFA_CHECK_ALPHA13 are executable paths,
  not booleans. internal/storage/routing_test.go:105–129 requires first version
  line exactly sing-box version 1.14.4 / 1.15.0-alpha.13, invokes check on stdin.
  Three cases (base1144/baseAlpha13/optionalAlpha13) skip without checker paths.
- VPN_TEST_SFA_DNS=1 invokes python3 ../../../pilot/profile_dns_check.py with
  each exact checker; script:37 requires only lo. Without flag branch omitted.
- VPN_TEST_SFA_CHECK path additionally activates internal/storage/profile_test.go:74;
  absence silently omits that extra validation, not an explicit skipped test.

Concrete command template (Lead substitutes verified artifact absolute paths;
these selected checker paths are staging destinations, not claims they exist):

```sh
systemd-run --quiet --wait --pipe --unit=vpn-lab-go-03f627a \
 -p PrivateNetwork=yes -p WorkingDirectory=/opt/vpn-control/src-03f627a/controlpanel \
 --setenv=GOTOOLCHAIN=local --setenv=GOSUMDB=off \
 --setenv=GOPROXY=file:///opt/vpn-control/module-proxy \
 --setenv=VPN_TEST_CADDY_ADAPTER=1 --setenv=VPN_TEST_NAIVE_PROBE=1 \
 --setenv=VPN_TEST_SFA_CHECK=/opt/vpn-control/checkers/1.14.4/sing-box \
 --setenv=VPN_TEST_SFA_CHECK_1144=/opt/vpn-control/checkers/1.14.4/sing-box \
 --setenv=VPN_TEST_SFA_CHECK_ALPHA13=/opt/vpn-control/checkers/1.15.0-alpha.13/sing-box \
 --setenv=VPN_TEST_SFA_DNS=1 \
 /opt/vpn-control/go/bin/go test -count=1 ./...
```

Root manager default identity required by cmd/vpnctl/worker_linux_test.go:17–18;
nonroot skips root policy proof. Verify actual Go executable/proxy/checker paths,
run offline go mod verify against repository go.sum first, preserve original
module sums, pin SHA/version receipts for Caddy, Naive server/client, both SFA
engines and Go. Network namespace disconnect means all dependencies must already
be staged. Do not use fake checkers or disable DNS when dependencies are missing.
Remaining Go skips are subprocess-entry guard tests, not missing acceptance:
cmd/vpnctl/caddy_create_linux_test.go:49, g5_linux_test.go:128 and
internal/storage/registry_test.go:140. Their parent tests must execute children.

Python Linux command, within separate sequential PrivateNetwork unit rooted in
pinned installer source: /usr/bin/python3 -B -m unittest discover -s tests -p
 'test_*.py' -v. Read-only inventory found no test suite opt-in to live SSH,
production units, WG outages or controlled_audit. SSH operations in installer
unit tests are mocks; Windows native-flow test uses process-level SSH stubs.
Linux owned-auth tests and migration SIGKILL/crash tests mutate temporary synthetic
fixtures and subprocesses, not production; run solely in lab. Non-discovered
helper files (site_http_fixture, handoff_crash_check, return_crash_check) are
invoked by callers, not general live audit authorization.

Python expected platform skips: Windows-only NativeWindowsProcessTests class at
 tests/test_launchers.py:171 (three methods), macOS real shell syntax :332.
Linux owned_auth class :17 and POSIX migration class :98 should run. Conditional
xattr skips owned_auth:122–124 and hardlink skip w8_backup_artifacts:94 require
actual reported accounting; missing filesystem capability is not a PASS. The
Windows syntax methods can silently loop over unavailable shells (:303–315),
so Linux suite cannot prove Windows PowerShell behavior. No additional live
runner or no-skip acceptance claim is made from this source mapping.