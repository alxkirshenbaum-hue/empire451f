# W8 local harness portability review

Baseline: original installer PLAN 0e98e9b context read. Qualification package
2/3 complete (inventory and adaptation proposal); step3 independent Lead patch
review PENDING. No heavy lab tests, SSH or production actions. Failed fixes0.

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