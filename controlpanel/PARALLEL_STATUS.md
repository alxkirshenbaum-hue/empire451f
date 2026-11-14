# Parallel development journal

## 2026-11-14 — approved round 1, integrated portable checkpoint

Owner approved PARALLEL_PLAN_2026-11-14 and automatic ASTRA escalation.
Every progress/final report includes completed deliverable steps and agent status.
Steps are package deliverables, not tool calls or Wn gate completion.

Baseline84c5262; Lead contract/checkpoint4bdd985. Two independent branches:
SOL-A work/w8-restore-20261114, SOL-B work/w8-security-20261114, each in its
own worktree. Integrations were sequential, existing commits retained as Git
checkpoints. Tracked changes clean before integration; foreign BACKLOG untouched.

| Agent | Completed steps | Result / current status |
|---|---|---|
| SOL Lead | 4/4: isolation/checkpoint, portable runtime, integration contract, review/integration | Integrated 4d64384; 13 targeted tests PASS; local Linux chosen, admin enable/reboot pending |
| SOL-A | 3/3: reuse/interface, portable artifact checks, verification/report | Source6dde629 -> integrated7e0d761; 8 tests PASS, reviewed by B and Lead; package done, runtime proof pending |
| SOL-B | 3/3: SEC inventory, fixture checker, verification/report; next mapping2/2 | Source2ba7245 ->7ff71f5; report7fdb84e ->4d64384; 5 tests PASS, 22-ID mapping done; A final review PASS limited scope |

Lead contract was independently reviewed by BOTH A and B: no blocking findings.
A independently reviewed B fixture-only code: no blocking finding within scope.
B independently reviewed A and reran final8 tests; Lead reran integrated13.
Review findings corrected before integration: whole-archive buffering, leaf
FD/single-link/identity checks, inventory owner/mode/unlisted-member checks and
Windows binary read mode. Parent/concurrent hostile mutation protection and
GNUtar PAX/xattr producer compatibility remain explicitly unproven. Artifact
checks never set registry consistency, persisted verified status or restore PASS.

Targeted command: bundled Python unittest discovery tests/test_w8_*.py.
Result at4d64384: Ran13, OK, no skips (0.673s). A includes19 artifact-negative
cases + existing-envelope wrong-key/tamper; B covers fixture metadata only.
Windows runtime Python3.12.14 / SQLite3.53.1 / cryptography50.0.2, no installation.
Linux identities/namespaces/CGO/live restore/full suite/resource peaks: NOT_RUN.
Full release/gate suite not claimed or rerun for this limited helper checkpoint.

Existing audit gap map found SEC15/16/17/19/20/21 absent, plus missing actual
API/frontend/worker identity and current restrictive capability coverage. Human
collector labels are not stable SEC IDs. Never run collector blindly on live VDS.

## Local Linux decision

Owner has only production VDS and asked Lead to choose local or production.
Lead selected local WSL2 first. Verified Windows10 Pro19045, firmware virtualization
and SLAT true,32GiB RAM; WSL/VirtualMachinePlatform disabled. Windows admin token
required for enabling, then manual reboot; unsandboxed tool is not admin.
[Concrete next step and reversal](LOCAL_LINUX_RUNNER.md). No features installed,
UAC prompts launched, reboot or production fallback performed. This environment
step is not an ASTRA bug escalation and does not invalidate portable test results.

W6 3/4, W7 3/4 unchanged. Three phone profiles connect; alpha13 owner login on
Wi-Fi confirmed. Deferred ChatGPT/Download Manager issue remains deferred.
W8 preparation is not G8 acceptance and does not supersede missing G6/G7 evidence.
No production access, deploy, stop or CRUD in this round. E1 not released.

## Automatic ASTRA routing log

Cases routed:0. Failed corrective attempts on current cases:0.
A first local import error was fixed successfully on first correction; ordinary
review iterations are not failed fixes. Worktree sandbox-path denials resolved
with authorized local escalation are also not bug-fix attempts.

For each ASTRA case record ID/date, originating agent, affected task, reproducible
symptom,3 failed corrective attempts/SHAs, sanitized evidence, ASTRA agent/model,
analysis/result, Lead decision, final test and limitations. No secrets/raw owner
artifacts. Count across the team. After third failed SOL correction pause that
case and start ASTRA in a freed slot (max2 concurrent Subagents). Analysis does
not reset the count; after a fourth failed correction stop/report to owner.

Final environment-plan review: SOL-B1/1 independently approved LOCAL_LINUX_RUNNER.md, no blocking findings; commands not executed. Agent tasks idle after completed portable packages/reviews, awaiting actual local environment step; no background production work.

14.11.2026 — владелец явно согласовал локальное развёртывание WSL2. Lead выполнил проверенный SOL-B1/1 скрипт через Windows UAC: Microsoft-Windows-Subsystem-Linux и VirtualMachinePlatform Disabled→Enabled, оба RestartNeeded=true; отдельный CIM подтвердил InstallState1, helper завершён. -NoRestart соблюдён, автоматической перезагрузки нет. Receipt и SHA/порядок продолжения — [LOCAL_LINUX_RUNNER.md](LOCAL_LINUX_RUNNER.md), raw receipt вне Git в worktrees/wsl-setup-20261114/receipt.json. Lead local runner1/3 (компоненты), distro/systemd и runtime tests ещё не выполнены; SOL-A3/3 portable завершён/idle, SOL-B3/3+mapping2/2 завершён, дополнительное review установки1/1 PASS; ASTRA0/failedfix0. Production не затронут. Первое следующее действие — владельцу сохранить работу и вручную перезагрузить Windows, затем сообщить о возврате; Lead проверяет WSL engine/distro и продолжает стенд. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN, G8 не принят.

## 2026-11-14 — post-reboot local lab installed

Owner confirmed manual Windows reboot. Both optional features enabled and
HypervisorPresent=true. Old inbox WSL lacked --version; installed official stable
microsoft/WSL3.0.5 (not prerelease), MSI exit0, AuthenticodeValid Microsoft,
SHA2562313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa.
No automatic reboot. SOL-B independently reviewed install/config scope.

Created only NEW VPNControl-Lab, WSL2 Ubuntu24.04, under
C:\AllFiles\SoftWare\VPN\Amnezia\CodexVPN\worktrees\wsl-lab-20261114.
Official Canonical image356736729bytes, SHA256
2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934 verified
by SOL-A and Lead. Rootfs/installer/source manifests/receipts/logs are outside Git
in worktrees/wsl-setup-20261114. Existing distro inventory was empty.

Preserved original /etc/wsl.conf in new distro. Enabled systemd, disabled automatic
Windows drive mounts/interop/Windows PATH append; restarted ONLY VPNControl-Lab.
This reduces accidental hostfile exposure, not a hostile-root boundary against
Windows. No real owner materials copied. One trailing CR in a PowerShell-piped
script caused final cat to fail; config was then reread and validated directly,
no repeated feature/install changes. First correction successful, failedfix0.

Observed WSL3.0.5.0/kernel6.18.58.1, Ubuntu Python3.12.3/cryptography41.0.7,
SQLite3.45.1, GCC13.3.0; signed Ubuntu apt installed build-essential/pkg-config/
python3-cryptography/nftables/CA packages, exit0. Exact Go1.27.3 installed in
/opt/vpn-control/toolchain/go (CGO_ENABLED1/CCgcc observed, actual CGO build pending).
Official Go archive70588678bytes SHA256
65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 verified
by SOL-A and Lead before use. No Go network modules fetched.

Base runtime observations PASS: PID1systemd; no /mnt/c mount or Windows PATH;
unshare network/mount/PID available, nft list in private netns succeeds; real
systemd transient PrivateNetwork/UID65534/CapEff0/NoNewPrivs1 job succeeds.
Pinned tracked source e263338 transferred via binary stdin (no untracked BACKLOG,
secrets or Windows mount) to /opt/vpn-control/src-e263338. Linux targeted W8
suite Ran13 OK/no skips0.771s. This is NOT full Go/Python product gate evidence.

Lead local runner2/3 done: features + engine/distro/tooling; third product harness
qualification PARTIAL (base checks PASS). SOL-A Ubuntu artifact2/2 and Go artifact
2/2 done; SOL-B install review1/1 and distro config review1/1 done. Previous
portable A3/3/B3/3+mapping2/2 unchanged. ASTRA0, failed corrective attempts0.
No production access/downtime/CRUD/deploy and no Windows reboot by agent.

FIRST NEXT ACTION: qualify existing RootDirectory/LoadCredential/API Unix socket
harness on this lab, bring verified module proxy (repository go.sum+mod verify),
exact Caddy/Naive/SFA engines and run required pinned product tests. Actual restore,
security identity matrix and disk/RAM peak remain open. No new gate accepted:
W6 3/4/G6OPEN, W7 3/4/G7OPEN, G8OPEN, E1 unreleased. Local lab install succeeded;
no further Windows action required now. Start interactively: wsl -d VPNControl-Lab.
