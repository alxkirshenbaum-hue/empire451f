# Local Linux runner — Lead decision, 2026-11-14

Status: local WSL2 selected; not installed/enabled; Linux acceptance NOT_RUN.
No production access, downtime, transport or network changes performed.

## Verified Windows facts

Windows10 Pro build19045; Intel i5-8250U, firmware virtualization and SLAT true;
32GiB installed RAM. HypervisorPresent=false. Win32_OptionalFeature InstallState2
(disabled): Microsoft-Windows-Subsystem-Linux, VirtualMachinePlatform and
Microsoft-Hyper-V-All. CIM read succeeded. DISM feature inspection reported
administrator elevation required, even from the tool's unsandboxed process.
This is Windows UAC privilege, not a Git/sandbox permission issue.

WSL2 is feasible hardware-wise; enabling/installing it requires an administrator
session and a Windows reboot. Do not declare it impossible and jump to production
because elevation/reboot is pending. A Git branch on a production VDS is not OS,
filesystem, privilege, memory or network isolation. W8 restore/failure/resource
checks belong on a separate local Linux instance first.

Microsoft references, checked14November2026:
- https://learn.microsoft.com/en-us/windows/wsl/install-manual
- https://learn.microsoft.com/en-us/windows/wsl/install
- https://learn.microsoft.com/en-us/windows/wsl/systemd/

Windows build19045 meets documented WSL2 platform requirements. Systemd requires
modern WSL >=0.67.6, not merely the old inbox wsl.exe stub. Availability of
package downloads/proxy is NOT assumed and must be checked before installation.

## Concrete administrator step

Save work first. Run the following in an administrator PowerShell; commands do
not restart Windows automatically. These two features were observed disabled.
Do not enable the full Hyper-V role unnecessarily.

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
```

After both succeed, reboot Windows manually at a convenient time. Lead must not
restart Windows automatically or silently launch an elevation prompt. Keep the
returned RestartNeeded/feature states as the local checkpoint. No VDS downtime
is involved. Current chat/source commits persist across the reboot.

After reboot Lead checks features, WSL engine version and existing distributions;
installs/updates official WSL and imports/creates a uniquely named VPNControl-Lab
Linux instance without overwriting another distro. Exact image version/hash and
installed packages are recorded before use. Do not run an old unsupported flag
blindly; check actual engine help. No owner keys/profiles/archives copied in.

## Runner acceptance before product tests

Linux filesystem (not /mnt/c) for copy state and executable scripts; source and
module cache pinned by commit/hash. Confirm systemd PID1, user/capabilities,
network namespace, private mounts, Unix sockets, CGO/compiler/SQLite and Python
cryptography. Use synthetic CA/users only. Caddy/Naive and both exact SFA engines
come from pinned verified inputs; go.sum checked, offline GOPROXY and mod verify.
Start no public listeners, no production routes/SSH-key copy. Actual systemd
RootDirectory/LoadCredential protections and nft namespace support must pass;
WSL convenience alone is not evidence. If a kernel feature is missing, report
that gate unknown and choose a full VM rather than weakening isolation.

Constrain lab VM resources separately from panel500MB RAM and disk gates. Collect
panel aggregate cgroup/RSS/PSS and allocated disk peaks; WSL host memory/vhd sizes
are additional lab overhead, not panel measurements. Heavy scenarios sequential.

## Reversal / checkpoints

Before any distro import record existing feature states/distro names and use a
new directory/name. No unregister/delete of pre-existing distributions. On
failure preserve source, receipts and synthetic evidence. Stop only the new lab
instance, never all WSL instances without assessing other users of WSL.

If enabling features must be reversed before a lab is in use, disable ONLY the
two features this run changed, with -NoRestart, in administrator PowerShell;
manual reboot may be needed. Disabling features does not authorize deleting VHDs
or other distributions. Do not execute feature reversal while other work depends
on WSL; Lead reviews actual current state first. No rollback action executed.

## Production fallback boundary

Owner stated production can be considered if local solutions do not work, with
advance downtime notice and good recovery checkpoints. This is not a reason to
skip the feasible local setup or grant agents unrestricted SSH. Lead prepares a
specific isolated test window, fresh current-user-preserving encrypted verified
snapshot and reviewed rollback before requesting any production stop/change.
Subagents still never deploy or modify production. No production fallback used.

## 2026-11-14 — owner approved local setup; features enabled

Owner said to deploy locally on Windows. Lead executed only the reviewed local
feature-enable script through Windows UAC (no silent elevation). Independent
SOL-B final review1/1 approved SHA256
93c3f21477e85158e0053777420b9fc2ddd47b8edab4f8951f5c7f87f9b8e1a7.

Result2026-11-14 13:22MSK: WSL and VirtualMachinePlatform both BeforeDisabled,
AfterEnabled, ChangedByRun=true, RestartNeeded=true. Separate CIM check confirmed
InstallState1 for both. Full Hyper-V role not enabled. Elevated helper exited;
AutomaticRestart=false. No distro/WSL engine downloaded, no Linux tests run,
no production access or changes. This is feature setup only, not a ready runner.

Local evidence outside Git:
C:\AllFiles\SoftWare\VPN\Amnezia\CodexVPN\worktrees\wsl-setup-20261114\receipt.json
and reviewed enable-features.ps1 in the same directory. No secrets in receipt.
Before any reversal reread actual feature states; only these two were changed.
Earlier partial-failure receipt issue was fixed before execution and reviewed.

NEXT REQUIRED USER ACTION: save work and manually reboot Windows. Do not have
Lead auto-restart it. After user confirms reboot, Lead reads latest PLAN/this
section, verifies feature state and WSL version/distributions, prepares modern
WSL2 + separate lab distro without overwriting existing instances, then proves
systemd/private namespace/socket/RootDirectory/CGO before product tests. No
repeated feature enabling, old deployment scripts, production fallback or G6/G7
acceptance implied by the reboot. Portable checkpoint9621e88 remains applicable.

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
