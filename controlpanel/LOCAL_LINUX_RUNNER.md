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
