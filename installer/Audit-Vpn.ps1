param([string]$Entry, [string]$ExitNode, [string]$Id,[switch]$Disruptive)
function Invoke-ControlledAudit {
    param($Entry,$ExitNode,$Id,$Source,[switch]$BootOnly)
    $options=@('-T','-o','ControlPath=none','-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2')
    foreach ($peer in @($Entry,$ExitNode)) {
        ssh @options $peer true
        if ($LASTEXITCODE -ne 0) { throw "Cannot start outage tests without fresh SSH to $peer" }
    }
    $pair=$Source | ssh @options $Entry python3 - pair $Id
    if ($LASTEXITCODE -ne 0 -or $pair -notmatch '^entry ([0-9.]+ [0-9.]+)$') { throw 'Entry role or deployment mismatch' }
    $expectedExit='exit '+$Matches[1]
    $pair=$Source | ssh @options $ExitNode python3 - pair $Id
    if ($LASTEXITCODE -ne 0 -or $pair -ne $expectedExit) { throw 'Exit role or deployment mismatch' }
    if (!$BootOnly) {
        $Source | ssh @options $Entry python3 - exercise $Id
        if ($LASTEXITCODE -ne 0) { throw 'Outage test failed. Check recovery on entry before rebooting.' }
    }
    foreach ($node in @($ExitNode,$Entry)) {
        $old=ssh @options $node cat /proc/sys/kernel/random/boot_id
        if ($LASTEXITCODE -ne 0 -or $old -notmatch '^[0-9a-f-]{36}$') { throw 'Cannot read boot ID' }
        Write-Host "Rebooting $node. Waiting up to 4 minutes for a new boot ID and key login."
        $Source | ssh @options $node python3 - reboot $Id
        if ($LASTEXITCODE -ne 0) { throw 'Reboot scheduling failed' }
        $deadline=(Get-Date).AddMinutes(4)
        do {
            Start-Sleep -Seconds 5
            $next=ssh @options $node cat /proc/sys/kernel/random/boot_id
            $ready=($LASTEXITCODE -eq 0 -and $next -match '^[0-9a-f-]{36}$' -and $next -ne $old)
        } until ($ready -or (Get-Date) -gt $deadline)
        if (!$ready) { throw "SSH after reboot failed on $node. Check provider console." }
        foreach ($peer in @($Entry,$ExitNode)) {
            ssh @options $peer true
            if ($LASTEXITCODE -ne 0) { throw "Fresh SSH failed: $peer" }
        }
        $Source | ssh @options $node python3 - boot-check $Id
        if ($LASTEXITCODE -ne 0) { throw 'Post-reboot journal check failed' }
        $Source | ssh @options $Entry python3 - health $Id
        if ($LASTEXITCODE -ne 0) { throw "VPN verification failed after rebooting $node" }
        Write-Host "PASS  changed boot ID, new SSH and VPN after reboot of $node"
    }
}

$ErrorActionPreference='Stop'
if (!$Entry) { $Entry=Read-Host 'Entry SSH alias or root@IP' }
if (!$ExitNode) { $ExitNode=Read-Host 'Exit SSH alias or root@IP (ProxyJump from SSH config is supported)' }
if (!$Id) { $Id=Read-Host 'Existing deployment ID' }
if ($Id -cnotmatch '^[a-z][a-z0-9]{2,9}$') { throw 'Invalid deployment ID' }
$failed=$false
foreach ($node in @($Entry,$ExitNode)) {
    if ($node -notmatch '^(root@)?[a-z0-9][a-z0-9._-]*$') { throw 'Invalid SSH destination' }
}
$source=(Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/audit-v1/security_audit.py' -TimeoutSec 30).Content
$verify=(Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.3/verify.py' -TimeoutSec 30).Content
if ($verify -is [byte[]]) { $verify=[Text.Encoding]::UTF8.GetString($verify) }
if ($source -is [byte[]]) { $source=[Text.Encoding]::UTF8.GetString($source) }
$source=$verify + [char]10 + $source
foreach ($role in 'entry','exit') {
    $node=if ($role -eq 'entry') { $Entry } else { $ExitNode }
    $source | ssh -T -o ControlPath=none -o BatchMode=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes -o ConnectTimeout=10 $node python3 - $role $Id
    if ($LASTEXITCODE -ne 0) { $failed=$true }
}
if ($Disruptive) {
    Write-Host 'VPN sessions will disconnect. This test interrupts WireGuard, kills proxy processes, recreates the namespace and reboots BOTH servers.'
    if ((Read-Host 'Open both provider recovery consoles. Type OUTAGE-AND-REBOOT to continue') -ceq 'OUTAGE-AND-REBOOT') {
        $exercise=(Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.4/controlled_audit.py' -TimeoutSec 30).Content
        if ($exercise -is [byte[]]) { $exercise=[Text.Encoding]::UTF8.GetString($exercise) }
        Invoke-ControlledAudit $Entry $ExitNode $Id ($verify + [char]10 + $exercise)
    } else { Write-Host 'Disruptive tests skipped.' }
} else { Write-Host 'Disruptive tests skipped. Use -Disruptive for outage and reboot tests.' }

if ($failed) { throw 'Audit incomplete or failed. See the role and check above.' }
