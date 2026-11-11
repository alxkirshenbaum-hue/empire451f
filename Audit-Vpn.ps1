param([string]$Entry, [string]$ExitNode, [string]$Id)
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
foreach ($role in 'entry','exit') {
    $node=if ($role -eq 'entry') { $Entry } else { $ExitNode }
    $source | ssh -T -o ControlPath=none -o BatchMode=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes -o ConnectTimeout=10 $node python3 - $role $Id
    if ($LASTEXITCODE -ne 0) { $failed=$true }
}
Write-Host 'Not exercised: WireGuard outage, service crashes, namespace recreation, reboot or packet capture.'
if ($failed) { throw 'Audit incomplete or failed. See the role and check above.' }
