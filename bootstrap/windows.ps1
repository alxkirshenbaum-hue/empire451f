# Native Windows launcher: no local Python, module bundle, or server templates.
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$Boot='python3 -c exec\(__import__\(\''base64\''\).b64decode\(\''aW1wb3J0IGhhc2hsaWIsaW8sanNvbixvcyxzeXMsdHlwZXMsdXJsbGliLnJlcXVlc3QsemlwZmlsZQp0cnk6CiAgICBpZiBvcy5nZXRldWlkKCkhPTA6IHJhaXNlIFJ1bnRpbWVFcnJvcigncm9vdCByZXF1aXJlZCcpCiAgICByZWxlYXNlPWRpY3QobGluZS5zcGxpdCgnPScsMSkgZm9yIGxpbmUgaW4gb3BlbignL2V0Yy9vcy1yZWxlYXNlJykgaWYgJz0nIGluIGxpbmUpCiAgICBpZiByZWxlYXNlLmdldCgnSUQnLCcnKS5zdHJpcCgpLnN0cmlwKCciJykhPSd1YnVudHUnIG9yIHJlbGVhc2UuZ2V0KCdWRVJTSU9OX0lEJywnJykuc3RyaXAoKS5zdHJpcCgnIicpIG5vdCBpbiAoJzI0LjA0JywnMjYuMDQnKSBvciBvcy51bmFtZSgpLm1hY2hpbmUhPSd4ODZfNjQnOiByYWlzZSBSdW50aW1lRXJyb3IoJ1VidW50dSAyNC4wNCBvciAyNi4wNCBhbWQ2NCByZXF1aXJlZCcpCiAgICBkYXRhPXVybGxpYi5yZXF1ZXN0LnVybG9wZW4oJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9hbHhraXJzaGVuYmF1bS1odWUvZW1waXJlNDUxZi92MC4yLjcvZGlzdC9pbnN0YWxsZXIuemlwJyx0aW1lb3V0PTYwKS5yZWFkKDIqMTAyNCoxMDI0KQogICAgaWYgaGFzaGxpYi5zaGEyNTYoZGF0YSkuaGV4ZGlnZXN0KCkhPSdlZWFhODZhN2ZmZjA2ZmM3NThkYzkxMzg0OGMxMjNmNmIzZjlkYzhhYjkzNzU5MDNjOTFmNzBhODMyNmZhYTk3JzogcmFpc2UgUnVudGltZUVycm9yKCdJbnN0YWxsZXIgU0hBMjU2IG1pc21hdGNoJykKICAgIGFyY2hpdmU9emlwZmlsZS5aaXBGaWxlKGlvLkJ5dGVzSU8oZGF0YSkpCiAgICBidW5kbGU9e25hbWU6YXJjaGl2ZS5yZWFkKG5hbWUpLmRlY29kZSgndXRmLTgnKSBmb3IgbmFtZSBpbiBhcmNoaXZlLm5hbWVsaXN0KCl9CiAgICBmb3IgbmFtZSBpbiAoJ3JlbmRlcicsJ3JlbW90ZScsJ2NsaWVudCcsJ2NvbnRyb2xsZXInKToKICAgICAgICBtb2R1bGU9dHlwZXMuTW9kdWxlVHlwZShuYW1lKTsgbW9kdWxlLl9fZmlsZV9fPScvcnVuL2VtcGlyZS1zb3VyY2UvJytuYW1lKycucHknCiAgICAgICAgc3lzLm1vZHVsZXNbbmFtZV09bW9kdWxlCiAgICAgICAgaWYgbmFtZT09J2NvbnRyb2xsZXInOiBtb2R1bGUuQlVORExFPWJ1bmRsZQogICAgICAgIGV4ZWMoY29tcGlsZShidW5kbGVbbmFtZSsnLnB5J10sbmFtZSsnLnB5JywnZXhlYycpLG1vZHVsZS5fX2RpY3RfXykKICAgIHN5cy5leGl0KHN5cy5tb2R1bGVzWydjb250cm9sbGVyJ10ubWFpbihzeXMuYXJndlsxOl0pKQpleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICBwcmludCgnSW5zdGFsbGVyIGJvb3RzdHJhcCBmYWlsZWQ6ICcrdHlwZShlKS5fX25hbWVfXyxmaWxlPXN5cy5zdGRlcnIpCiAgICBzeXMuZXhpdCgxKQo=\''\)\)'
function Ask([string]$Id,[string]$Text,[string]$Default=''){
 $answer=Read-Host ('['+$Id+'] '+$Text+$(if($Default){' ['+$Default+']'}else{''}))
 if(!$answer){return $Default};return $answer
}
function Resolve-Target([string]$Target){
 if($Target -notmatch '^[A-Za-z0-9_.@:-]+$' -or $Target.StartsWith('-')){throw 'Invalid SSH destination'}
 if($Target -match '^\d+\.\d+\.\d+\.\d+$'){$Target='root@'+$Target}
 $lines=& ssh -G $Target 2>$null
 if($LASTEXITCODE -ne 0){throw 'Cannot resolve SSH destination'}
 $result=@{}
 foreach($line in $lines){$parts=$line -split ' ',2;if($parts.Count -eq 2 -and !$result.ContainsKey($parts[0])){$result[$parts[0]]=$parts[1]}}
 if($result['hostname'] -notmatch '^[A-Za-z0-9_.:-]+$'){throw 'Invalid resolved hostname'}
 if($Target -notmatch '@|:' -and $Target -ne $result['hostname'] -and $result['identityfile']){
  $aliasKey=$result['identityfile']
  if($aliasKey.StartsWith('~/')){$aliasKey=Join-Path $HOME $aliasKey.Substring(2)}
  if(Test-Path -LiteralPath $aliasKey -PathType Leaf){$result['aliasKey']=(Resolve-Path -LiteralPath $aliasKey).ProviderPath}
 }
 return $result
}
function Write-Config{
 $lines=@('Host *',' StrictHostKeyChecking yes',' BatchMode yes',' ForwardAgent no',' ExitOnForwardFailure yes',' ConnectTimeout 12',' ServerAliveInterval 10',' ServerAliveCountMax 2',' IdentitiesOnly yes',' ControlMaster no',' ControlPath none')
 foreach($role in $Nodes.Keys){
  $node=$Nodes[$role];$key=$Identity
  if($node.ContainsKey('key')){$key=$node['key']}
  if($key.Contains('"') -or $key.Contains("`n")){throw 'Unsupported SSH key path'}
  $lines+=@("Host $role",(" HostName "+$node['hostname']),(" User "+$node['user']),(" Port "+$node['port']),(' IdentityFile "'+$key.Replace('\','/')+'"'))
  if($node['aliasKey'] -and $node['aliasKey'] -ne $key){
   $aliasKey=$node['aliasKey']
   if($aliasKey -match '["\r\n]'){throw 'Unsupported alias SSH key path'}
   $lines+=' IdentityFile "'+$aliasKey.Replace('\','/')+'"'
  }
  if($node['hostkeyalias'] -and $node['hostkeyalias'] -ne 'none'){$lines+=' HostKeyAlias '+$node['hostkeyalias']}
  if($Jumps.ContainsKey($role)){$lines+=' ProxyJump '+$Jumps[$role]}
 }
 [IO.File]::WriteAllText($Config,($lines -join "`n")+"`n",(New-Object Text.UTF8Encoding($false)))
}
function Invoke-SshCheck([string[]]$Arguments){
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=(Get-Command ssh.exe).Source
 $info.Arguments=(@('-n','-T','-F',$Config)+$Arguments | ForEach-Object {Quote-WindowsArg $_}) -join ' '
 $info.UseShellExecute=$false
 $info.CreateNoWindow=$true
 $info.RedirectStandardError=$true
 $info.RedirectStandardOutput=$true
 $process=[Diagnostics.Process]::Start($info)
 try{
  $stderr=$process.StandardError.ReadToEndAsync()
  $stdout=$process.StandardOutput.ReadToEndAsync()
  if(!$process.WaitForExit(25000)){
   $process.Kill()
   return @{Code=124;Output='';ErrorText=''}
  }
  if(!$stderr.Wait(1000) -or !$stdout.Wait(1000)){return @{Code=124;Output='';ErrorText=''}}
  return @{Code=$process.ExitCode;Output=$stdout.Result.Trim();ErrorText=$stderr.Result}
 }finally{$process.Dispose()}
}
function Probe([string]$Role){
 Write-Host ("Checking SSH: "+$Role+" (up to 25 seconds)...")
 $check=Invoke-SshCheck @($Role,'true')
 if($check.Code -eq 0){return 'ok'}
 if($check.Code -eq 124){Write-Host ("SSH "+$Role+" timed out.");return 'network'}
 $result=$check.ErrorText
 if($result -match 'REMOTE HOST IDENTIFICATION HAS CHANGED'){return 'changed-key'}
 if($result -match 'Host key verification failed|No .* host key is known'){return 'identity'}
 if($result -match 'Permission denied|authentication failed|sign_and_send_pubkey'){return 'authentication'}
 return 'network'
}
function Public-Key{
 $p=$Identity+'.pub'
 if(!(Test-Path -LiteralPath $p)){
  $value=& ssh-keygen -y -f $Identity
  if($LASTEXITCODE -ne 0){throw 'Cannot obtain public key'}
  return ($value -join '').Trim()
 }
 return [IO.File]::ReadAllText($p).Trim()
}
function Shell-Quote([string]$Value){return "'"+$Value.Replace("'","'\''")+"'"}
function Authenticate([string]$Role){
 $status=Probe $Role
 if($status -eq 'changed-key'){throw 'SSH host identity changed. Check provider console; no automatic replacement.'}
 if($status -eq 'identity'){
  Write-Host ('Verify '+$Role+' SSH fingerprint against the provider console.')
  & ssh -F $Config -o BatchMode=no -o StrictHostKeyChecking=ask $Role true
  $status=Probe $Role
 }
 if($status -eq 'authentication'){
  $choice=Ask Q17 ($Role+': password / console / retry') 'retry'
  if($choice -eq 'retry'){if($Nodes[$Role]['aliasKey']){& ssh-add $Nodes[$Role]['aliasKey']}else{& ssh-add $Identity}}
  elseif($choice -eq 'password' -or $choice -eq 'console'){
   $public=Public-Key
   if($public -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+'){throw 'Invalid public key'}
   $quoted=Shell-Quote $public
   $cmd='set -eu; . /etc/os-release; case $ID:$VERSION_ID:$(uname -m) in ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;; *) exit 41;; esac; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; grep -qxF '+$quoted+' ~/.ssh/authorized_keys || printf ''%s\n'' '+$quoted+' >> ~/.ssh/authorized_keys'
   if($choice -eq 'console'){Write-Host $cmd;[void](Read-Host 'Run this PUBLIC-key command in provider console, then Enter')}
   else{& ssh -F $Config -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive $Role $cmd}
  }else{throw 'Unknown initial-access choice'}
  $status=Probe $Role
 }
 return $status
}
function Quote-WindowsArg([string]$Value){
 if($Value -notmatch '[\s"]' -and $Value.Length){return $Value}
 $Value=[regex]::Replace($Value,'(\\*)"','$1$1\"')
 $Value=[regex]::Replace($Value,'(\\+)$','$1$1')
 return '"'+$Value+'"'
}
function New-Port{
 $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
 $listener.Start();$port=$listener.LocalEndpoint.Port;$listener.Stop();return $port
}
function Start-Rpc{
 $arguments=@('-F',$Config,'-n','-o','SendEnv=LC_EVPN_TOKEN','-L',('127.0.0.1:'+$LocalPort+':127.0.0.1:'+$RpcPort),'exit',($Boot+' rpc '+$RpcPort))
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=(Get-Command ssh.exe).Source
 $info.Arguments=($arguments | ForEach-Object {Quote-WindowsArg $_}) -join ' '
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 [void]$info.EnvironmentVariables.Remove('LC_EVPN_CLIENTS')
 $process=New-Object Diagnostics.Process;$process.StartInfo=$info
 [void]$process.Start()
 $line=$process.StandardOutput.ReadLineAsync()
 if(!$line.Wait(90000) -or $line.Result -ne 'EVPN_RPC_READY'){
  if(!$process.HasExited){$process.Kill()}
  throw 'Exit RPC bootstrap failed. Check Ubuntu 24.04/26.04, Git HTTPS access and SSH AcceptEnv LC_*.'
 }
 return $process
}
function Run-Wizard([string]$Operation){
 # Keep native console handles: capturing/piping stdout buffers prompts without LF.
 & ssh -F $Config -tt -o SendEnv=LC_EVPN_TOKEN -o SendEnv=LC_EVPN_SESSION -o SendEnv=LC_EVPN_CLIENTS -R ('127.0.0.1:'+$RelayPort+':127.0.0.1:'+$LocalPort) entry ($Boot+' wizard '+$RelayPort+' '+$Operation)
 $script:WizardExit=$LASTEXITCODE
}
function Fresh-Sessions{
 foreach($role in @('entry','exit')){if((Probe $role) -ne 'ok'){return $false}}
 Write-Host 'New key-authenticated SSH sessions to both nodes: PASS';return $true
}
function Wait-Reboot([string]$Role){
 Start-Sleep -Seconds 8
 for($attempt=0;$attempt -lt 48;$attempt++){if((Probe $Role) -eq 'ok'){return};Start-Sleep -Seconds 5}
 throw ($Role+': SSH did not recover after reboot; use provider console.')
}
foreach($tool in @('ssh.exe','ssh-keygen.exe')){
 if(!(Get-Command $tool -ErrorAction SilentlyContinue)){
  if((Ask B01 'Install native Windows OpenSSH Client (requires UAC)? yes/no' 'yes') -ne 'yes'){throw 'OpenSSH required'}
  $install=Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile -Command "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"'
  if($install.ExitCode -ne 0){throw 'OpenSSH installation failed'}
  $env:PATH+=';'+(Join-Path $env:WINDIR 'System32\OpenSSH')
  break
 }
}
$entry=Ask Q03 'Entry root@IP or existing SSH alias'
$exit=Ask Q05 'Exit root@IP or existing SSH alias'
if(!$entry -or !$exit){throw 'SSH destinations are required'}
while ($true) {
 $Identity=Ask Q09 'Private SSH key path (e.g. id_ed25519), or new' 'new'
 if ($Identity -eq 'new') {break}
 if ($Identity -like '*.pub') {
  Write-Host 'This is a public key. Enter the private key path, usually the same name without .pub.'
  continue
 }
 if ($Identity.StartsWith('~')) {$Identity=$HOME+$Identity.Substring(1)}
 if (Test-Path -LiteralPath $Identity -PathType Leaf) {break}
 Write-Host 'SSH key file not found. Enter an existing private key path.'
}
if($Identity -eq 'new'){
 $Identity=Join-Path $HOME '.ssh/empire-install'
 if(!(Test-Path -LiteralPath $Identity)){
  [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Identity))
  & ssh-keygen -t ed25519 -a 100 -f $Identity
  if($LASTEXITCODE -ne 0){throw 'SSH key creation failed'}
 }else{Write-Host 'Existing empire-install key will be reused.'}
}
if($Identity.StartsWith('~')){$Identity=$HOME+$Identity.Substring(1)}
$Identity=(Resolve-Path -LiteralPath $Identity).ProviderPath
$previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
& ssh-keygen -y -P '""' -f $Identity 2>$null | Out-Null
$encrypted=$LASTEXITCODE -ne 0
$ErrorActionPreference=$previous
if($encrypted){
 $previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
 & ssh-add -l 2>$null | Out-Null
 $agentMissing=$LASTEXITCODE -eq 2
 $ErrorActionPreference=$previous
 if($agentMissing){
  if((Ask Q21 'Start Windows ssh-agent service (requires UAC)? yes/no' 'yes') -ne 'yes'){throw 'ssh-agent required'}
  Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -Command "Set-Service ssh-agent -StartupType Manual; Start-Service ssh-agent"'
 }
 & ssh-add $Identity
 if($LASTEXITCODE -ne 0){throw 'SSH key could not be unlocked'}
}
$Nodes=@{entry=(Resolve-Target $entry);exit=(Resolve-Target $exit)}
if($Nodes.entry.user -ne 'root' -or $Nodes.exit.user -ne 'root'){throw 'Use root SSH access (or provider console to prepare it).'}
$Jumps=@{}
$Config=[IO.Path]::GetTempFileName()
$RpcProcess=$null
$SavedEnv=@{}
foreach($name in @('LC_EVPN_TOKEN','LC_EVPN_SESSION','LC_EVPN_CLIENTS','LC_EVPN_PROBE')){$SavedEnv[$name]=[Environment]::GetEnvironmentVariable($name)}
try{
 Write-Config
 $status=@{}
 foreach($role in @('entry','exit')){$status[$role]=Authenticate $role}
 foreach($role in @('entry','exit')){
  while($status[$role] -eq 'network'){
   $other=if($role -eq 'entry'){'exit'}else{'entry'}
   $jump=$Nodes[$role]['proxyjump']
   $choices=@('0')
   Write-Host ("Direct SSH to "+$role+" ("+$Nodes[$role]['hostname']+") failed. Choose how this computer should reach it.")
   if($jump -and $jump -ne 'none' -and !$jump.Contains(',')){
    $choices+='1'
    Write-Host ("  1  Connect via "+$jump+" (from your SSH settings)")
   }
   if($status[$other] -eq 'ok' -and !$Jumps.ContainsKey($other)){
    $choices+='2'
    Write-Host ("  2  Connect via the "+$other+" server ("+$Nodes[$other]['hostname']+")")
   }
   Write-Host '  0  Stop setup'
   $default=if($choices.Count -gt 1){$choices[1]}else{'0'}
   do {$choice=Ask Q18 ('Enter '+($choices -join '/')) $default} until ($choice -in $choices)
   if($choice -eq '0'){throw 'Setup stopped at SSH route selection.'}
   if($choice -eq '1'){
    if(!$jump -or $jump -eq 'none' -or $jump.Contains(',')){throw 'Configured single-hop ProxyJump unavailable'}
    $transit=Resolve-Target $jump
    if($transit['identityfile']){
     $candidate=$transit['identityfile'].Replace('~',$HOME)
     if(Test-Path -LiteralPath $candidate){$transit['key']=(Resolve-Path -LiteralPath $candidate).ProviderPath}
    }
    $Nodes['transit']=$transit;$Jumps[$role]='transit'
   }elseif($choice -eq '2'){$Jumps[$role]=$other}
   else{throw 'No reachable SSH route selected'}
   Write-Config;$status[$role]=Authenticate $role
   if($status[$role] -eq 'network'){
    Write-Host ("Route "+$choice+" did not reach "+$role+". Choose another route, retry, or enter 0 to stop.")
    $Jumps.Remove($role)
   }
  }
  if($status[$role] -ne 'ok'){throw ($role+': SSH '+$status[$role]+'; no deployment changes made')}
 }
 $env:LC_EVPN_PROBE='1'
 foreach($role in @('entry','exit')){
  Write-Host ("Checking Ubuntu, Python and SSH environment: "+$role+" (up to 25 seconds)...")
  $probe=Invoke-SshCheck @('-o','SendEnv=LC_EVPN_PROBE',$role,'set -eu; . /etc/os-release; case $ID:$VERSION_ID:$(uname -m):$(id -u) in ubuntu:24.04:x86_64:0|ubuntu:26.04:x86_64:0) ;; *) exit 41;; esac; test x${LC_EVPN_PROBE:-} = x1 || exit 43; if command -v python3 >/dev/null; then echo READY; else echo MISSING_PYTHON; fi')
  switch($probe.Code){
   124 {Write-Host ("Platform check timed out on "+$role+". Setup stopped before package installation."); return}
   41 {Write-Host ($role+': Ubuntu 24.04 or 26.04 amd64 and root access required.'); return}
   43 {Write-Host ($role+': SSH server did not accept LC_EVPN_PROBE. Check AcceptEnv LC_*.'); return}
   0 {}
   default {Write-Host ($role+': platform check failed (SSH exit '+$probe.Code+').'); return}
  }
  if($probe.Output -notin @('READY','MISSING_PYTHON')){throw ($role+': unexpected platform check response')}
  if($probe.Output -eq 'MISSING_PYTHON'){
   if((Ask Q22 ($role+': install python3 on VPS for inventory? Type INSTALL-PYTHON')) -ne 'INSTALL-PYTHON'){throw 'Python bootstrap declined'}
   & ssh -F $Config $role 'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; apt-get update && apt-get install -y --no-install-recommends python3'
   if($LASTEXITCODE -ne 0){throw 'VPS Python bootstrap failed'}
  }
 }
 $import=Ask Q13 'Optional LOCAL client export path (empty = existing/new credentials on entry)'
 $env:LC_EVPN_CLIENTS=''
 if($import){
  $bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $import).ProviderPath)
  if($bytes.Length -gt 64000){throw 'Client export too large'}
  $env:LC_EVPN_CLIENTS=[Convert]::ToBase64String($bytes)
 }
 $random=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rng.GetBytes($random);$rng.Dispose()
 $env:LC_EVPN_TOKEN=[BitConverter]::ToString($random).Replace('-','').ToLowerInvariant()
 $env:LC_EVPN_SESSION=[guid]::NewGuid().ToString('N')
 $LocalPort=New-Port;$RpcPort=Get-Random -Minimum 30000 -Maximum 59000;$RelayPort=Get-Random -Minimum 30000 -Maximum 59000
 $RpcProcess=Start-Rpc
 Run-Wizard start
 $code=$script:WizardExit
 if($code -eq 42){
  if(Fresh-Sessions){Run-Wizard finish;$code=$script:WizardExit}else{Run-Wizard abort;throw 'New SSH session failed; rollback requested'}
 }
 if($code -eq 44){
  Wait-Reboot exit
  if(!$RpcProcess.HasExited){$RpcProcess.Kill()};$RpcProcess.Dispose()
  $RpcProcess=Start-Rpc
  Run-Wizard after-exit-reboot
  $code=$script:WizardExit
 }
 if($code -eq 45){Wait-Reboot entry;if(!(Fresh-Sessions)){throw 'SSH did not recover'};Run-Wizard after-entry-reboot;$code=$script:WizardExit}
 if($code -ne 0){throw ('Installer ended with code '+$code+'. If apply started, server rollback timers remain the safety net.')}
 if(!(Fresh-Sessions)){throw 'Final SSH check failed'}
}finally{
 if($RpcProcess){
  try{
   $request=[Net.WebRequest]::Create('http://127.0.0.1:'+$LocalPort+'/');$request.Method='POST';$request.Timeout=2000;$request.Proxy=$null
   $request.Headers.Add('Authorization','Bearer '+$env:LC_EVPN_TOKEN)
   $body=[Text.Encoding]::UTF8.GetBytes('{"action":"shutdown"}');$request.ContentLength=$body.Length
   $stream=$request.GetRequestStream();$stream.Write($body,0,$body.Length);$stream.Dispose();$request.GetResponse().Dispose()
  }catch{}
  if(!$RpcProcess.HasExited){$RpcProcess.Kill()};$RpcProcess.Dispose()
 }
 foreach($name in $SavedEnv.Keys){[Environment]::SetEnvironmentVariable($name,$SavedEnv[$name])}
 if($Config){[IO.File]::Delete($Config)}
}
