# Native Windows launcher: no local Python, module bundle, or server templates.
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$Boot='python3 -c exec\(__import__\(\''base64\''\).b64decode\(\''aW1wb3J0IHNpZ25hbCxoYXNobGliLGlvLGpzb24sb3Msc3lzLHR5cGVzLHVybGxpYi5yZXF1ZXN0LHppcGZpbGUKdHJ5OgogICAgaWYgb3MuZ2V0ZXVpZCgpIT0wOiByYWlzZSBSdW50aW1lRXJyb3IoJ3Jvb3QgcmVxdWlyZWQnKQogICAgcmVsZWFzZT1kaWN0KGxpbmUuc3BsaXQoJz0nLDEpIGZvciBsaW5lIGluIG9wZW4oJy9ldGMvb3MtcmVsZWFzZScpIGlmICc9JyBpbiBsaW5lKQogICAgaWYgcmVsZWFzZS5nZXQoJ0lEJywnJykuc3RyaXAoKS5zdHJpcCgnIicpIT0ndWJ1bnR1JyBvciByZWxlYXNlLmdldCgnVkVSU0lPTl9JRCcsJycpLnN0cmlwKCkuc3RyaXAoJyInKSBub3QgaW4gKCcyNC4wNCcsJzI2LjA0Jykgb3Igb3MudW5hbWUoKS5tYWNoaW5lIT0neDg2XzY0JzogcmFpc2UgUnVudGltZUVycm9yKCdVYnVudHUgMjQuMDQgb3IgMjYuMDQgYW1kNjQgcmVxdWlyZWQnKQogICAgZGVmIGV4cGlyZWQoKmFyZ3MpOiByYWlzZSBUaW1lb3V0RXJyb3IoIkJ1bmRsZSBkb3dubG9hZCB0aW1lZCBvdXQiKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQUxSTSxleHBpcmVkKQogICAgc2lnbmFsLmFsYXJtKDY1KQogICAgZGF0YT11cmxsaWIucmVxdWVzdC51cmxvcGVuKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vYWx4a2lyc2hlbmJhdW0taHVlL2VtcGlyZTQ1MWYvdjAuMy4yL2Rpc3QvaW5zdGFsbGVyLnppcCcsdGltZW91dD02MCkucmVhZCgyKjEwMjQqMTAyNCkKICAgIHNpZ25hbC5hbGFybSgwKQogICAgaWYgaGFzaGxpYi5zaGEyNTYoZGF0YSkuaGV4ZGlnZXN0KCkhPSdlNjA2YzQ4MTUwNmQ0M2RkMzdhMzQ5M2RhMjUwYTQ2MzdjZmZiODZjYTkzODI1MTgxNzliZjIyNzg0ODAwNWY3JzogcmFpc2UgUnVudGltZUVycm9yKCdJbnN0YWxsZXIgU0hBMjU2IG1pc21hdGNoJykKICAgIGFyY2hpdmU9emlwZmlsZS5aaXBGaWxlKGlvLkJ5dGVzSU8oZGF0YSkpCiAgICBidW5kbGU9e25hbWU6YXJjaGl2ZS5yZWFkKG5hbWUpLmRlY29kZSgndXRmLTgnKSBmb3IgbmFtZSBpbiBhcmNoaXZlLm5hbWVsaXN0KCl9CiAgICBmb3IgbmFtZSBpbiAoJ3JlbmRlcicsJ3JlbW90ZScsJ2NsaWVudCcsJ2RlbGl2ZXJ5JywnY29udHJvbGxlcicpOgogICAgICAgIG1vZHVsZT10eXBlcy5Nb2R1bGVUeXBlKG5hbWUpOyBtb2R1bGUuX19maWxlX189Jy9ydW4vZW1waXJlLXNvdXJjZS8nK25hbWUrJy5weScKICAgICAgICBzeXMubW9kdWxlc1tuYW1lXT1tb2R1bGUKICAgICAgICBpZiBuYW1lPT0nY29udHJvbGxlcic6IG1vZHVsZS5CVU5ETEU9YnVuZGxlCiAgICAgICAgZXhlYyhjb21waWxlKGJ1bmRsZVtuYW1lKycucHknXSxuYW1lKycucHknLCdleGVjJyksbW9kdWxlLl9fZGljdF9fKQogICAgc3lzLmV4aXQoc3lzLm1vZHVsZXNbJ2NvbnRyb2xsZXInXS5tYWluKHN5cy5hcmd2WzE6XSkpCmV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgIHByaW50KCdJbnN0YWxsZXIgYm9vdHN0cmFwIGZhaWxlZDogJyt0eXBlKGUpLl9fbmFtZV9fLGZpbGU9c3lzLnN0ZGVycikKICAgIHN5cy5leGl0KDEpCg==\''\)\)'
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
function Offer-Alias($role,$dir=(Join-Path $HOME '.ssh')){
 if(!$Nodes[$role]['enteredIPv4']){return}
 $node=$Nodes[$role]
 $aliasName=Ask Q23 ("Save an SSH shortcut for "+$role+" ("+$node.hostname+")? Enter a new name, or press Enter to skip")
 if(!$aliasName){return}
 if($aliasName -notmatch '^[a-zA-Z][a-zA-Z0-9_-]{0,39}$'){Write-Host 'Alias skipped: use a letter followed by letters, digits, dashes or underscores.';return}
 $path=Join-Path $dir 'config'
 try{
  $raw=[IO.File]::ReadAllText($Config)
  $roles=@($role);$names=@{};$names[$role]=$aliasName
  if($Jumps.ContainsKey($role)){
   $hop=$Jumps[$role];$roles+=$hop;$names[$hop]=$aliasName+'-hop'
  }
  $append=""
  foreach($r in $roles){
   $name=$names[$r]
   # Refuse a name matched by any specific existing Host stanza, including Include files.
   $previous=$ErrorActionPreference
   try{$ErrorActionPreference='Continue';$effective=& ssh -v -G $name 2>&1 | Out-String}finally{$ErrorActionPreference=$previous}
   if($LASTEXITCODE -ne 0 -or ($effective -split "`n" | Where-Object {$_ -match 'Applying options for (.+)' -and $Matches[1].Trim() -ne '*'})){
    Write-Host ("Alias skipped: existing SSH settings match "+$name);return
   }
   $section=[regex]::Match($raw,('(?m)^Host '+$r+'\n(?: [^\n]*\n)+')).Value
   if(!$section){throw 'Missing SSH route'}
   $section=$section.Replace(('Host '+$r+"`n"),('Host '+$name+"`n"))
   if($Jumps.ContainsKey($r)){$section=$section.Replace((' ProxyJump '+$Jumps[$r]+"`n"),(' ProxyJump '+$names[$Jumps[$r]]+"`n"))}
   $append+="`n"+$section+" IdentitiesOnly yes`n ForwardAgent no`n StrictHostKeyChecking yes`n"
  }
  [void][IO.Directory]::CreateDirectory($dir)
  $bytes=[Text.Encoding]::UTF8.GetBytes($append)
  if([IO.File]::Exists($path)){
   $old=[IO.File]::ReadAllText($path)
   foreach($name in $names.Values){
    if($old -match ('(?im)^\s*Host\s+[^#\r\n]*\b'+[regex]::Escape($name)+'(?=\s|$)')){Write-Host 'Alias already present; skipped.';return}
   }
  }
  $stream=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  Write-Host ("Saved to "+$path+". Connect with: ssh "+$aliasName)
 }catch{Write-Host 'Could not save SSH shortcut. Continuing with the verified session settings.'}
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
 while($status -eq 'authentication'){
  Write-Host ("SSH login to "+$Role+" failed. How would you like to get access?")
  Write-Host '  1  Unlock the existing key and retry SSH login'
  Write-Host '  2  Use the server password to add your public key'
  Write-Host '  3  Show a public-key command for the provider console'
  Write-Host '  0  Stop setup'
  $choice=Ask Q17 'Enter 1/2/3/0' '1'
  $actions=@{'1'='retry';'2'='password';'3'='console';'0'='stop'}
  if($actions.ContainsKey($choice)){$choice=$actions[$choice]}
  if($choice -eq 'stop'){throw 'Stopped at SSH authorization.'}
  if($choice -eq 'retry'){if($Nodes[$Role]['aliasKey']){& ssh-add $Nodes[$Role]['aliasKey']}else{& ssh-add $Identity}}
  elseif($choice -eq 'password' -or $choice -eq 'console'){
   $public=Public-Key
   if($public -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+'){throw 'Invalid public key'}
   $quoted=Shell-Quote $public
   $cmd='set -eu; . /etc/os-release; case $ID:$VERSION_ID:$(uname -m) in ubuntu:24.04:x86_64|ubuntu:26.04:x86_64) ;; *) exit 41;; esac; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; grep -qxF '+$quoted+' ~/.ssh/authorized_keys || printf ''%s\n'' '+$quoted+' >> ~/.ssh/authorized_keys'
   if($choice -eq 'console'){Write-Host $cmd;[void](Read-Host 'Run this PUBLIC-key command in provider console, then Enter')}
   else{& ssh -F $Config -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive $Role $cmd}
  }else{Write-Host 'Choose password, console, retry or stop.';continue}
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
 Write-Host 'Opening exit SSH tunnel and loading installer on exit (up to 90 seconds)...'
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
 Write-Host ("Opening interactive wizard on entry: "+$Operation+" ...")
 # Keep native console handles: capturing/piping stdout buffers prompts without LF.
 & ssh -F $Config -tt -o SendEnv=LC_EVPN_TOKEN -o SendEnv=LC_EVPN_SESSION -o SendEnv=LC_EVPN_CLIENTS -R ('127.0.0.1:'+$RelayPort+':127.0.0.1:'+$LocalPort) entry ($Boot+' wizard '+$RelayPort+' '+$Operation)
 $script:WizardExit=$LASTEXITCODE
}
function Finish-Handoff {
 $prefix='/var/lib/empire-vpn-sessions/'+$env:LC_EVPN_SESSION
 while($true){
  $target=Ask Q24 'Save the private Android profile? Enter a NEW local JSON file path, or Enter to skip'
  if(!$target){break}
  $tmp=$null
  try{
   $dest=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($target)
   if([IO.File]::Exists($dest)){throw 'File already exists'}
   $tmp=Join-Path ([IO.Path]::GetDirectoryName($dest)) ([guid]::NewGuid().ToString('N')+'.tmp')
   [IO.File]::Open($tmp,'CreateNew','Write','None').Dispose()
   $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   & icacls.exe $tmp /inheritance:r /grant:r ('*'+$sid+':(F)') | Out-Null
   if($LASTEXITCODE){throw 'Private file permissions unavailable'}
   & scp -q -F $Config ('entry:'+$prefix+'.profile.json') $tmp
   if($LASTEXITCODE){throw 'Transfer failed'}
   [IO.File]::Move($tmp,$dest); Write-Host ('Saved private profile: '+$dest);break
  }catch{Write-Host 'Could not save the profile. Choose a new path in a private writable folder.'}
  finally{if($tmp -and [IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
 }
 while($true){
  $zip=Ask Q25 'Publish a static website now? Enter a local handoff ZIP path, or Enter to keep the current site'
  if(!$zip){return}
  try{$f=Get-Item -LiteralPath $zip -ErrorAction Stop;if($f.PSIsContainer -or $f.Length -gt 209715200){throw 'Invalid file'}}catch{Write-Host 'Select a ZIP up to 200 MiB.';continue}
  Write-Host 'Uploading site ZIP to entry. Only files under site/ will be published.'
  & scp -F $Config $f.FullName ('entry:'+$prefix+'.zip')
  if($LASTEXITCODE){Write-Host 'Upload failed. Retry or press Enter to skip.';continue}
  Run-Wizard publish-site
  if($script:WizardExit -eq 0){return}
 }
}
function Fresh-Sessions{
 foreach($role in @('entry','exit')){if((Probe $role) -ne 'ok'){return $false}}
 Write-Host 'New key-authenticated SSH sessions to both nodes: PASS';return $true
}
function Wait-Reboot([string]$Role){
 Start-Sleep -Seconds 8
 $clock=[Diagnostics.Stopwatch]::StartNew()
 Write-Host ("Waiting for "+$Role+" SSH after reboot (4 minutes plus final probe)...")
 while($clock.Elapsed.TotalSeconds -lt 240){if((Probe $Role) -eq 'ok'){return};Start-Sleep -Seconds 5}
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
function Ask-Node($id,$label){
 while($true){
  $target=Ask $id ($label+' root@IP or existing SSH alias')
  try{$node=Resolve-Target $target;if($node.user -eq 'root'){$node['enteredIPv4']=$target -match '^(root@)?(\d{1,3}\.){3}\d{1,3}$';return $node}}catch{}
  Write-Host 'Enter a valid root destination or SSH alias for root.'
 }
}
$Nodes=@{entry=(Ask-Node Q03 'Entry');exit=(Ask-Node Q05 'Exit')}
$keyDefault='new'
:selectKey while($true){
while ($true) {
 $Identity=Ask Q09 'Private SSH key path, new, or stop' $keyDefault
 if ($Identity -eq 'stop'){return}
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
  if($LASTEXITCODE -ne 0){Write-Host 'Key creation did not finish. Choose a key again.';continue selectKey}
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
  if((Ask Q21 'Start Windows ssh-agent service (requires UAC)? yes/no' 'yes') -ne 'yes'){continue selectKey}
  try {Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -Command "Set-Service ssh-agent -StartupType Manual; Start-Service ssh-agent"'} catch {Write-Host 'Agent startup cancelled or failed. Choose a key again.';continue selectKey}
 }
 & ssh-add $Identity
 if($LASTEXITCODE -ne 0){$keyDefault=$Identity;Write-Host 'Key was not unlocked. Press Enter at Q09 to retry the same key, enter a different path, or type stop.';continue selectKey}
}
break
}
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
 foreach($role in @('entry','exit')){Offer-Alias $role}
 $env:LC_EVPN_PROBE='1'
 foreach($role in @('entry','exit')){
  while($true){
  Write-Host ("Checking Ubuntu, Python and SSH environment: "+$role+" (up to 25 seconds)...")
  $probe=Invoke-SshCheck @('-o','SendEnv=LC_EVPN_PROBE',$role,'set -eu; . /etc/os-release; case $ID:$VERSION_ID:$(uname -m):$(id -u) in ubuntu:24.04:x86_64:0|ubuntu:26.04:x86_64:0) ;; *) exit 41;; esac; test x${LC_EVPN_PROBE:-} = x1 || exit 43; if command -v python3 >/dev/null; then echo READY; else echo MISSING_PYTHON; fi')
  if($probe.Code -eq 0 -and $probe.Output -in @('READY','MISSING_PYTHON')){break}
  $reason=switch($probe.Code){
   124 {'Timed out after 25 seconds.'}
   41 {'Ubuntu 24.04/26.04 amd64 and root access required.'}
   43 {'The SSH server did not accept LC_EVPN_PROBE. Check AcceptEnv LC_*.'}
   default {'Unexpected SSH response; code '+$probe.Code}
  }
  Write-Host ($role+': '+$reason)
  if((Ask 'Platform' 'Retry this check or stop?' 'retry') -eq 'stop'){return}
  }
  if($probe.Output -eq 'MISSING_PYTHON'){
   if((Ask Q22 ($role+': install python3 on VPS for inventory? Type INSTALL-PYTHON')) -ne 'INSTALL-PYTHON'){throw 'Python bootstrap declined'}
   & ssh -F $Config $role 'export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l; timeout -k 15s 600 apt-get update && timeout -k 15s 1200 apt-get install -y --no-install-recommends python3'
   if($LASTEXITCODE -ne 0){throw 'VPS Python bootstrap failed'}
  }
 }
 function Read-ClientExport{
 $env:LC_EVPN_CLIENTS=''
 while($true){
 $import=Ask Q13 'Optional LOCAL client export path (empty = existing/new credentials on entry)'
 try{
 if($import){
  $bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $import).ProviderPath)
  if($bytes.Length -gt 64000){throw 'Client export too large'}
  $env:LC_EVPN_CLIENTS=[Convert]::ToBase64String($bytes)
 }
 break
 }catch{Write-Host 'Cannot read this export (maximum 64000 bytes). Enter the path again.'}
 }
 }
 Read-ClientExport
 $random=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rng.GetBytes($random);$rng.Dispose()
 $env:LC_EVPN_TOKEN=[BitConverter]::ToString($random).Replace('-','').ToLowerInvariant()
 $env:LC_EVPN_SESSION=[guid]::NewGuid().ToString('N')
 $LocalPort=New-Port;$RpcPort=Get-Random -Minimum 30000 -Maximum 59000;$RelayPort=Get-Random -Minimum 30000 -Maximum 59000
 while(!$RpcProcess){
  try{$RpcProcess=Start-Rpc}catch{
   Write-Host 'Exit tunnel startup failed. Check SSH forwarding, Git HTTPS access and AcceptEnv.'
   if((Ask 'Tunnel' 'Retry or stop?' 'retry') -eq 'stop'){return}
  }
 }
 do {
  Run-Wizard start
  $code=$script:WizardExit
  if($code -eq 46){Read-ClientExport}
 }while($code -eq 46)
 if($code -eq 42){
  if(Fresh-Sessions){Run-Wizard finish;$code=$script:WizardExit;if($code -eq 0){Finish-Handoff}}else{Run-Wizard abort;throw 'New SSH session failed; rollback requested'}
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
}catch{
 Write-Host ('Setup stopped: '+$_.Exception.Message)
 $global:LASTEXITCODE=1
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
