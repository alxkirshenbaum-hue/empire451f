$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot '../bootstrap/native-windows.ps1.in'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors | Out-String)}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Finish-Handoff'},$true)
Invoke-Expression $fn.Extent.Text
$root=Join-Path ([IO.Path]::GetTempPath()) ('handoff test '+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
function Assert($condition,$message){if(!$condition){throw $message}}
function Ask($id,$message,$default){
 $script:questions+=@($id)
 if(!$script:answers.Count){throw 'Unexpected prompt'}
 $value=$script:answers[0];$script:answers=@($script:answers | Select-Object -Skip 1)
 if($value -eq '<default>'){return $default};return $value
}
function Write-Host { $script:output+=($args -join ' ') }
function icacls.exe { $global:LASTEXITCODE=0 }
function ssh { $global:LASTEXITCODE=0 }
function scp {
 $script:transfers++
 if($script:failOnce){$script:failOnce=$false;$global:LASTEXITCODE=1;return}
 [IO.File]::WriteAllText([string]$args[-1],'private-test-json');$global:LASTEXITCODE=0
}
$env:LC_EVPN_SESSION='testsession'
$Config=Join-Path $root 'ephemeral.conf';$entryHost='entry';$resume=$false
$Identity=Join-Path $root 'key with spaces';$Jumps=@{}
$Nodes=@{entry=@{hostname='192.0.2.1';user='root';port='2222'}}
try {
 foreach($case in @('later','yes','failure','existing')){
  $script:output=@();$script:questions=@();$script:transfers=0;$script:failOnce=($case -eq 'failure')
  $dest=Join-Path $root ($case+' private.json')
  switch($case){
   later {$script:answers=@('2')}
   yes {$script:answers=@('<default>',$dest)}
   failure {$script:answers=@('1',$dest,'1',$dest)}
   existing {[IO.File]::WriteAllText($dest,'old');$script:answers=@('1',$dest,'2')}
  }
  Finish-Handoff
  $command=($script:output | Where-Object {$_ -like 'Download command:*'}) -join ''
  Assert ($command.Contains('192.0.2.1') -and $command.Contains('2222')) 'Standalone route missing'
  Assert (!$command.Contains($Config)) 'Command refers to temporary config'
  Assert ($command.Contains('CreateNew') -and $command.Contains('icacls.exe') -and $command.Contains('[IO.File]::Move')) 'Private no-overwrite command missing'
  Assert ($script:questions[0] -eq 'Q24.1') 'Choice missing'
  if($case -eq 'later'){Assert ($script:transfers -eq 0) 'Later transferred'}
  if($case -eq 'yes' -or $case -eq 'failure'){Assert ([IO.File]::ReadAllText($dest) -eq 'private-test-json') 'Transfer failed'}
  if($case -eq 'failure'){Assert ($script:transfers -eq 2) 'Retry missing'}
  if($case -eq 'existing'){Assert ([IO.File]::ReadAllText($dest) -eq 'old') 'Existing file overwritten'}
 }
 [Console]::WriteLine('profile handoff: PASS (later/default yes/spaces/failure/no overwrite)')
}finally{[IO.Directory]::Delete($root,$true)}