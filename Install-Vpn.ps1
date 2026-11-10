[CmdletBinding()]
param(
 [ValidateSet('wizard','preview','apply','verify','rollback','acceptance','reboot-test','test')][string]$Action='wizard',
 [string]$Config,
 [string]$PythonPath=$env:EMPIRE_PYTHON,
 [switch]$Offline
)
$ErrorActionPreference='Stop'
if(!$PythonPath){
 foreach($candidate in @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),'python3.exe','python.exe')){
  $cmd=Get-Command $candidate -ErrorAction SilentlyContinue
  if($cmd -and $cmd.Source -notmatch 'WindowsApps'){
   & $cmd.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)' 2>$null
   if($LASTEXITCODE -eq 0){$PythonPath=$cmd.Source;break}
  }
 }
}
if(!$PythonPath){throw 'Python 3.12+ not found. Run the README bootstrap command; it offers the official Python installer.'}
$arguments=@('-B',(Join-Path $PSScriptRoot 'client.py'),$Action)
if($Config){$arguments+=@('--config',$Config)}
if($Offline){$arguments+='--offline'}
& $PythonPath @arguments
exit $LASTEXITCODE
