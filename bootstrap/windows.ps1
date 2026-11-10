$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$Version='v0.1.1'
$BundleHash='1c2ddc94f83624b18916dd83b0648f273b5f239806a12c05836744c05b900d8c'
$Base='https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/'+$Version
$PythonHash='67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb'
function Get-EmpireHash([string]$Path){
 $stream=[IO.File]::OpenRead($Path)
 $algorithm=[Security.Cryptography.SHA256]::Create()
 try{return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
 finally{$algorithm.Dispose();$stream.Dispose()}
}
foreach($tool in @('ssh.exe','ssh-keygen.exe')){
 if(!(Get-Command $tool -ErrorAction SilentlyContinue)){
  Write-Host 'Windows OpenSSH Client is required. Windows may ask for administrator permission.'
  if((Read-Host '[B01] Install Windows OpenSSH Client? yes/no') -ne 'yes'){throw 'OpenSSH installation declined'}
  $process=Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile -Command "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"'
  if($process.ExitCode -ne 0){throw 'OpenSSH installation failed'}
  break
 }
}
$PythonPath=$null
foreach($candidate in @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),'python3.exe','python.exe')){
 $resolved=Get-Command $candidate -ErrorAction SilentlyContinue
 if($resolved -and $resolved.Source -notmatch 'WindowsApps'){
  & $resolved.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)' 2>$null
  if($LASTEXITCODE -eq 0){$PythonPath=$resolved.Source;break}
 }
}
$DownloadDir=Join-Path $env:TEMP ('empire-bootstrap-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $DownloadDir | Out-Null
try{
 if(!$PythonPath){
  if((Read-Host '[B02] Install official Python 3.12.10 for this Windows user? yes/no') -ne 'yes'){throw 'Python installation declined'}
  $installer=Join-Path $DownloadDir 'python.exe'
  Invoke-WebRequest -UseBasicParsing 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe' -OutFile $installer
  if((Get-EmpireHash $installer) -ne $PythonHash){throw 'Python checksum mismatch'}
  $install=Start-Process -FilePath $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList '/quiet InstallAllUsers=0 Include_test=0 Include_pip=0 PrependPath=0'
  if($install.ExitCode -ne 0){throw 'Python installation failed'}
  $PythonPath=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
 }
 $archive=Join-Path $DownloadDir 'installer.zip'
 Invoke-WebRequest -UseBasicParsing ($Base+'/dist/installer.zip') -OutFile $archive
 if((Get-EmpireHash $archive) -ne $BundleHash){throw 'Installer bundle checksum mismatch'}
 $destination=Join-Path $env:LOCALAPPDATA ('EmpireVPN\'+$Version+'-'+$BundleHash.Substring(0,12))
 if(Test-Path -LiteralPath $destination){
  & $PythonPath -c 'import pathlib,sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); p=pathlib.Path(sys.argv[2]); sys.exit(0 if all((p/n).is_file() and (p/n).read_bytes()==z.read(n) for n in z.namelist()) else 1)' $archive $destination
  if($LASTEXITCODE -ne 0){throw 'Previously downloaded files changed. Refusing overwrite.'}
 }else{
  [void][Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
  [IO.Compression.ZipFile]::ExtractToDirectory($archive,$destination)
 }
 Write-Host ('Installer directory: '+$destination)
 & $PythonPath -B (Join-Path $destination 'client.py') wizard
 if($LASTEXITCODE -ne 0){throw ('Installer exited with code '+$LASTEXITCODE+'; resume using '+$destination+'\Install-Vpn.ps1')}
} finally {
 if($DownloadDir -and (Split-Path -Parent $DownloadDir) -eq $env:TEMP){
  try{Remove-Item -LiteralPath $DownloadDir -Recurse -Force}catch{Write-Warning 'Temporary download directory could not be removed.'}
 }
}
