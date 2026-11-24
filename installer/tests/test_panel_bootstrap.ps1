param([Parameter(Mandatory=$true)][string]$Bootstrap)
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Bootstrap,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
$node=$ast.Find({param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Offer-PanelCA'},$true)
if(!$node){throw 'Missing CA handoff'}
Invoke-Expression $node.Extent.Text
$work=Join-Path ([IO.Path]::GetTempPath()) ('panel-public-ca-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work)|Out-Null
try{
 $script:certificate=[Text.Encoding]::ASCII.GetBytes("PUBLIC CA TEST`n")
 $script:hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($script:certificate)).ToLowerInvariant()
 $script:present=$true;$script:tamper=$false;$script:asks=0;$script:copies=0
 $script:target=Join-Path $work 'panel-ca.crt';$Config='mock';$entryHost='entry'
 function ssh { $global:LASTEXITCODE=0;if(!$script:present){$global:LASTEXITCODE=1;return};if(($args -join ' ') -like '*sha256sum*'){return ($script:hash+'  remote-ca.crt')} }
 function scp {$script:copies++;$destination=$args[-1];[IO.File]::WriteAllBytes($destination,$(if($script:tamper){[byte[]]@(0,1,2)}else{$script:certificate}));$global:LASTEXITCODE=0}
 function Ask {$script:asks++;if($script:asks-eq1){return $script:target};return ''}
 Offer-PanelCA '/var/lib/empire-vpn-sessions/synthetic'
 if(!$script:PanelCAAvailable -or !(Test-Path -LiteralPath $script:target) -or $script:copies-ne1){throw 'CA download failed'}
 if((Get-FileHash -LiteralPath $script:target).Hash.ToLowerInvariant()-ne$script:hash){throw 'CA changed'}
 $script:target=Join-Path $work 'bad-ca.crt';$script:tamper=$true;$script:asks=0
 Offer-PanelCA '/var/lib/empire-vpn-sessions/synthetic'
 if(Test-Path -LiteralPath $script:target){throw 'Mismatched CA published'}
 $script:present=$false;$script:copies=0;$script:asks=0
 Offer-PanelCA '/var/lib/empire-vpn-sessions/synthetic'
 if($script:PanelCAAvailable -or $script:copies-ne0 -or $script:asks-ne0){throw 'Missing CA was not skipped'}
 if($node.Extent.Text -match 'Import-Certificate|certutil|X509Store'){throw 'CA handoff changes trust'}
 Write-Output 'PASS: PowerShell CA verified/no-overwrite, corrupt refusal, absent skip; SSH mocked, no trust store changes'
}finally{Get-ChildItem -LiteralPath $work -File|Remove-Item;[IO.Directory]::Delete($work)}
