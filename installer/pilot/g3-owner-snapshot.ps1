param(
    [string]$OwnerDirectory,
    [string]$Source,
    [string]$ExpectedSha256,
    [switch]$PrepareOwner,
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Same compact JWE envelope as recovery_rehearsal.py: RSA-OAEP-256/A256GCM.
# Native .NET avoids installing a second runtime on the owner's Windows PC.
$Limit = 32MB
function Get-Digest([byte[]]$Bytes) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}
function To-B64([byte[]]$Bytes) { return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
function From-B64([string]$Text) {
    $text = $Text.Replace('-','+').Replace('_','/')
    return ,([Convert]::FromBase64String($text.PadRight($text.Length + ((4-$text.Length%4)%4),'=')))
}
function Set-PrivateAcl([string]$Path,[bool]$Directory) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $existing = Get-Acl -LiteralPath $Path
    $rules = @($existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $private = $rules.Count -eq 2
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin @($identity.Value,$system.Value) -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) { $private = $false }
    }
    if ($private -and (-not $Directory -or $existing.AreAccessRulesProtected)) { return }
    if ($Directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { $acl = [Security.AccessControl.FileSecurity]::new(); $inherit = [Security.AccessControl.InheritanceFlags]::None }
    # Set only the DACL. Reassigning an existing owner needs unnecessary
    # SeRestorePrivilege; user+SYSTEM access does not require that privilege.
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($identity,$system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    if ($Directory) { [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path),$acl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path),$acl) }
}
function Get-OwnerPath([string]$Directory) {
    $full = [IO.Path]::GetFullPath($Directory)
    $project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
    if ($full.Equals($project,[StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($project+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Owner files must stay outside the repository' }
    $probe = [IO.DirectoryInfo]::new($full)
    while ($null -ne $probe) {
        if ($probe.Exists -and ($probe.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse owner path refused' }
        $probe = $probe.Parent
    }
    return $full
}
function Initialize-Owner([string]$Directory) {
    $directory = Get-OwnerPath $Directory
    $private = Join-Path $directory 'recipient-private.pem'; $public = Join-Path $directory 'recipient-public.pem'
    if ((Test-Path -LiteralPath $directory) -and -not (Test-Path -LiteralPath $private) -and -not (Test-Path -LiteralPath $public) -and @(Get-ChildItem -LiteralPath $directory -Force).Count -gt 0) { throw 'Unknown owner directory refused' }
    [void][IO.Directory]::CreateDirectory($directory); Set-PrivateAcl $directory $true
    $rsa = [Security.Cryptography.RSA]::Create()
    if ((Test-Path -LiteralPath $private) -or (Test-Path -LiteralPath $public)) {
        if (-not (Test-Path -LiteralPath $private) -or -not (Test-Path -LiteralPath $public)) { $rsa.Dispose(); throw 'Partial key pair; preserve existing key' }
        foreach ($path in @($private,$public)) {
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse key refused' }
            Set-PrivateAcl $path $false
        }
        $rsa.ImportFromPem([IO.File]::ReadAllText($private))
        if ($rsa.ExportSubjectPublicKeyInfoPem() -ne [IO.File]::ReadAllText($public)) { $rsa.Dispose(); throw 'Recipient mismatch' }
    } else {
        $rsa.KeySize = 3072
        [IO.File]::WriteAllText($private,$rsa.ExportPkcs8PrivateKeyPem(),[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($public,$rsa.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))
        Set-PrivateAcl $private $false; Set-PrivateAcl $public $false
    }
    return $rsa
}
function Protect-Bytes([Security.Cryptography.RSA]$Rsa,[byte[]]$Plain) {
    $header = To-B64 ([Text.Encoding]::UTF8.GetBytes('{"alg":"RSA-OAEP-256","enc":"A256GCM"}'))
    $key = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $nonce = [Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
    $cipher = [byte[]]::new($Plain.Length); $tag = [byte[]]::new(16)
    $gcm = [Security.Cryptography.AesGcm]::new($key,16)
    try {
        $gcm.Encrypt($nonce,$Plain,$cipher,$tag,[Text.Encoding]::ASCII.GetBytes($header))
        $wrapped = $Rsa.Encrypt($key,[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        return [Text.Encoding]::ASCII.GetBytes((@($header,(To-B64 $wrapped),(To-B64 $nonce),(To-B64 $cipher),(To-B64 $tag)) -join '.'))
    } finally { $gcm.Dispose(); [Array]::Clear($key,0,$key.Length) }
}
function Unprotect-Bytes([Security.Cryptography.RSA]$Rsa,[byte[]]$Envelope) {
    if ($Envelope.Length -gt 48MB) { throw 'Envelope size refused' }
    $parts = [Text.Encoding]::ASCII.GetString($Envelope).Split('.')
    if ($parts.Length -ne 5) { throw 'Envelope format refused' }
    $header = [Text.Encoding]::UTF8.GetString((From-B64 $parts[0])) | ConvertFrom-Json
    if ($header.alg -ne 'RSA-OAEP-256' -or $header.enc -ne 'A256GCM') { throw 'Envelope algorithm refused' }
    $key = $Rsa.Decrypt((From-B64 $parts[1]),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $cipher = From-B64 $parts[3]; $plain = [byte[]]::new($cipher.Length)
    $gcm = [Security.Cryptography.AesGcm]::new($key,16)
    try {
        $gcm.Decrypt((From-B64 $parts[2]),$cipher,(From-B64 $parts[4]),$plain,[Text.Encoding]::ASCII.GetBytes($parts[0]))
        return ,$plain
    } finally { $gcm.Dispose(); [Array]::Clear($key,0,$key.Length) }
}
function Read-SnapshotMetadata([byte[]]$Payload) {
    if ($Payload.Length -gt $Limit) { throw 'Snapshot size refused' }
    $stream = [IO.MemoryStream]::new($Payload,$false)
    $reader = [System.Formats.Tar.TarReader]::new($stream,$false)
    $metadata = $null; $count = 0
    try {
        while ($null -ne ($entry = $reader.GetNextEntry())) {
            $count++; if ($count -gt 4096 -or $entry.Name.StartsWith('/') -or ($entry.Name.Split('/') -contains '..') -or $entry.EntryType -in @([System.Formats.Tar.TarEntryType]::SymbolicLink,[System.Formats.Tar.TarEntryType]::HardLink)) { throw 'Archive member refused' }
            if ($entry.Name -in @('G3-SNAPSHOT.json','./G3-SNAPSHOT.json')) {
                if ($entry.Length -gt 1MB) { throw 'Metadata size refused' }
                $body = [IO.MemoryStream]::new(); $entry.DataStream.CopyTo($body)
                $metadata = [Text.Encoding]::UTF8.GetString($body.ToArray()) | ConvertFrom-Json
                $body.Dispose()
            }
        }
        if ($null -eq $metadata -or $metadata.format -ne 'vpn-control-g3-snapshot-v1') { throw 'Snapshot metadata refused' }
        return $metadata
    } finally { $reader.Dispose() }
}
function Protect-Snapshot([string]$Directory,[string]$InputPath,[string]$Expected) {
    $directory = Get-OwnerPath $Directory
    $inputPath = [IO.Path]::GetFullPath($InputPath)
    if ([IO.Path]::GetDirectoryName($inputPath) -ne $directory -or -not (Test-Path -LiteralPath (Join-Path $directory 'recipient-private.pem'))) { throw 'Prepare private recipient before transferring raw data' }
    if ((Get-Item -LiteralPath $inputPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse source refused' }
    if ((Get-Item -LiteralPath $inputPath).Length -gt $Limit) { throw 'Snapshot size refused' }
    Set-PrivateAcl $inputPath $false
    $rsa = Initialize-Owner $directory
    $plain = [IO.File]::ReadAllBytes($inputPath)
    try {
        if ((Get-Digest $plain) -ne $Expected) { throw 'SSH snapshot digest mismatch' }
        $metadata = Read-SnapshotMetadata $plain
        $output = [IO.Path]::ChangeExtension($inputPath,'jwe'); $receipt = $output+'.receipt.json'
        if (Test-Path -LiteralPath $output) {
            $envelope = [IO.File]::ReadAllBytes($output)
            if (Test-Path -LiteralPath $receipt) {
                $record = [IO.File]::ReadAllText($receipt) | ConvertFrom-Json
                if ($record.raw_sha256 -ne $Expected -or $record.cipher_sha256 -ne (Get-Digest $envelope)) { throw 'Existing snapshot mismatch' }
            }
        } else { $envelope = Protect-Bytes $rsa $plain }
        $verified = Unprotect-Bytes $rsa $envelope
        try { if ((Get-Digest $verified) -ne $Expected) { throw 'Decrypted snapshot mismatch' } } finally { [Array]::Clear($verified,0,$verified.Length) }
        if (-not (Test-Path -LiteralPath $output)) {
            [IO.File]::WriteAllBytes($output,$envelope); Set-PrivateAcl $output $false
        }
        if (-not (Test-Path -LiteralPath $receipt)) {
            $record = @{ raw_sha256=$Expected; cipher_sha256=(Get-Digest $envelope); phase=$metadata.phase; generation=$metadata.generation; window=$metadata.window }
            [IO.File]::WriteAllText($receipt,($record | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false)); Set-PrivateAcl $receipt $false
        }
        Write-Output 'Protected owner snapshot encrypted, decrypted and verified'
    } finally { $rsa.Dispose(); [Array]::Clear($plain,0,$plain.Length) }
}
function Invoke-SelfTest {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    $directory = Join-Path $tempRoot ('vpn-g3-owner-'+[Guid]::NewGuid().ToString('N'))
    try {
        $rsa = Initialize-Owner $directory; $rsa.Dispose()
        $payload = [Text.Encoding]::UTF8.GetBytes('{"format":"vpn-control-g3-snapshot-v1","window":"synthetic","phase":"pre","generation":0}')
        $stream = [IO.MemoryStream]::new(); $writer = [System.Formats.Tar.TarWriter]::new($stream,$true)
        $entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile,'./G3-SNAPSHOT.json')
        $entry.DataStream = [IO.MemoryStream]::new($payload,$false); $writer.WriteEntry($entry); $writer.Dispose()
        $source = Join-Path $directory 'synthetic.tar'; [IO.File]::WriteAllBytes($source,$stream.ToArray()); $stream.Dispose()
        $digest = Get-Digest ([IO.File]::ReadAllBytes($source))
        Protect-Snapshot $directory $source $digest
        $first = Get-Digest ([IO.File]::ReadAllBytes((Join-Path $directory 'synthetic.jwe')))
        Remove-Item -LiteralPath (Join-Path $directory 'synthetic.jwe.receipt.json')
        Protect-Snapshot $directory $source $digest
        if ($first -ne (Get-Digest ([IO.File]::ReadAllBytes((Join-Path $directory 'synthetic.jwe'))))) { throw 'Replay changed ciphertext' }
        $rsa = Initialize-Owner $directory
        try {
            $damaged = [IO.File]::ReadAllBytes((Join-Path $directory 'synthetic.jwe')); $damaged[$damaged.Length-5] = $damaged[$damaged.Length-5] -bxor 1
            $rejected = $false; try { [void](Unprotect-Bytes $rsa $damaged) } catch { $rejected = $true }
            if (-not $rejected) { throw 'Tampered envelope accepted' }
            # Existing Python provider encrypts to the public key only.
            # The private key remains on Windows, even in this synthetic test.
            $info = [Diagnostics.ProcessStartInfo]::new('ssh')
            foreach ($arg in @('-o','BatchMode=yes','hh-entry',"python3 -B -c 'import sys;sys.path.insert(0,`"/run/vpn-w3-worker-tests/pilot`");from recovery_rehearsal import seal;sys.stdout.buffer.write(seal(sys.stdin.buffer.read(),b`"owner-g3-interop`"))'")) { $info.ArgumentList.Add($arg) }
            $info.UseShellExecute=$false; $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            $process=[Diagnostics.Process]::Start($info)
            $process.StandardInput.Write([IO.File]::ReadAllText((Join-Path $directory 'recipient-public.pem')));$process.StandardInput.Close()
            $reply=$process.StandardOutput.ReadToEnd();$diagnostic=$process.StandardError.ReadToEnd();$process.WaitForExit()
            if ($process.ExitCode -ne 0) { throw 'Existing provider interoperability failed' }
            $decoded=Unprotect-Bytes $rsa ([Text.Encoding]::ASCII.GetBytes($reply))
            if ([Text.Encoding]::ASCII.GetString($decoded) -ne 'owner-g3-interop') { throw 'Interoperability plaintext mismatch' }
            [Array]::Clear($decoded,0,$decoded.Length)
        } finally { $rsa.Dispose() }
        Write-Output 'Owner snapshot self-test PASS: private ACL, roundtrip, replay, tamper rejection'
    } finally {
        if (-not [IO.Path]::GetFullPath($directory).StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup path refused' }
        foreach ($name in @('synthetic.tar','synthetic.jwe','synthetic.jwe.receipt.json','recipient-private.pem','recipient-public.pem')) {
            $path = Join-Path $directory $name; if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
        }
        if (Test-Path -LiteralPath $directory) { [IO.Directory]::Delete($directory,$false) }
    }
}
try {
    if ([Environment]::Version.Major -lt 8) { throw 'PowerShell with .NET 8 or newer required' }
    if ($SelfTest) { Invoke-SelfTest }
    elseif ($PrepareOwner) { $rsa = Initialize-Owner $OwnerDirectory; $rsa.Dispose(); Write-Output 'Private owner recipient ready' }
    else { Protect-Snapshot $OwnerDirectory $Source $ExpectedSha256 }
} catch {
    if ($SelfTest) { Write-Output ($_.Exception.GetType().FullName+': '+$_.ScriptStackTrace) }
    Write-Error -Message 'Owner snapshot refused; preserve protected files and keys.' -ErrorAction Continue; exit 1
}
