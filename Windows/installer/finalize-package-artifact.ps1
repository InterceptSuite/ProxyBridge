param(
    [Parameter(Mandatory=$true)][string]$Configuration,
    [Parameter(Mandatory=$true)][ValidateSet('Uninstaller','Installer')][string]$Kind,
    [Parameter(Mandatory=$true)][string]$Artifact
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$path = (Resolve-Path -LiteralPath $Artifact).ProviderPath
$output = (Resolve-Path -LiteralPath $config.OutputDirectory).ProviderPath
if ($Kind -eq 'Installer' -and $path -ne (Join-Path $output 'ProxyBridge-Setup.exe')) { throw 'Unexpected installer output path.' }
$receipt = Join-Path $output ($Kind + '.json')
if (Test-Path -LiteralPath $receipt) { throw 'Finalization evidence already exists; use a new output directory.' }
if ($config.SignerThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid signing certificate identity.' }
$timestamp = [uri]$config.TimestampServer
if (!$timestamp.IsAbsoluteUri -or $timestamp.Scheme -notin @('http','https') -or !$timestamp.Host) {
    throw 'HTTP(S) RFC3161 timestamp server required.'
}
if ($Kind -eq 'Installer') {
    $uninstaller = Get-Content -LiteralPath (Join-Path $output 'Uninstaller.json') -Raw | ConvertFrom-Json
    if (!$uninstaller.SignatureVerified -or $uninstaller.SignerThumbprint -ne $config.SignerThumbprint -or
        $uninstaller.ManifestHash -ne $config.ManifestHash -or $uninstaller.LauncherHash -ne $config.LauncherHash -or
        (Get-FileHash -LiteralPath (Join-Path $output 'uninstall.exe') -Algorithm SHA256).Hash -ne $uninstaller.SHA256) {
        throw 'Uninstaller evidence does not match this package.'
    }
}
# Only generated artifacts are signed. Input payload/launcher and trust stores
# are never modified; no passwords or private keys are placed on command lines.
& $config.SignTool sign /sha1 $config.SignerThumbprint /s My /fd SHA256 /tr $timestamp.AbsoluteUri /td SHA256 $path
if ($LASTEXITCODE) { throw "Signing $Kind failed ($LASTEXITCODE)." }
& $config.SignTool verify /pa /all $path
if ($LASTEXITCODE) { throw "Signature policy verification of $Kind failed ($LASTEXITCODE)." }
$signature = Get-AuthenticodeSignature -LiteralPath $path
if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint -ne $config.SignerThumbprint -or !$signature.TimeStamperCertificate) {
    throw "Publisher/timestamp verification of $Kind failed."
}
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
if ($Kind -eq 'Uninstaller') {
    [IO.File]::Copy($path, (Join-Path $output 'uninstall.exe'), $false)
    if ((Get-FileHash -LiteralPath (Join-Path $output 'uninstall.exe') -Algorithm SHA256).Hash -ne $hash) { throw 'Uninstaller copy mismatch.' }
}
[pscustomobject]@{
    Kind=$Kind; SHA256=$hash; Bytes=(Get-Item -LiteralPath $path).Length
    SignerThumbprint=$signature.SignerCertificate.Thumbprint; SignatureVerified=$true
    ManifestHash=$config.ManifestHash; LauncherHash=$config.LauncherHash
    DriverSignaturePolicy=$config.DriverSignaturePolicy
    UninstallerHash=if($Kind -eq 'Installer'){$uninstaller.SHA256}else{$null}
} | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
