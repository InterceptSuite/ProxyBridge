param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Launcher,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedLauncherHash,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedManifestHash,
    [Parameter(Mandatory=$true)][uint32]$Protocol,
    [Parameter(Mandatory=$true)][uint32]$DriverVersion,
    [Parameter(Mandatory=$true)][version]$AppVersion,
    [ValidateSet('KernelPolicy','TestTrusted')][string]$DriverSignaturePolicy = 'KernelPolicy'
)
$ErrorActionPreference = 'Stop'
# Validation only: never sign, create certificates, modify trust or install.
# Call again if any input bytes change. Native staging retains verified handles
# at install time; this build-time script is not a substitute for that boundary.
$identity = & (Join-Path $PSScriptRoot 'verify-payload-manifest.ps1') -Directory $Directory `
    -ExpectedManifestHash $ExpectedManifestHash -Protocol $Protocol -DriverVersion $DriverVersion -AppVersion $AppVersion
$root = $identity.Directory
$tool = (Resolve-Path -LiteralPath $SignTool).ProviderPath
$launcherPath = (Resolve-Path -LiteralPath $Launcher).ProviderPath
if ((Get-FileHash -LiteralPath $launcherPath -Algorithm SHA256).Hash -ne $ExpectedLauncherHash) { throw 'Launcher SHA256 mismatch.' }
function Assert-Signature([string[]]$Arguments, [string]$Label) {
    $diagnostics = & $tool @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Signature verification failed: $Label`n$($diagnostics -join [Environment]::NewLine)"
    }
}
function Assert-Publisher([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
        throw "Expected publisher signature not verified: $Path"
    }
}
foreach ($name in @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe')) {
    Assert-Signature -Arguments @('verify','/pa','/all',(Join-Path $root $name)) -Label $name
    Assert-Publisher (Join-Path $root $name)
}
Assert-Signature -Arguments @('verify','/pa','/all',$launcherPath) -Label 'launcher'
Assert-Publisher $launcherPath
$catalog = Join-Path $root 'driver\ProxyBridgeDrv.cat'
$catalogArguments = if ($DriverSignaturePolicy -eq 'KernelPolicy') {
    @('verify','/kp',$catalog)
} else {
    @('verify','/pa','/all',$catalog)
}
Assert-Signature -Arguments $catalogArguments -Label "driver catalog $DriverSignaturePolicy policy"
foreach ($name in @('ProxyBridgeDrv.inf','ProxyBridgeDrv.sys')) {
    $memberArguments = if ($DriverSignaturePolicy -eq 'KernelPolicy') {
        @('verify','/kp','/c',$catalog,(Join-Path $root "driver\$name"))
    } else {
        @('verify','/pa','/c',$catalog,(Join-Path $root "driver\$name"))
    }
    Assert-Signature -Arguments $memberArguments -Label "catalog membership: $name"
}
[pscustomobject]@{
    Directory = $root
    ManifestHash = $identity.ManifestHash
    LauncherHash = (Get-FileHash -LiteralPath $launcherPath -Algorithm SHA256).Hash
    DriverSignaturePolicy = $DriverSignaturePolicy
    HostSignaturePolicyVerified = $true
}
# TestTrusted establishes host trust and catalog membership only; it does not
# prove production kernel-signing eligibility, HLK certification, or support
# on a host without the test root. The final installer must itself be signed.
