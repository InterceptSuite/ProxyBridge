param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Launcher,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [Parameter(Mandatory=$true)][string]$MakeNSIS,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedManifestHash,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedLauncherHash,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory=$true)][uint32]$Protocol,
    [Parameter(Mandatory=$true)][uint32]$DriverVersion,
    [Parameter(Mandatory=$true)][version]$AppVersion,
    [Parameter(Mandatory=$true)][uri]$TimestampServer,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('KernelPolicy','TestTrusted')][string]$DriverSignaturePolicy = 'KernelPolicy'
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Directory).ProviderPath
$launcherPath = (Resolve-Path -LiteralPath $Launcher).ProviderPath
$sign = (Resolve-Path -LiteralPath $SignTool).ProviderPath
$compiler = (Resolve-Path -LiteralPath $MakeNSIS).ProviderPath
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must be new.' }
# RFC 3161 timestamp tokens are signed by the TSA. Established providers expose
# their SignTool endpoints over HTTP, so TLS-only transport would make a valid
# signed token unavailable. Reject all other URI schemes and missing hosts.
if (!$TimestampServer.IsAbsoluteUri -or $TimestampServer.Scheme -notin @('http','https') -or !$TimestampServer.Host) {
    throw 'HTTP(S) RFC3161 timestamp server required.'
}
$shell = Join-Path $PSHOME 'powershell.exe'
if (!(Test-Path -LiteralPath $shell)) { $shell = Join-Path $PSHOME 'pwsh.exe' }
$finalizer = Join-Path $PSScriptRoot 'finalize-package-artifact.ps1'
# NSIS finalizers invoke a command shell. Reject metacharacters in the few paths
# passed through that shell; signing/tool arguments otherwise remain arrays.
foreach ($path in @($output,$shell,$finalizer)) {
    if ($path -match '[%&|<>^!"\r\n]') { throw 'Unsupported command-shell character in finalizer path.' }
}
$held = [Collections.Generic.List[IO.FileStream]]::new()
try {
    $files = @('payload.manifest','ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll',
        'ProxyBridgeDriverSetup.exe','driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')
    foreach ($path in (@($files | ForEach-Object { Join-Path $root $_ }) + @($launcherPath))) {
        $held.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    }
    $verified = & (Join-Path $PSScriptRoot 'verify-release-inputs.ps1') -Directory $root -Launcher $launcherPath `
        -SignTool $sign -ExpectedManifestHash $ExpectedManifestHash -ExpectedLauncherHash $ExpectedLauncherHash `
        -ExpectedSignerThumbprint $ExpectedSignerThumbprint -Protocol $Protocol -DriverVersion $DriverVersion -AppVersion $AppVersion `
        -DriverSignaturePolicy $DriverSignaturePolicy
    New-Item -ItemType Directory -Path $output -ErrorAction Stop | Out-Null
    $configuration = Join-Path $output 'signing.json'
    [pscustomobject]@{
        OutputDirectory=$output; SignTool=$sign; SignerThumbprint=$ExpectedSignerThumbprint
        TimestampServer=$TimestampServer.AbsoluteUri; ManifestHash=$verified.ManifestHash; LauncherHash=$verified.LauncherHash
        DriverSignaturePolicy=$verified.DriverSignaturePolicy
    } | ConvertTo-Json | Set-Content -LiteralPath $configuration -Encoding UTF8
    $setup = Join-Path $output 'ProxyBridge-Setup.exe'
    $arguments = @('/V2','/DTRANSACTION_REHEARSAL',"/DPRODUCT_VERSION=$AppVersion","/DPAYLOAD_DIR=$root","/DLAUNCHER_FILE=$launcherPath",
        "/DMANIFEST_SHA256=$ExpectedManifestHash","/DSETUP_OUTPUT=$setup","/DPACKAGE_FINALIZER=$finalizer",
        "/DPACKAGE_SIGNING_CONFIG=$configuration","/DPACKAGE_POWERSHELL=$shell",(Join-Path $PSScriptRoot 'ProxyBridge-transaction.nsi'))
    & $compiler @arguments
    if ($LASTEXITCODE) { throw "NSIS/signing failed ($LASTEXITCODE); output is incomplete." }
    $result = Get-Content -LiteralPath (Join-Path $output 'Installer.json') -Raw | ConvertFrom-Json
    if (!$result.SignatureVerified -or $result.Kind -ne 'Installer' -or
        $result.SignerThumbprint -ne $ExpectedSignerThumbprint -or $result.ManifestHash -ne $ExpectedManifestHash -or
        $result.LauncherHash -ne $ExpectedLauncherHash -or
        $result.DriverSignaturePolicy -ne $DriverSignaturePolicy -or
        (Get-FileHash -LiteralPath (Join-Path $output 'uninstall.exe') -Algorithm SHA256).Hash -ne $result.UninstallerHash -or
        (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -ne $result.SHA256) { throw 'Final installer evidence mismatch.' }
    $result
} finally {
    foreach ($stream in $held) { $stream.Dispose() }
}
# Authenticode on the final setup covers its embedded payload, launcher and
# signed uninstaller. JSON receipts are provenance, not independent trust roots.
# Transaction rehearsal status remains until PB-SUT gates pass.
