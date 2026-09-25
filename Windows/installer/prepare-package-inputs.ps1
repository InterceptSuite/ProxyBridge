[CmdletBinding(DefaultParameterSetName='BuildTree')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='BuildTree')][string]$BuildRoot,
    [Parameter(Mandatory=$true,ParameterSetName='SeparateDriver')][string]$ApplicationDirectory,
    [Parameter(Mandatory=$true,ParameterSetName='SeparateDriver')][string]$DriverDirectory,
    [Parameter(Mandatory=$true,ParameterSetName='SeparateDriver')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedDriverCatalogHash,
    [Parameter(Mandatory=$true,ParameterSetName='SeparateDriver')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedDriverBinaryHash,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][uint32]$Protocol,
    [Parameter(Mandatory=$true)][uint32]$DriverVersion,
    [Parameter(Mandatory=$true)][version]$AppVersion
)
$ErrorActionPreference = 'Stop'
$separate = $PSCmdlet.ParameterSetName -eq 'SeparateDriver'
$root = if ($separate) { (Resolve-Path -LiteralPath $ApplicationDirectory).ProviderPath } else { (Resolve-Path -LiteralPath $BuildRoot).ProviderPath }
$driverRoot = if ($separate) { (Resolve-Path -LiteralPath $DriverDirectory).ProviderPath } else { $root }
$target = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $target) { throw 'Destination must be new; existing artifacts are never replaced.' }
# The helper validates the manifest against these compile-time values. Accepting
# arbitrary caller numbers can make an otherwise intact package fail only after
# its recovery bootstrap was published. Keep payload metadata tied to the same
# driver contract used to compile the helper.
$contract = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\driver\ProxyBridgeDrv_ioctl.h'
if (!(Test-Path -LiteralPath $contract -PathType Leaf)) { throw "Driver contract header missing: $contract" }
$header = Get-Content -LiteralPath $contract -Raw
$protocolMatch = [regex]::Match($header, '(?m)^\s*#define\s+PBDRV_PROTOCOL_VERSION\s+(\d+)u?\s*$')
$versionMatch = [regex]::Match($header, '(?m)^\s*#define\s+PBDRV_DRIVER_VERSION\s+(0x[0-9a-fA-F]+|\d+)u?\b')
if (!$protocolMatch.Success -or !$versionMatch.Success) { throw 'Unable to read driver protocol/version contract.' }
$contractProtocol = [uint32]$protocolMatch.Groups[1].Value
$versionText = $versionMatch.Groups[1].Value
$contractDriverVersion = if ($versionText.StartsWith('0x')) {
    [Convert]::ToUInt32($versionText.Substring(2), 16)
} else { [uint32]$versionText }
if ($Protocol -ne $contractProtocol -or $DriverVersion -ne $contractDriverVersion) {
    throw "Payload contract mismatch: requested protocol=$Protocol, driverVersion=$DriverVersion; helper requires protocol=$contractProtocol, driverVersion=$contractDriverVersion."
}
$mapping = [ordered]@{
    'gui\ProxyBridge.exe' = 'payload\ProxyBridge.exe'
    'cli\ProxyBridge_CLI.exe' = 'payload\ProxyBridge_CLI.exe'
    'core\ProxyBridgeCore.dll' = 'payload\ProxyBridgeCore.dll'
    'helper\bin\ProxyBridgeDriverSetup.exe' = 'payload\ProxyBridgeDriverSetup.exe'
    'driver\bin\ProxyBridgeDrv\ProxyBridgeDrv.inf' = 'payload\driver\ProxyBridgeDrv.inf'
    'driver\bin\ProxyBridgeDrv\ProxyBridgeDrv.cat' = 'payload\driver\ProxyBridgeDrv.cat'
    'driver\bin\ProxyBridgeDrv\ProxyBridgeDrv.sys' = 'payload\driver\ProxyBridgeDrv.sys'
    'launcher\bin\ProxyBridgeLauncher.exe' = 'ProxyBridgeLauncher.exe'
}
# Map a flat application build to a separately retained Microsoft-signed driver.
# Hash pinning selects exact inputs; signature/catalog membership is independently
# required by verify-release-inputs/build-signed-package after preparation.
$sources = @{}
foreach ($name in $mapping.Keys) {
    $isDriver = $name.StartsWith('driver\')
    $sources[$name] = if ($separate) {
        Join-Path $(if ($isDriver) { $driverRoot } else { $root }) (Split-Path $name -Leaf)
    } else { Join-Path $root $name }
}
foreach ($name in $mapping.Keys) {
    if (!(Test-Path -LiteralPath $sources[$name] -PathType Leaf)) { throw "Missing build artifact: $name" }
}
if ($separate) {
    if ((Get-FileHash -LiteralPath (Join-Path $driverRoot 'ProxyBridgeDrv.cat')).Hash -ne $ExpectedDriverCatalogHash -or
        (Get-FileHash -LiteralPath (Join-Path $driverRoot 'ProxyBridgeDrv.sys')).Hash -ne $ExpectedDriverBinaryHash) {
        throw 'Selected driver hashes do not match the expected package.'
    }
}
New-Item -ItemType Directory -Path (Join-Path $target 'payload\driver') | Out-Null
$inventory = foreach ($entry in $mapping.GetEnumerator()) {
    $source = $sources[$entry.Key]
    $output = Join-Path $target $entry.Value
    # No overwrite, no move, no signing and no recursive copy.
    [IO.File]::Copy($source, $output, $false)
    $hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    if ($hash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash) { throw "Source changed during copy: $source" }
    [pscustomobject]@{ File=$entry.Value; Source=$source; Bytes=(Get-Item -LiteralPath $output).Length; SHA256=$hash }
}
if ($separate) {
    if ((Get-FileHash -LiteralPath (Join-Path $target 'payload\driver\ProxyBridgeDrv.cat')).Hash -ne $ExpectedDriverCatalogHash -or
        (Get-FileHash -LiteralPath (Join-Path $target 'payload\driver\ProxyBridgeDrv.sys')).Hash -ne $ExpectedDriverBinaryHash) {
        throw 'Copied driver hashes differ from the pinned input; no manifest produced.'
    }
}
$manifest = & (Join-Path $PSScriptRoot 'make-payload-manifest.ps1') -Directory (Join-Path $target 'payload') `
    -Protocol $Protocol -DriverVersion $DriverVersion -AppVersion $AppVersion
& (Join-Path $PSScriptRoot 'verify-payload-manifest.ps1') -Directory (Join-Path $target 'payload') `
    -ExpectedManifestHash $manifest.Hash -Protocol $Protocol -DriverVersion $DriverVersion -AppVersion $AppVersion | Out-Null
$inventory | Export-Csv -LiteralPath (Join-Path $target 'inventory.csv') -NoTypeInformation -Encoding UTF8
[pscustomobject]@{ Directory=$target; ManifestHash=$manifest.Hash; LauncherHash=(Get-FileHash -LiteralPath (Join-Path $target 'ProxyBridgeLauncher.exe')).Hash; BinaryBytes=($inventory | Measure-Object Bytes -Sum).Sum }
# Input collection only. Declared versions are not inferred from PE metadata.
# Any later signing changes hashes: generate a new manifest/package directory.
