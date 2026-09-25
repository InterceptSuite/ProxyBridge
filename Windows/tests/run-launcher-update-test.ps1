param([Parameter(Mandatory=$true)][string]$Evidence)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Evidence).ProviderPath
$hashes = @{}
foreach ($label in @('a','b')) {
    $directory = Join-Path $root "fixture-$label"
    if (Test-Path -LiteralPath $directory) { throw "Fixture already exists: $directory" }
    New-Item -ItemType Directory -Path (Join-Path $directory 'driver') | Out-Null
    foreach ($name in @('ProxyBridge.exe','ProxyBridge_CLI.exe')) {
        [IO.File]::Copy((Join-Path $root "version-$label.exe"), (Join-Path $directory $name), $false)
    }
    foreach ($name in @('ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe','driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')) {
        # Deliberately inert placeholders. Only the benign GUI/CLI children run.
        [IO.File]::WriteAllText((Join-Path $directory $name), "NOT INSTALLABLE: launcher test fixture $label")
    }
    $manifest = & "$PSScriptRoot\..\installer\make-payload-manifest.ps1" -Directory $directory -Protocol 4 -DriverVersion 65537 -AppVersion '1.0.0.0'
    $hashes[$label] = $manifest.Hash
}
& (Join-Path $root 'launcher-update-test.exe') (Join-Path $root 'fixture-a') $hashes['a'] (Join-Path $root 'fixture-b') $hashes['b'] *> (Join-Path $root 'test.log')
$testExit = $LASTEXITCODE
Get-Content -LiteralPath (Join-Path $root 'test.log')
if ($testExit -ne 0) { throw "Launcher update test failed: $testExit" }
[pscustomobject]@{ TestExit=$testExit; ManifestA=$hashes['a']; ManifestB=$hashes['b']; RealRegistryAccess=$false; DriverLoaded=$false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'verification.json')
