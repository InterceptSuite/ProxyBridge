param([Parameter(Mandatory=$true)][string]$Results)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Results) { throw 'Use new results directory.' }
$app = Join-Path $Results 'app'
$driver = Join-Path $Results 'driver'
New-Item -ItemType Directory -Path $app,$driver | Out-Null
foreach ($name in @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe','ProxyBridgeLauncher.exe')) {
    Set-Content -LiteralPath (Join-Path $app $name) -Value "INERT APP $name"
}
foreach ($name in @('ProxyBridgeDrv.inf','ProxyBridgeDrv.cat','ProxyBridgeDrv.sys')) {
    Set-Content -LiteralPath (Join-Path $driver $name) -Value "INERT DRIVER $name"
}
$prepare = Join-Path (Split-Path $PSScriptRoot) 'prepare-package-inputs.ps1'
$params = @{ApplicationDirectory=$app; DriverDirectory=$driver; Protocol=4; DriverVersion=65537; AppVersion='1.0.0.0';
    ExpectedDriverCatalogHash=(Get-FileHash (Join-Path $driver 'ProxyBridgeDrv.cat')).Hash;
    ExpectedDriverBinaryHash=(Get-FileHash (Join-Path $driver 'ProxyBridgeDrv.sys')).Hash}
$dest = Join-Path $Results 'prepared'
$result = & $prepare @params -Destination $dest
$inventory = @(Import-Csv (Join-Path $dest 'inventory.csv'))
if ($inventory.Count -ne 8) { throw 'Expected exactly eight files.' }
foreach ($row in $inventory) {
    if ((Get-FileHash -LiteralPath (Join-Path $dest $row.File)).Hash -ne (Get-FileHash -LiteralPath $row.Source).Hash) { throw 'Copy mismatch.' }
}
function Refuse($label,$changes,$expected) {
    $argsCopy = $params.Clone()
    foreach ($key in $changes.Keys) { $argsCopy[$key]=$changes[$key] }
    $path = Join-Path $Results $label
    $caught = $false
    try { & $prepare @argsCopy -Destination $path | Out-Null } catch {
        if ($_.Exception.Message -notmatch $expected) { throw }
        $caught = $true
    }
    if (!$caught -or (Test-Path -LiteralPath $path)) { throw "Expected pre-copy refusal: $label" }
}
Refuse 'wrong-catalog' @{ExpectedDriverCatalogHash=('0'*64)} 'driver hashes'
Refuse 'wrong-binary' @{ExpectedDriverBinaryHash=('0'*64)} 'driver hashes'
Refuse 'wrong-protocol' @{Protocol=2} 'contract mismatch'
Rename-Item -LiteralPath (Join-Path $driver 'ProxyBridgeDrv.inf') -NewName 'retained.inf'
Refuse 'missing-inf' @{} 'Missing build artifact'
Rename-Item -LiteralPath (Join-Path $driver 'retained.inf') -NewName 'ProxyBridgeDrv.inf'
$caught=$false
try { & $prepare @params -Destination $dest | Out-Null } catch { $caught=$_.Exception.Message -match 'Destination must be new' }
if (!$caught) { throw 'Existing output accepted.' }
# Ensure the original build-tree interface used for package75 still works.
$tree=Join-Path $Results 'build-tree'
$map=@{
 'gui\ProxyBridge.exe'='ProxyBridge.exe'; 'cli\ProxyBridge_CLI.exe'='ProxyBridge_CLI.exe';
 'core\ProxyBridgeCore.dll'='ProxyBridgeCore.dll'; 'helper\bin\ProxyBridgeDriverSetup.exe'='ProxyBridgeDriverSetup.exe';
 'launcher\bin\ProxyBridgeLauncher.exe'='ProxyBridgeLauncher.exe'
}
foreach ($key in $map.Keys) {
    $path=Join-Path $tree $key
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $app $map[$key]) -Destination $path
}
$treeDriver=Join-Path $tree 'driver\bin\ProxyBridgeDrv'
New-Item -ItemType Directory -Path $treeDriver -Force | Out-Null
Get-ChildItem -LiteralPath $driver -File | Copy-Item -Destination $treeDriver
$legacy=& $prepare -BuildRoot $tree -Destination (Join-Path $Results 'tree-prepared') -Protocol 4 -DriverVersion 65537 -AppVersion 1.0.0.0
if ($legacy.ManifestHash -ne $result.ManifestHash) { throw 'Layouts produced different payloads.' }
Write-Host 'PASS: exact copies, pinned driver hashes, contract/missing-file/output refusal, legacy layout parity.'
