param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new test directory.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$compiler = Join-Path (Split-Path $PSScriptRoot) 'compile.ps1'
$child = Join-Path $OutputDirectory 'fail-stage.ps1'
# Test the real orchestration with inert compiler outputs. Native MSBuild is
# deliberately given an unavailable toolset to verify helper failure propagation.
@'
param($Compiler,$Destination,$Stage)
$ErrorActionPreference = 'Stop'
function global:cmd {
    $line = $args -join ' '
    $part = if ($line -match 'core\\ProxyBridge.c') { 'core' } elseif ($line -match 'pushd res') { 'gui' } else { 'cli' }
    if ($part -eq $Stage) { $global:LASTEXITCODE = 23; return 'injected compiler failure' }
    if ($part -eq 'core') { Set-Content ProxyBridgeCore.dll 'inert' }
    if ($part -eq 'gui') { Set-Content ProxyBridge.exe 'inert' }
    if ($part -eq 'cli') { Set-Content ProxyBridge_CLI.exe 'inert' }
    $global:LASTEXITCODE = 0
}
& $Compiler -NoSign -UserModeOnly -PlatformToolset v999 -OutputDirectory $Destination
'@ | Set-Content -LiteralPath $child -Encoding utf8
foreach ($stage in @('core','gui','cli','helper')) {
    $dest = Join-Path $OutputDirectory $stage
    & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $child $compiler $dest $stage *> (Join-Path $OutputDirectory "$stage.log")
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath (Join-Path $dest 'build-result.json'))) {
        throw "Failed build accepted at $stage"
    }
    $log = Get-Content -LiteralPath (Join-Path $OutputDirectory "$stage.log") -Raw
    $marker = switch ($stage) {
        core { 'Compilation FAILED' }; gui { 'GUI build failed' }; cli { 'CLI build failed' }; helper { 'driver-helper failed' }
    }
    if ($log -notmatch $marker) { throw "Did not reach expected failure at $stage" }
    Write-Host "PASS: $stage failure is not accepted"
}
$sentinel = Join-Path $OutputDirectory 'keep.txt'
Set-Content -LiteralPath $sentinel 'preserve'
& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $compiler -NoSign -UserModeOnly -OutputDirectory $OutputDirectory *> (Join-Path $OutputDirectory 'existing.log')
if ($LASTEXITCODE -eq 0 -or (Get-Content -LiteralPath $sentinel) -ne 'preserve') { throw 'Existing output not protected.' }
$blocked = Join-Path $OutputDirectory 'release'
& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $compiler -OutputDirectory $blocked *> (Join-Path $OutputDirectory 'release.log')
if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $blocked)) { throw 'Implicit signing/release accepted.' }
Write-Host 'PASS: existing output preservation and explicit unsigned-build gate'
$global:LASTEXITCODE = 0
