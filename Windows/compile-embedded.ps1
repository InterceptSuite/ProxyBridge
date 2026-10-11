# compile-embedded.ps1 - builds the engine for an application that bundles its own copy
# (for example InterceptSuite), as opposed to the standalone ProxyBridge product.
#
# Output: output\embedded\
#   InterceptSuiteRedirectSvc.exe   LocalSystem service; own service name and pipe names (/DPB_EMBEDDED)
#   ProxyBridgeCore.dll             the engine, unchanged
#   WinDivert.dll, WinDivert64.sys  copied from the WinDivert package
#
# The standalone ProxyBridge (ProxyBridgeSvc, ProxyBridgeCtl/Evt pipes) is untouched, so both can
# be installed on one machine.
param(
    [Parameter(Mandatory=$false)]
    [switch]$NoSign,

    [Parameter(Mandatory=$false)]
    [switch]$SkipCore   # reuse an existing output\ProxyBridgeCore.dll
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$WinDivertPath = "C:\WinDivert-2.2.2-A"
$Arch = "x64"
$OutDir = "output\embedded"

if (-not $SkipCore) {
    Write-Host "Building the engine (compile.ps1)..." -ForegroundColor Cyan
    & "$PSScriptRoot\compile.ps1" -Compiler msvc -NoSign
}
if (-not (Test-Path "output\ProxyBridgeCore.dll")) { throw "output\ProxyBridgeCore.dll is missing - run without -SkipCore" }

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "Visual Studio C++ tools not found" }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"

if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "Building InterceptSuiteRedirectSvc.exe..." -ForegroundColor Cyan
$svcArgs = "/nologo /O2 /GL /Gy /W4 /MT /GS /guard:cf /sdl /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE /DPB_EMBEDDED " +
           "src\service\pb_service.c " +
           "/link /LTCG /OPT:REF /OPT:ICF /RELEASE /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /CETCOMPAT /SUBSYSTEM:CONSOLE " +
           "advapi32.lib /OUT:InterceptSuiteRedirectSvc.exe"
$out = cmd /c "`"$vcvars`" $Arch >nul && cl.exe $svcArgs" '2>&1'
if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "service build failed" }
Move-Item "InterceptSuiteRedirectSvc.exe" $OutDir -Force
Remove-Item "*.obj" -Force -ErrorAction SilentlyContinue

Copy-Item "output\ProxyBridgeCore.dll" $OutDir -Force
Copy-Item "$WinDivertPath\$Arch\WinDivert.dll", "$WinDivertPath\$Arch\WinDivert64.sys" $OutDir -Force

if (-not $NoSign) {
    Write-Host "Signing is done by the caller's release process (signtool); pass -NoSign to silence this." -ForegroundColor Yellow
}
Get-ChildItem $OutDir | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "Done: $OutDir" -ForegroundColor Green
