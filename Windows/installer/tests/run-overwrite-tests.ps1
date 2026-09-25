param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($out) | Out-Null
$fixture = Join-Path $out ('fixture-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$names = @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe',
    'driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')
$hashes = @()
foreach ($version in @('a','b')) {
    $payload = Join-Path $fixture $version
    [IO.Directory]::CreateDirectory((Join-Path $payload 'driver')) | Out-Null
    foreach ($name in $names) {
        $content = if ($version -eq 'a') { 'old payload with a longer tail: ' + $name } else { 'new ' + $name }
        [IO.File]::WriteAllText((Join-Path $payload $name), $content)
    }
    $hashes += (& (Join-Path $sourceRoot 'make-payload-manifest.ps1') -Directory $payload -Protocol 4 -DriverVersion 65537 -AppVersion '4.0.0.0').Hash
}
$recipe = @"
@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
cd /d "$out"
cl /nologo /utf-8 /MT /W4 /WX /Gy /D_WIN32_WINNT=0x0A00 "$PSScriptRoot\install-overwrite-test.c" "$sourceRoot\install-payload.c" "$sourceRoot\install-layout.c" /Fe:install-overwrite-test.exe /link /OPT:REF advapi32.lib ole32.lib shell32.lib bcrypt.lib
if errorlevel 1 exit /b %errorlevel%
install-overwrite-test.exe "$fixture" "$fixture\a" $($hashes[0]) "$fixture\b" $($hashes[1])
exit /b %errorlevel%
"@
$recipePath = Join-Path $out 'verify.cmd'
[IO.File]::WriteAllText($recipePath, $recipe, [Text.Encoding]::ASCII)
& $recipePath
if ($LASTEXITCODE) { throw "Overwrite tests failed: $LASTEXITCODE" }
