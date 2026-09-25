param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('msvc', 'gcc', 'auto')]
    [string]$Compiler = 'auto',

    [Parameter(Mandatory=$false)]
    [switch]$NoSign,
    [switch]$UserModeOnly,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'output'),
    [ValidatePattern('^v[0-9]+$')][string]$PlatformToolset = 'v143',
    [ValidatePattern('^10\.0\.[0-9]+\.0$')][string]$WindowsSdkVersion = '10.0.26100.0'
)

$ErrorActionPreference = 'Stop'
if (!$NoSign) { throw 'Compilation requires -NoSign. Use installer/build-signed-package.ps1 for explicit verified signed packaging; release remains gated.' }
if ($Compiler -eq 'gcc') { throw 'The full Windows application requires MSVC.' }
if (![Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell.' }
# Build a private source snapshot: preserve existing outputs, running apps and source intermediates.
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory must be new.' }
foreach ($path in @($output,$PSScriptRoot)) {
    if ($path -match '[%&|<>^!"\r\n]') { throw 'Unsupported command-shell character in build path.' }
}
foreach ($folder in @('src','gui','cli','shared','installer','driver')) {
    $sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $folder))
    if ($output.Equals($sourceRoot,[StringComparison]::OrdinalIgnoreCase) -or
        $output.StartsWith($sourceRoot + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputDirectory must be outside source subdirectories.'
    }
}
New-Item -ItemType Directory -Path $output | Out-Null
$work = Join-Path $output 'intermediate'
New-Item -ItemType Directory -Path $work | Out-Null
foreach ($folder in @('src','gui','cli','shared','installer','driver')) {
    $source = Join-Path $PSScriptRoot $folder
    $dest = Join-Path $work $folder
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
        if ($file.Extension -notin @('.c','.cpp','.h','.inc','.rc','.ico','.manifest','.vcxproj','.inf')) { continue }
        $target = Join-Path $dest $file.FullName.Substring($source.Length + 1)
        New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}
Push-Location -LiteralPath $work
try {
$SourcePath = "src"
# WFP driver is compiled unsigned unless -UserModeOnly is specified.
$DriverSys  = "driver\x64\Release\ProxyBridgeDrv.sys"
$DriverProj = "driver\ProxyBridgeDrv.vcxproj"
# Core split across subsystem subfolders (see src\core\pb_internal.h). Paths are relative to $SourcePath.
$SourceFile = "core\ProxyBridge.c net\pb_util.c net\pb_process.c rules\pb_rules.c rules\pb_match.c rules\pb_ipmatch.c proxy\pb_proxy.c net\pb_dns.c proxy\pb_socks5.c proxy\pb_http.c relay\pb_conntrack.c relay\pb_relay_tcp.c relay\pb_relay_udp.c driver\pb_driver.c driver\ProxyBridgeDrv_user.c"
$SourceFile += " ..\installer\install-journal.c ..\installer\install-store.c ..\installer\install-selection.c"
$SourceFiles = ($SourceFile.Split(' ') | ForEach-Object { "$SourcePath\$_" }) -join ' '
$OutputDLL = "ProxyBridgeCore.dll"
$OutputDir = $output

$SignTool = "signtool.exe"
$CertThumbprint = ""
$TimestampServer = "http://timestamp.digicert.com"

$Arch = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
Write-Host "Architecture: $Arch" -ForegroundColor Cyan

function Compile-MSVC {
    Write-Host "`nCompiling DLL with MSVC..." -ForegroundColor Green

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path $vsWhere)) {
        Write-Host "Visual Studio not found" -ForegroundColor Yellow
        return $false
    }

    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) {
        Write-Host "Visual Studio C++ tools not found" -ForegroundColor Yellow
        return $false
    }

    $vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsPath)) {
        Write-Host "vcvarsall.bat not found" -ForegroundColor Yellow
        return $false
    }

    Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Cyan
    $script:foundVcvarsPath = $vcvarsPath
    $script:foundArch = $Arch

    $clArgs = "/nologo /utf-8 /O2 /MT /GL /Gy /W4 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996 " +
              "/D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /DPROXYBRIDGE_EXPORTS /DNDEBUG " +
              "/arch:SSE2 /fp:fast /GS /guard:cf /Qpar " +
              "/I`"$SourcePath\core`" /I`"$SourcePath\driver`" " +
              "$SourceFiles " +
              "/LD " +
              "/link /LTCG /OPT:REF /OPT:ICF /RELEASE /DYNAMICBASE /NXCOMPAT " +
              "ws2_32.lib iphlpapi.lib advapi32.lib fwpuclnt.lib setupapi.lib " +
              "/OUT:$OutputDLL"

    $cmd = "`"$vcvarsPath`" x64 $WindowsSdkVersion >nul && cl.exe $clArgs"

    Write-Host "Command: cl.exe $clArgs" -ForegroundColor Gray

    $result = cmd /d /c $cmd 2>&1
    $exitCode = $LASTEXITCODE

    Write-Host $result

    return $exitCode -eq 0
}

# Build the WFP kernel driver via MSBuild + the WDK. Independent of the core compiler above.
function Build-Driver {
    Write-Host "`nBuilding WFP driver (ProxyBridgeDrv.sys)..." -ForegroundColor Green
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $msb = $null
    if (Test-Path $vsWhere) {
        $msb = & $vsWhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
    }
    if (-not $msb) {
        $msb = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $msb) { Write-Host "  MSBuild not found - install VS + WDK. Skipping driver build." -ForegroundColor Yellow; return $false }

    $out = & $msb $DriverProj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:SignMode=Off "/p:WindowsTargetPlatformVersion=$WindowsSdkVersion" /v:minimal /nologo 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $DriverSys)) {
        Write-Host "  Driver built: $DriverSys" -ForegroundColor Gray
        return $true
    }
    Write-Host "  Driver build FAILED (WDK installed?). No fresh driver will be accepted." -ForegroundColor Yellow
    Write-Host $out
    return $false
}

if (!$UserModeOnly -and !(Build-Driver)) { throw 'Driver build failed; stale artifacts are not accepted.' }
$success = Compile-MSVC

if ($success) {
    Write-Host "`nCompilation SUCCESSFUL!" -ForegroundColor Green

    Write-Host "`nCleaning up intermediate files..." -ForegroundColor Yellow
    $intermediateFiles = @("*.obj", "*.exp", "*.lib", "ProxyBridge.obj")
    foreach ($pattern in $intermediateFiles) {
        Get-ChildItem -Path . -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item $_.FullName -Force
            Write-Host "  Removed: $($_.Name)" -ForegroundColor Gray
        }
    }

    Write-Host "`nMoving files to output directory..." -ForegroundColor Green
    Move-Item $OutputDLL -Destination $OutputDir -Force
    Write-Host "  Moved: $OutputDLL -> $OutputDir\" -ForegroundColor Gray

    if (!$UserModeOnly -and (Test-Path $DriverSys)) {
        Copy-Item $DriverSys -Destination $OutputDir -Force
        Write-Host "  Copied: ProxyBridgeDrv.sys (WFP driver)" -ForegroundColor Gray

    } else {
        Write-Host "User-mode-only build: driver explicitly omitted."
    }

    # ── C GUI (MSVC) ─────────────────────────────────────────────────────────
    # Single self-contained ProxyBridge.exe (~0.5 MB, static CRT) that loads
    # ProxyBridgeCore.dll from its own folder. No extra runtime or DLLs.
    Write-Host "`nBuilding C GUI (MSVC)..." -ForegroundColor Green
    if ($script:foundVcvarsPath -and (Test-Path $script:foundVcvarsPath)) {
        # Production build. Compiler: size-optimized static-CRT release with the security
        # hardening set - /GS (stack cookies), /guard:cf (Control Flow Guard), /sdl (extra
        # security diagnostics), /GL + /Gy for whole-program opt & COMDAT folding.
        # Linker: /DYNAMICBASE + /HIGHENTROPYVA (64-bit ASLR), /NXCOMPAT (DEP),
        # /guard:cf (CFG), /CETCOMPAT (shadow-stack), /LTCG, dead-code strip.
        $guiClArgs = "/nologo /utf-8 /O1 /Os /MT /GL /Gy /GS /guard:cf /sdl /W4 " +
                     "/DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE " +
                     "main.c profile\profile.c app.res " +
                     "/Fe:ProxyBridge.exe " +
                     "/link /LTCG /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /RELEASE " +
                     "/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /CETCOMPAT " +
                     "user32.lib gdi32.lib comctl32.lib shell32.lib comdlg32.lib winhttp.lib"

        # Sources live in subfolders. rc runs from res\ so app.rc's relative paths
        # (resource.h, app.manifest, logo.ico) resolve; it writes app.res back to gui\.
        Push-Location "gui"
        $guiCmd = "`"$script:foundVcvarsPath`" x64 $WindowsSdkVersion >nul && " +
                  "pushd res && rc /nologo /fo ..\app.res app.rc && popd && cl.exe $guiClArgs"
        $guiOut  = cmd /d /c $guiCmd 2>&1
        $guiExit = $LASTEXITCODE
        Pop-Location

        if ($guiExit -eq 0 -and (Test-Path "gui\ProxyBridge.exe")) {
            Move-Item "gui\ProxyBridge.exe" -Destination $OutputDir -Force
            Write-Host "  C GUI built: ProxyBridge.exe" -ForegroundColor Gray
            Remove-Item "gui\*.obj","gui\app.res" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  C GUI build failed!" -ForegroundColor Red
            throw "GUI build failed: $guiOut"
        }
    } else {
        throw 'MSVC is required for all components.'
    }

    # ── Build CLI ────────────────────────────────────────────────────────────
    Write-Host "`nBuilding CLI..." -ForegroundColor Green
    if ($script:foundVcvarsPath -and (Test-Path $script:foundVcvarsPath)) {
        $cliArgs = "/nologo /utf-8 /O2 /MT /GL /Gy /W4 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996 " +
                   "/D_WINSOCK_DEPRECATED_NO_WARNINGS /D_WIN32_WINNT=0x0601 /DNDEBUG " +
                   "/arch:SSE2 /fp:fast /GS /guard:cf /Qpar " +
                   "cli\main.c " +
                   "/link /LTCG /OPT:REF /OPT:ICF /RELEASE /DYNAMICBASE /NXCOMPAT /SUBSYSTEM:CONSOLE " +
                   "winhttp.lib shell32.lib advapi32.lib " +
                   "/OUT:ProxyBridge_CLI.exe"

        $cliCmd = "`"$script:foundVcvarsPath`" x64 $WindowsSdkVersion >nul && cl.exe $cliArgs"
        Write-Host "Command: cl.exe $cliArgs" -ForegroundColor Gray

        $cliOut = cmd /d /c $cliCmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Move-Item "ProxyBridge_CLI.exe" -Destination $OutputDir -Force
            Write-Host "  CLI built: ProxyBridge_CLI.exe" -ForegroundColor Gray
            Remove-Item "*.obj" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  CLI build failed!" -ForegroundColor Red
            throw "CLI build failed: $cliOut"
        }
    } else {
        throw 'MSVC is required for all components.'
    }

    Write-Host "`nUser components compiled; building helper and launcher..." -ForegroundColor Cyan
    Write-Host "Contents:" -ForegroundColor Yellow
    Get-ChildItem $OutputDir | ForEach-Object {
        $size = [math]::Round($_.Length/1MB, 2)
        Write-Host "  - $($_.Name) ($size MB)" -ForegroundColor Gray
    }

    $msb = Join-Path (Split-Path (Split-Path (Split-Path (Split-Path $script:foundVcvarsPath)))) 'MSBuild\Current\Bin\MSBuild.exe'
    foreach ($component in @(
        @{Project='driver-helper'; File='ProxyBridgeDriverSetup.exe'},
        @{Project='launcher'; File='ProxyBridgeLauncher.exe'}
    )) {
        $name = $component.Project
        & $msb "installer\$name.vcxproj" /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
            "/p:PlatformToolset=$PlatformToolset" "/p:WindowsTargetPlatformVersion=$WindowsSdkVersion" `
            "/p:OutDir=$output\" "/p:IntDir=$work\$name-obj\" /v:minimal /nologo
        if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)." }
        if (!(Test-Path -LiteralPath (Join-Path $output $component.File))) { throw "$name output missing." }
    }
    $required = @('ProxyBridgeCore.dll','ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeDriverSetup.exe','ProxyBridgeLauncher.exe')
    if (!$UserModeOnly) { $required += 'ProxyBridgeDrv.sys' }
    $files = @($required | ForEach-Object {
        $file = Get-Item -LiteralPath (Join-Path $output $_)
        [pscustomobject]@{Path=$_; Bytes=$file.Length; SHA256=(Get-FileHash -LiteralPath $file.FullName).Hash}
    })
    [pscustomobject]@{UserModeOnly=[bool]$UserModeOnly; ReleaseReady=$false; Files=$files} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $output 'build-result.json') -Encoding utf8
    Write-Host 'Unsigned compilation complete. Signed packaging is a separate explicit step.'

} else {
    Write-Host "`nCompilation FAILED!" -ForegroundColor Red
    Write-Host "MSVC compilation failed; inspect compiler output above." -ForegroundColor Yellow
    throw 'Core compilation failed.'
}

} finally { Pop-Location }
