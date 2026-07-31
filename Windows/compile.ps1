param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('msvc', 'gcc', 'auto')]
    [string]$Compiler = 'auto',

    [Parameter(Mandatory=$false)]
    [switch]$NoSign
)

$SourcePath = "src"
# WFP kernel driver (driver\ProxyBridgeDrv.vcxproj) - built + test-signed below, packaged in output\.
$DriverSys  = "driver\x64\Release\ProxyBridgeDrv.sys"
$DriverProj = "driver\ProxyBridgeDrv.vcxproj"
# Core split across subsystem subfolders (see src\core\pb_internal.h). Paths are relative to $SourcePath.
$SourceFile = "core\ProxyBridge.c net\pb_util.c net\pb_process.c rules\pb_rules.c rules\pb_match.c rules\pb_ipmatch.c proxy\pb_proxy.c net\pb_dns.c proxy\pb_socks5.c proxy\pb_http.c relay\pb_conntrack.c relay\pb_relay_tcp.c relay\pb_relay_udp.c driver\pb_driver.c driver\ProxyBridgeDrv_user.c"
$SourceFiles = ($SourceFile.Split(' ') | ForEach-Object { "$SourcePath\$_" }) -join ' '
$OutputDLL = "ProxyBridgeCore.dll"
$OutputDir = "output"

$SignTool = "signtool.exe"
$CertThumbprint = ""
$TimestampServer = "http://timestamp.digicert.com"

$Arch = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
Write-Host "Architecture: $Arch" -ForegroundColor Cyan

# A running ProxyBridge locks ProxyBridgeCore.dll, so the build would silently keep the old
# DLL. Close it first so the fresh build actually lands in output\.
foreach ($proc in @('ProxyBridge','ProxyBridge_CLI')) {
    $running = Get-Process $proc -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "Closing running $proc (it locks the DLL)..." -ForegroundColor Yellow
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

if (Test-Path $OutputDir) {
    Write-Host "Removing existing output directory..." -ForegroundColor Yellow
    Remove-Item $OutputDir -Recurse -Force
}
Write-Host "Creating output directory: $OutputDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

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

    $clArgs = "/nologo /O2 /Ot /GL /Gy /W4 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996 " +
              "/D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /DPROXYBRIDGE_EXPORTS /DNDEBUG " +
              "/arch:SSE2 /fp:fast /GS /guard:cf /Qpar " +
              "/I`"$SourcePath\core`" /I`"$SourcePath\driver`" " +
              "$SourceFiles " +
              "/LD " +
              "/link /LTCG /OPT:REF /OPT:ICF /RELEASE /DYNAMICBASE /NXCOMPAT " +
              "ws2_32.lib iphlpapi.lib advapi32.lib " +
              "/OUT:$OutputDLL"

    $cmd = "`"$vcvarsPath`" $Arch >nul && cl.exe $clArgs"

    Write-Host "Command: cl.exe $clArgs" -ForegroundColor Gray

    $result = cmd /c $cmd '2>&1'
    $exitCode = $LASTEXITCODE

    Write-Host $result

    return $exitCode -eq 0
}

function Compile-GCC {
    Write-Host "`nCompiling DLL with GCC..." -ForegroundColor Green

    $gccVersion = cmd /c gcc --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GCC not found in PATH" -ForegroundColor Yellow
        return $false
    }

    Write-Host "GCC found: $($gccVersion[0])" -ForegroundColor Cyan

    $cmd = "gcc -shared -O2 -flto -s -Wall -D_WIN32_WINNT=0x0601 -DPROXYBRIDGE_EXPORTS " +
           "$SourcePath\$SourceFile " +
           "-lws2_32 -liphlpapi -ladvapi32 " +
           "-o $OutputDLL"

    Write-Host "Command: $cmd" -ForegroundColor Gray

    $result = cmd /c $cmd '2>&1'
    $exitCode = $LASTEXITCODE

    Write-Host $result

    return $exitCode -eq 0
}

function Sign-Binary {
    param(
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        Write-Host "  File not found: $FilePath" -ForegroundColor Red
        return $false
    }

    $fileName = Split-Path $FilePath -Leaf

    Write-Host "  Signing: $fileName" -ForegroundColor Cyan

    if ([string]::IsNullOrEmpty($CertThumbprint)) {
        $cmd = "signtool.exe sign /a /fd SHA256 /tr `"$TimestampServer`" /td SHA256 `"$FilePath`""
    } else {
        $cmd = "signtool.exe sign /sha1 $CertThumbprint /fd SHA256 /tr `"$TimestampServer`" /td SHA256 `"$FilePath`""
    }

    $result = cmd /c $cmd '2>&1'
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host "    ✓ Signed successfully" -ForegroundColor Green
        return $true
    } else {
        Write-Host "    ✗ Signing failed: $result" -ForegroundColor Red
        return $false
    }
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

    $out = & $msb $DriverProj /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /v:minimal /nologo 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $DriverSys)) {
        Write-Host "  Driver built: $DriverSys" -ForegroundColor Gray
        return $true
    }
    Write-Host "  Driver build FAILED (WDK installed?). Continuing without a fresh .sys." -ForegroundColor Yellow
    Write-Host $out
    return $false
}

# Test-sign output\ProxyBridgeDrv.sys with a self-signed cert so it can load on a machine where the
# cert is trusted (run temp-sign.ps1 once to establish trust). Signing itself needs no elevation.
function Sign-Driver {
    $drv = Join-Path $OutputDir "ProxyBridgeDrv.sys"
    if (-not (Test-Path $drv)) { return }
    $subject = 'CN=ProxyBridge Test Signing'
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My `
                  -KeyUsage DigitalSignature -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -NotAfter (Get-Date).AddYears(5)
    }
    $st = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
          Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $st) { $st = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
    if (-not $st) { Write-Host "  signtool not found - driver left unsigned" -ForegroundColor Yellow; return }
    & $st sign /fd SHA256 /sha1 $cert.Thumbprint $drv 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Test-signed: ProxyBridgeDrv.sys ($((Get-AuthenticodeSignature $drv).Status))" -ForegroundColor Gray
    } else {
        Write-Host "  Driver signing failed (file locked by a running ProxyBridgeDrv service?)" -ForegroundColor Yellow
    }
}

Build-Driver | Out-Null

$success = $false

if ($Compiler -eq 'auto') {
    Write-Host "Auto-detecting compiler..." -ForegroundColor Cyan

    $success = Compile-MSVC

    if (-not $success) {
        Write-Host "`nMSVC compilation failed, trying GCC..." -ForegroundColor Yellow
        $success = Compile-GCC
    }
} elseif ($Compiler -eq 'msvc') {
    $success = Compile-MSVC
} elseif ($Compiler -eq 'gcc') {
    $success = Compile-GCC
}


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

    if (Test-Path $DriverSys) {
        Copy-Item $DriverSys -Destination $OutputDir -Force
        Write-Host "  Copied: ProxyBridgeDrv.sys (WFP driver)" -ForegroundColor Gray
        Sign-Driver
    } else {
        Write-Host "  WARNING: $DriverSys not found - build the driver first" -ForegroundColor Yellow
    }

    # Test-signing helper + VM test guide so output\ is a self-contained test package.
    foreach ($extra in @("driver\temp-sign\temp-sign.ps1")) {
        if (Test-Path $extra) {
            Copy-Item $extra -Destination $OutputDir -Force
            Write-Host "  Copied: $(Split-Path $extra -Leaf)" -ForegroundColor Gray
        }
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
        $guiCmd = "`"$script:foundVcvarsPath`" $script:foundArch >nul && " +
                  "pushd res && rc /nologo /fo ..\app.res app.rc && popd && cl.exe $guiClArgs"
        $guiOut  = cmd /c $guiCmd '2>&1'
        $guiExit = $LASTEXITCODE
        Pop-Location

        if ($guiExit -eq 0 -and (Test-Path "gui\ProxyBridge.exe")) {
            Move-Item "gui\ProxyBridge.exe" -Destination $OutputDir -Force
            Write-Host "  C GUI built: ProxyBridge.exe" -ForegroundColor Gray
            Remove-Item "gui\*.obj","gui\app.res" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  C GUI build failed!" -ForegroundColor Red
            Write-Host $guiOut
        }
    } else {
        Write-Host "  Skipped: MSVC not found" -ForegroundColor Yellow
    }

    # ── Build CLI ────────────────────────────────────────────────────────────
    Write-Host "`nBuilding CLI..." -ForegroundColor Green
    if ($script:foundVcvarsPath -and (Test-Path $script:foundVcvarsPath)) {
        $cliArgs = "/nologo /O2 /Ot /GL /Gy /W4 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996 " +
                   "/D_WINSOCK_DEPRECATED_NO_WARNINGS /D_WIN32_WINNT=0x0601 /DNDEBUG " +
                   "/arch:SSE2 /fp:fast /GS /guard:cf /Qpar " +
                   "cli\main.c " +
                   "/link /LTCG /OPT:REF /OPT:ICF /RELEASE /DYNAMICBASE /NXCOMPAT /SUBSYSTEM:CONSOLE " +
                   "winhttp.lib shell32.lib advapi32.lib " +
                   "/OUT:ProxyBridge_CLI.exe"

        $cliCmd = "`"$script:foundVcvarsPath`" $script:foundArch >nul && cl.exe $cliArgs"
        Write-Host "Command: cl.exe $cliArgs" -ForegroundColor Gray

        $cliOut = cmd /c $cliCmd '2>&1'
        if ($LASTEXITCODE -eq 0) {
            Move-Item "ProxyBridge_CLI.exe" -Destination $OutputDir -Force
            Write-Host "  CLI built: ProxyBridge_CLI.exe" -ForegroundColor Gray
            Remove-Item "*.obj" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  CLI build failed!" -ForegroundColor Red
            Write-Host $cliOut
        }
    } else {
        Write-Host "  Skipped: MSVC not found" -ForegroundColor Yellow
    }

    if (-not $NoSign) {
        Write-Host "`nSigning binaries..." -ForegroundColor Green
        $filesToSign = Get-ChildItem $OutputDir -Include *.exe,*.dll -Recurse
        $signedCount = 0

        foreach ($file in $filesToSign) {
            if (Sign-Binary -FilePath $file.FullName) {
                $signedCount++
            }
        }

        Write-Host "`nSigning Summary:" -ForegroundColor Cyan
        Write-Host "  Signed: $signedCount files" -ForegroundColor Green
    } else {
        Write-Host "`nSigning skipped (-NoSign flag)" -ForegroundColor Yellow
    }

    Write-Host "`nAll files ready in: $OutputDir\" -ForegroundColor Cyan
    Write-Host "Contents:" -ForegroundColor Yellow
    Get-ChildItem $OutputDir | ForEach-Object {
        $size = [math]::Round($_.Length/1MB, 2)
        Write-Host "  - $($_.Name) ($size MB)" -ForegroundColor Gray
    }

    Write-Host "`nBuilding installer..." -ForegroundColor Green
    $nsisPath = "C:\Program Files (x86)\NSIS\Bin\makensis.exe"
    if (Test-Path $nsisPath) {
        Push-Location installer
        $result = & $nsisPath "ProxyBridge.nsi" 2>&1
        Pop-Location
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Installer created successfully" -ForegroundColor Green
            # Derive installer name from the version defined in the NSI file
            $nsiContent = Get-Content "installer\ProxyBridge.nsi" -Raw -ErrorAction SilentlyContinue
            $installerVersion = if ($nsiContent -match '!define PRODUCT_VERSION "([^"]+)"') { $Matches[1] } else { "0.0.0" }
            $installerName = "ProxyBridge-Setup-$installerVersion.exe"
            if (Test-Path "installer\$installerName") {
                Move-Item "installer\$installerName" -Destination $OutputDir -Force
                Write-Host "  Moved: $installerName -> $OutputDir\" -ForegroundColor Gray

                if (-not $NoSign) {
                    Write-Host "`nSigning installer..." -ForegroundColor Green
                    if (Sign-Binary -FilePath "$OutputDir\$installerName") {
                        $installerSize = [math]::Round((Get-Item "$OutputDir\$installerName").Length/1MB, 2)
                        Write-Host "  Installer ready: $OutputDir\$installerName ($installerSize MB)" -ForegroundColor Cyan
                    }
                } else {
                    $installerSize = [math]::Round((Get-Item "$OutputDir\$installerName").Length/1MB, 2)
                    Write-Host "  Installer ready: $OutputDir\$installerName ($installerSize MB)" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "  Installer build failed!" -ForegroundColor Red
            Write-Host $result
        }
    } else {
        Write-Host "  NSIS not found at: $nsisPath" -ForegroundColor Yellow
        Write-Host "  Skipping installer creation" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nCompilation FAILED!" -ForegroundColor Red
    Write-Host "Need: Visual Studio with C++ or MinGW-w64" -ForegroundColor Yellow
    exit 1
}
