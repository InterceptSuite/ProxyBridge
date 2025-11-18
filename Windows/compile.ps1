param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('msvc', 'gcc', 'auto')]
    [string]$Compiler = 'auto',

    [Parameter(Mandatory=$false)]
    [switch]$NoSign
)

$WinDivertPath = "C:\WinDivert-2.2.2-A"
$SourcePath = "src"
$SourceFile = "ProxyBridge.c"
$OutputDLL = "ProxyBridgeCore.dll"
$OutputDir = "output"

$SignTool = "signtool.exe"
$CertThumbprint = ""
$TimestampServer = "http://timestamp.digicert.com"

$Arch = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
Write-Host "Architecture: $Arch" -ForegroundColor Cyan

if (Test-Path $OutputDir) {
    Write-Host "Removing existing output directory..." -ForegroundColor Yellow
    Remove-Item $OutputDir -Recurse -Force
}
Write-Host "Creating output directory: $OutputDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if (-not (Test-Path $WinDivertPath)) {
    Write-Host "ERROR: WinDivert not found at: $WinDivertPath" -ForegroundColor Red
    Write-Host "Please update the path in this script or install WinDivert" -ForegroundColor Yellow
    exit 1
}

function Compile-MSVC {
    Write-Host "`nCompiling DLL with MSVC..." -ForegroundColor Green

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) {
            $vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
            if (Test-Path $vcvarsPath) {
                Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Cyan
            }
        }
    }

    $cmd = "cl.exe /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DPROXYBRIDGE_EXPORTS " +
           "/I`"$WinDivertPath\include`" " +
           "$SourcePath\$SourceFile " +
           "/LD " +
           "/link /LIBPATH:`"$WinDivertPath\$Arch`" " +
           "WinDivert.lib ws2_32.lib iphlpapi.lib " +
           "/OUT:$OutputDLL"

    Write-Host "Command: $cmd" -ForegroundColor Gray

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

    $cmd = "gcc -shared -O2 -Wall -D_WIN32_WINNT=0x0601 -DPROXYBRIDGE_EXPORTS " +
           "-I`"$WinDivertPath\include`" " +
           "$SourcePath\$SourceFile " +
           "-L`"$WinDivertPath\$Arch`" " +
           "-lWinDivert -lws2_32 -liphlpapi " +
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

    if ($fileName -like "WinDivert*") {
        Write-Host "  Skipped: $fileName (WinDivert is already EV signed)" -ForegroundColor Yellow
        return $true
    }

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

    Write-Host "`nMoving files to output directory..." -ForegroundColor Green
    Move-Item $OutputDLL -Destination $OutputDir -Force
    Write-Host "  Moved: $OutputDLL -> $OutputDir\" -ForegroundColor Gray

    $files = @(
        "$WinDivertPath\$Arch\WinDivert.dll",
        "$WinDivertPath\$Arch\WinDivert64.sys",
        "$WinDivertPath\$Arch\WinDivert32.sys"
    )
    foreach ($file in $files) {
        if (Test-Path $file) {
            Copy-Item $file -Destination $OutputDir -Force
            Write-Host "  Copied: $(Split-Path $file -Leaf)" -ForegroundColor Gray
        }
    }

    Write-Host "`nPublishing GUI..." -ForegroundColor Green
    $publishResult = dotnet publish gui/ProxyBridge.GUI.csproj -c Release -r win-x64 --self-contained -o gui/bin/Release/net9.0-windows/win-x64/publish 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  GUI published successfully" -ForegroundColor Gray

        Write-Host "`nCopying GUI files to output..." -ForegroundColor Green
        $guiPublishPath = "gui\bin\Release\net9.0-windows\win-x64\publish"

        Copy-Item "$guiPublishPath\ProxyBridge.exe" -Destination $OutputDir -Force
        Write-Host "  Copied: ProxyBridge.exe" -ForegroundColor Gray

        Get-ChildItem "$guiPublishPath\*.dll" | ForEach-Object {
            Copy-Item $_.FullName -Destination $OutputDir -Force
            Write-Host "  Copied: $($_.Name)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  GUI publish failed!" -ForegroundColor Red
        Write-Host $publishResult
    }

    Write-Host "`nPublishing CLI..." -ForegroundColor Green
    $publishResult = dotnet publish cli/ProxyBridge.CLI.csproj -c Release -r win-x64 --self-contained -o cli/bin/Release/net9.0-windows/win-x64/publish 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  CLI published successfully" -ForegroundColor Gray

        Write-Host "`nCopying CLI files to output..." -ForegroundColor Green
        $cliPublishPath = "cli\bin\Release\net9.0-windows\win-x64\publish"

        Copy-Item "$cliPublishPath\ProxyBridge_CLI.exe" -Destination $OutputDir -Force
        Write-Host "  Copied: ProxyBridge_CLI.exe" -ForegroundColor Gray
    } else {
        Write-Host "  CLI publish failed!" -ForegroundColor Red
        Write-Host $publishResult
    }

    if (-not $NoSign) {
        Write-Host "`nSigning binaries..." -ForegroundColor Green
        $filesToSign = Get-ChildItem $OutputDir -Include *.exe,*.dll -Recurse
        $signedCount = 0
        $skippedCount = 0

        foreach ($file in $filesToSign) {
            if ($file.Name -like "WinDivert*") {
                Write-Host "  Skipped: $($file.Name) (WinDivert is already EV signed)" -ForegroundColor Yellow
                $skippedCount++
            } else {
                if (Sign-Binary -FilePath $file.FullName) {
                    $signedCount++
                }
            }
        }

        Write-Host "`nSigning Summary:" -ForegroundColor Cyan
        Write-Host "  Signed: $signedCount files" -ForegroundColor Green
        Write-Host "  Skipped: $skippedCount files (WinDivert)" -ForegroundColor Yellow
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
            $installerName = "ProxyBridge-Setup-3.0.0.exe"
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
