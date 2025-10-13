param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('msvc', 'gcc', 'auto')]
    [string]$Compiler = 'auto'
)

$WinDivertPath = "C:\WinDivert-2.2.2-A"
$SourceFile = "ProxyBridge.c"
$OutputFile = "ProxyBridge.exe"

$Arch = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
Write-Host "Architecture: $Arch" -ForegroundColor Cyan

if (-not (Test-Path $WinDivertPath)) {
    Write-Host "ERROR: WinDivert not found at: $WinDivertPath" -ForegroundColor Red
    Write-Host "Please update the path in this script or install WinDivert" -ForegroundColor Yellow
    exit 1
}

function Compile-MSVC {
    Write-Host "`nCompiling with MSVC..." -ForegroundColor Green

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

    $cmd = "cl.exe /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS " +
           "/I`"$WinDivertPath\include`" " +
           "$SourceFile " +
           "/link /LIBPATH:`"$WinDivertPath\$Arch`" " +
           "WinDivert.lib ws2_32.lib iphlpapi.lib " +
           "/OUT:$OutputFile"

    Write-Host "Command: $cmd" -ForegroundColor Gray

    $result = cmd /c $cmd '2>&1'
    $exitCode = $LASTEXITCODE

    Write-Host $result

    return $exitCode -eq 0
}

function Compile-GCC {
    Write-Host "`nCompiling with GCC..." -ForegroundColor Green

    $gccVersion = cmd /c gcc --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GCC not found in PATH" -ForegroundColor Yellow
        return $false
    }

    Write-Host "GCC found: $($gccVersion[0])" -ForegroundColor Cyan

    $cmd = "gcc -O2 -Wall -D_WIN32_WINNT=0x0601 " +
           "-I`"$WinDivertPath\include`" " +
           "$SourceFile " +
           "-L`"$WinDivertPath\$Arch`" " +
           "-lWinDivert -lws2_32 -liphlpapi " +
           "-o $OutputFile"

    Write-Host "Command: $cmd" -ForegroundColor Gray

    $result = cmd /c $cmd '2>&1'
    $exitCode = $LASTEXITCODE

    Write-Host $result

    return $exitCode -eq 0
}

function Copy-WinDivertFiles {
    Write-Host "`nCopying WinDivert runtime files..." -ForegroundColor Green

    $files = @(
        "$WinDivertPath\$Arch\WinDivert.dll",
        "$WinDivertPath\$Arch\WinDivert64.sys",
        "$WinDivertPath\$Arch\WinDivert32.sys"
    )

    foreach ($file in $files) {
        if (Test-Path $file) {
            Copy-Item $file -Destination . -Force
            Write-Host "  Copied: $(Split-Path $file -Leaf)" -ForegroundColor Gray
        }
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
    Copy-WinDivertFiles
    Write-Host "`nUsage: .\$OutputFile chrome.exe -pid 27876" -ForegroundColor Cyan
    Write-Host "Note: Run as Administrator!" -ForegroundColor Yellow
} else {
    Write-Host "`nCompilation FAILED!" -ForegroundColor Red
    Write-Host "Need: Visual Studio with C++ or MinGW-w64" -ForegroundColor Yellow
    exit 1
}
