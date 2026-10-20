# Compiles every Windows C file (compile only, no link) so the SonarQube Build Wrapper can record the compiler
# calls. Same build as the CodeQL Windows job. Run from the repository root:
#   build-wrapper-win-x86-64.exe --out-dir bw-output pwsh -NoProfile -File .github\scripts\sonar-compile-windows.ps1
$ErrorActionPreference = "Stop"

$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$common = "/nologo /c /W4 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /GS /guard:cf"

# every .c file of a folder is listed, so a new source file is picked up without touching this script
function Compile($dir, $extra) {
  $files = (Get-ChildItem $dir -Filter *.c -File | ForEach-Object { Join-Path $dir $_.Name }) -join " "
  if (-not $files) { throw "no C files found in $dir" }
  cmd /c "`"$vcvars`" && cl.exe $common $extra $files"
  if ($LASTEXITCODE -ne 0) { throw "compile failed in $dir" }
}

# Core DLL
Compile "Windows\src" "/DPROXYBRIDGE_EXPORTS /I`"C:\WinDivert-2.2.2-A\include`""
# Engine service (runs as LocalSystem)
Compile "Windows\src\service" "/D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE"
# CLI
Compile "Windows\cli" "/D_WIN32_WINNT=0x0601 /DUNICODE /D_UNICODE"
# Native C GUI: built from its own folder so the subfolder includes resolve
Push-Location Windows\gui
$guiFiles = (Get-ChildItem . -Filter *.c -File -Recurse | ForEach-Object { Resolve-Path -Relative $_.FullName }) -join " "
cmd /c "`"$vcvars`" && cl.exe $common /utf-8 /DUNICODE /D_UNICODE $guiFiles"
if ($LASTEXITCODE -ne 0) { throw "compile failed in Windows\gui" }
Pop-Location
