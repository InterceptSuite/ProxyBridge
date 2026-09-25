@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX /DTEST_VERSION=41 "%~dp0..\installer\tests\launcher-version-child.c" /Fe:version-a.exe
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX /DTEST_VERSION=42 "%~dp0..\installer\tests\launcher-version-child.c" /Fe:version-b.exe
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%~dp0..\installer\tests\launcher-update-test.c" "%~dp0..\installer\install-journal.c" "%~dp0..\installer\install-selection.c" "%~dp0..\installer\install-payload.c" "%~dp0..\installer\launch-command.c" /Fe:launcher-update-test.exe /link advapi32.lib bcrypt.lib user32.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
