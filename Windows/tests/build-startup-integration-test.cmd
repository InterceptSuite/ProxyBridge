@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
set "SRC=%~dp0..\installer"
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%~dp0startup-gui-test.c" /Fe:startup-gui-test.exe
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%SRC%\tests\startup-file-security-test.c" "%SRC%\startup-installed.c" "%SRC%\startup-identity.c" "%SRC%\install-stage.c" "%SRC%\install-payload.c" /Fe:startup-file-security-test.exe /link advapi32.lib bcrypt.lib ole32.lib shell32.lib
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%SRC%\tests\bootstrap-read-test.c" "%SRC%\install-payload.c" /Fe:bootstrap-read-test.exe /link advapi32.lib bcrypt.lib ole32.lib shell32.lib
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%SRC%\tests\stage-security-test.c" "%SRC%\install-payload.c" /Fe:stage-security-test.exe /link advapi32.lib bcrypt.lib ole32.lib shell32.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
