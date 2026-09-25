@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX "%~dp0..\installer\tests\install-owned-test.c" "%~dp0..\installer\install-journal.c" /Fe:install-owned-test.exe /link advapi32.lib ole32.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
