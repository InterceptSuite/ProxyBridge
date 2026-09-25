@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl /nologo /utf-8 /O1 /MT /W4 /DPROXYBRIDGE_EXPORTS /I"%~dp0..\src\core" "%~dp0prepared-profile-test.c" "%~dp0..\src\rules\pb_rules.c" /Fe:prepared-profile-test.exe /link ws2_32.lib iphlpapi.lib
set "result=%errorlevel%"
popd
exit /b %result%
