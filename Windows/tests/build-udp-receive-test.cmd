@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl /nologo /utf-8 /O2 /Gy /MT /W4 /I"%~dp0..\src\core" "%~dp0udp-receive-test.c" /Fe:udp-receive-test.exe /link /OPT:REF ws2_32.lib iphlpapi.lib
set "result=%errorlevel%"
popd
exit /b %result%
