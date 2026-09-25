@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O2 /Gy /MT /W4 /DPROXYBRIDGE_EXPORTS /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%~dp0..\src\core" /I"%~dp0..\src\driver" "%~dp0tcp-iocp-production-test.c" "%~dp0..\src\net\pb_util.c" /link /OPT:REF /INCREMENTAL:NO /OUT:tcp-iocp-production-test.exe ws2_32.lib iphlpapi.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
