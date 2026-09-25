@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O2 /MT /W4 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS /DPROXYBRIDGE_EXPORTS /DNDEBUG /I"%~dp0..\src\core" /I"%~dp0..\src\driver" "%~dp0..\tests\core-lifecycle-test.c" "%~dp0..\src\net\pb_util.c" "%~dp0..\src\net\pb_process.c" "%~dp0..\src\rules\pb_rules.c" "%~dp0..\src\rules\pb_match.c" "%~dp0..\src\rules\pb_ipmatch.c" "%~dp0..\src\proxy\pb_proxy.c" "%~dp0..\src\net\pb_dns.c" "%~dp0..\src\proxy\pb_socks5.c" "%~dp0..\src\proxy\pb_http.c" "%~dp0..\src\relay\pb_conntrack.c" "%~dp0..\tests\core-lifecycle-tcp.c" "%~dp0..\tests\core-lifecycle-udp.c"   "%~dp0..\installer\install-journal.c" "%~dp0..\installer\install-store.c" "%~dp0..\installer\install-selection.c" /LD /link /OUT:"core-lifecycle-test.dll" ws2_32.lib iphlpapi.lib advapi32.lib fwpuclnt.lib setupapi.lib
if errorlevel 1 goto done
cl.exe /nologo /W4 /MT "%~dp0..\tests\core-lifecycle-runner.c" /link /OUT:core-lifecycle-runner.exe
:done
set "test_result=%errorlevel%"
popd
exit /b %test_result%
