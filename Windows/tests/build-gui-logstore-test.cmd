@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O2 /MT /W4 "%~dp0gui-logstore-test.c" /link /OUT:gui-logstore-test.exe user32.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
