@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl /nologo /utf-8 /O1 /MT /W4 /WX "%~dp0profile-switch-test.c" /Fe:profile-switch-test.exe /link user32.lib
set "result=%errorlevel%"
popd
exit /b %result%
