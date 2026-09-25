@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
set "SRC=%~dp0..\installer"
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX /EHsc /GR- "%SRC%\tests\install-registration-test.cpp" "%SRC%\startup-installed.c" "%SRC%\startup-task.cpp" "%SRC%\startup-dispatch.c" "%SRC%\startup-identity.c" "%SRC%\install-stage.c" "%SRC%\install-payload.c" /Fe:install-registration-test.exe /link advapi32.lib bcrypt.lib ole32.lib shell32.lib
set "test_result=%errorlevel%"
popd
exit /b %test_result%
