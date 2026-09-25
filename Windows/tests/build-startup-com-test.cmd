@echo off
setlocal
if "%~1"=="" exit /b 2
if not exist "%~1\" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~1"
cl.exe /nologo /utf-8 /O1 /MT /W4 /WX /EHsc /GR- "%~dp0..\installer\tests\startup-com-definition-test.cpp" "%~dp0..\installer\startup-dispatch.c" "%~dp0..\installer\startup-identity.c" /Fe:startup-com-definition-test.exe
set "test_result=%errorlevel%"
popd
exit /b %test_result%
