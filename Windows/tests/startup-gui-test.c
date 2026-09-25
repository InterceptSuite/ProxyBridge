#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
static DWORD waitResult, exitResult, lastError = ERROR_ACCESS_DENIED;
static BOOL createOk = TRUE, exitOk = TRUE;
static unsigned closes, creates;
static WCHAR lastCommand[MAX_PATH+80];
static DWORD WINAPI fake_module(HMODULE module, LPWSTR path, DWORD length) {
    (void)module; wcscpy_s(path, length, L"C:\\space dir\\ProxyBridge.exe"); return (DWORD)wcslen(path);
}
static BOOL WINAPI fake_create(LPCWSTR app, LPWSTR command, LPSECURITY_ATTRIBUTES p, LPSECURITY_ATTRIBUTES t,
    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    (void)p; (void)t; (void)env; (void)cwd; (void)si; ++creates;
    if (wcscmp(app,L"C:\\space dir\\ProxyBridgeDriverSetup.exe") || inherit || flags != CREATE_NO_WINDOW) return FALSE;
    wcscpy_s(lastCommand, ARRAYSIZE(lastCommand), command);
    pi->hProcess = (HANDLE)1; pi->hThread = (HANDLE)2; return createOk;
}
static DWORD WINAPI fake_wait(HANDLE h, DWORD ms) { (void)h; return ms == 15000 ? waitResult : WAIT_FAILED; }
static BOOL WINAPI fake_exit(HANDLE h, LPDWORD code) { (void)h; *code = exitResult; return exitOk; }
static BOOL WINAPI fake_close(HANDLE h) { (void)h; ++closes; return TRUE; }
static DWORD WINAPI fake_error(void) { return lastError; }
#define GetModuleFileNameW fake_module
#define CreateProcessW fake_create
#define WaitForSingleObject fake_wait
#define GetExitCodeProcess fake_exit
#define CloseHandle fake_close
#define GetLastError fake_error
#include "../gui/ui/startup.h"
#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    (void)&AnotherInstanceRunning;
    CHECK(StartupSet(TRUE) == 0 && closes == 2 && creates == 1);
    CHECK(!wcscmp(lastCommand, L"\"C:\\space dir\\ProxyBridgeDriverSetup.exe\" startup-enable"));
    CHECK(StartupSet(FALSE) == 0 && wcsstr(lastCommand, L"startup-disable"));
    CHECK(StartupIsEnabled());
    exitResult = ERROR_NOT_FOUND; CHECK(!StartupIsEnabled());
    BOOL enabled = TRUE; exitResult = ERROR_BUSY;
    CHECK(StartupRead(&enabled) == ERROR_BUSY && enabled);
    waitResult = WAIT_TIMEOUT; CHECK(StartupSet(TRUE) == ERROR_TIMEOUT);
    waitResult = WAIT_FAILED; CHECK(StartupSet(TRUE) == ERROR_ACCESS_DENIED);
    waitResult = WAIT_OBJECT_0; exitOk = FALSE; CHECK(StartupSet(TRUE) == ERROR_ACCESS_DENIED);
    unsigned before = closes; createOk = FALSE;
    CHECK(StartupSet(TRUE) == ERROR_ACCESS_DENIED && closes == before);
    puts("PASS GUI startup helper: explicit quoted path, enable/disable/query, timeout and process errors");
    return 0;
}
