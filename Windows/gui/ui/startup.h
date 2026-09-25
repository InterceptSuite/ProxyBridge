// ui/startup.h - single-instance guard + native-helper GUI startup settings.
//
// Unity-build include: pulled into main.c (uses only Win32 + APP-independent state).
#ifndef PB_UI_STARTUP_H
#define PB_UI_STARTUP_H

// TRUE if another ProxyBridge GUI or CLI process (not us) is already running. Two instances
// would fight over the WinDivert driver and the local relay ports.
static BOOL AnotherInstanceRunning(void)
{
    DWORD self = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    BOOL found = FALSE;
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (pe.th32ProcessID == self) continue;
            if (_wcsicmp(pe.szExeFile, L"ProxyBridge.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"ProxyBridge_CLI.exe") == 0)
            { found = TRUE; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// Keep scheduler/installation code in the existing native helper. The GUI
// invokes its adjacent helper explicitly; no PATH lookup or shell expansion.
static DWORD StartupCommand(const wchar_t *operation)
{
    wchar_t helper[MAX_PATH], command[MAX_PATH + 80];
    DWORD length = GetModuleFileNameW(NULL, helper, MAX_PATH);
    if (!length) return GetLastError();
    if (length >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    wchar_t *name = wcsrchr(helper, L'\\');
    if (!name) return ERROR_INVALID_NAME;
    if (wcscpy_s(name + 1, MAX_PATH - (size_t)(name + 1 - helper), L"ProxyBridgeDriverSetup.exe"))
        return ERROR_FILENAME_EXCED_RANGE;
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%s\" %s", helper, operation) < 0)
        return ERROR_FILENAME_EXCED_RANGE;
    STARTUPINFOW si = {0}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(helper, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return GetLastError();
    DWORD wait = WaitForSingleObject(pi.hProcess, 15000), result;
    if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(pi.hProcess, &result)) result = GetLastError();
    } else result = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return result;
}
static DWORD StartupRead(BOOL *enabled)
{
    DWORD error = StartupCommand(L"startup-query");
    if (!error || error == ERROR_NOT_FOUND) { *enabled = !error; return 0; }
    return error;
}
static BOOL StartupIsEnabled(void)
{
    BOOL enabled = FALSE;
    StartupRead(&enabled);
    return enabled;
}
static DWORD StartupSet(BOOL enable)
{
    return StartupCommand(enable ? L"startup-enable" : L"startup-disable");
}

#endif // PB_UI_STARTUP_H
