// ui/startup.h - single-instance guard + "Run at Startup" logon task (schtasks).
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

// Run at Startup: HKCU\...\Run value. Per-user, so it needs no elevation (the engine lives in
// the ProxyBridgeSvc service). Older versions used an elevated "ProxyBridge" logon task; it is
// removed here when the setting is toggled (and by the uninstaller).
#define PB_RUN_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define PB_RUN_VALUE L"ProxyBridge"

// Runs schtasks.exe hidden and returns its exit code (0 = success / task exists).
static DWORD RunSchtasks(const wchar_t* args)
{
    wchar_t cmd[1024];
    _snwprintf_s(cmd, 1024, _TRUNCATE, L"schtasks.exe %s", args); cmd[1023] = 0;
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return (DWORD)-1;
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = (DWORD)-1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return code;
}
static BOOL StartupIsEnabled(void)
{
    HKEY k; BOOL on = FALSE;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, PB_RUN_KEY, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        on = RegQueryValueExW(k, PB_RUN_VALUE, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
        RegCloseKey(k);
    }
    return on;
}
static void StartupSet(BOOL enable)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, PB_RUN_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
    if (enable)
    {
        wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
        wchar_t cmd[MAX_PATH + 32];
        _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE, L"\"%s\" --minimized", exe);
        RegSetValueExW(k, PB_RUN_VALUE, 0, REG_SZ, (const BYTE*)cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
    }
    else RegDeleteValueW(k, PB_RUN_VALUE);
    RegCloseKey(k);
    RunSchtasks(L"/Delete /F /TN \"ProxyBridge\"");   // legacy elevated logon task (no-op if absent / not admin)
}

#endif // PB_UI_STARTUP_H
