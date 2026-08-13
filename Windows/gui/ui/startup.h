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

// Run at Startup (schtasks logon task)
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
    return RunSchtasks(L"/Query /TN \"ProxyBridge\"") == 0;
}
static void StartupSet(BOOL enable)
{
    if (enable)
    {
        wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
        wchar_t args[1200];
        // ONLOGON task launching the exe minimized, highest run level.
        // The short delay lets the shell/tray come up first so the tray icon appears
        _snwprintf_s(args, 1200, _TRUNCATE,
                   L"/Create /F /TN \"ProxyBridge\" /TR \"\\\"%s\\\" --minimized\" /SC ONLOGON /DELAY 0000:15 /RL HIGHEST",
                   exe);
        args[1199] = 0;
        RunSchtasks(args);
    }
    else RunSchtasks(L"/Delete /F /TN \"ProxyBridge\"");
}

#endif // PB_UI_STARTUP_H
