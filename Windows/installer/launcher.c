#include "install-store.h"
#include "install-selection.h"
#include "install-payload.h"
#include "launch-command.h"
#include <stdio.h>
#include <wchar.h>

static DWORD launch_selected(int argc, WCHAR **argv, BOOL cli)
{
    HKEY key;
    DWORD error = pb_install_store_open(FALSE, &key);
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    RegCloseKey(key);
    PB_APP_SELECTION selection = {0};
    if (error == ERROR_SUCCESS) error = pb_select_application(&record, &selection);
    if (error != ERROR_SUCCESS) return error;
    PB_VERIFIED_PAYLOAD payload;
    error = pb_payload_open(selection.directory, selection.manifestHash,
                            selection.protocol, selection.driverVersion, &payload);
    if (error != ERROR_SUCCESS) return error;
    WCHAR executable[MAX_PATH];
    if (swprintf_s(executable, MAX_PATH, L"%s\\%s", selection.directory,
                   cli ? L"ProxyBridge_CLI.exe" : L"ProxyBridge.exe") < 0) {
        pb_payload_close(&payload); return ERROR_FILENAME_EXCED_RANGE;
    }
    int first = cli ? 2 : 1;
    int count = argc - first + 1;
    const WCHAR **arguments = HeapAlloc(GetProcessHeap(), 0, (size_t)count * sizeof(*arguments));
    if (!arguments) { pb_payload_close(&payload); return ERROR_NOT_ENOUGH_MEMORY; }
    arguments[0] = executable;
    for (int i = first; i < argc; ++i) arguments[i - first + 1] = argv[i];
    WCHAR *command = NULL;
    error = pb_launch_command(count, arguments, &command);
    HeapFree(GetProcessHeap(), 0, arguments);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    HANDLE standard[3] = {NULL, NULL, NULL};
    SIZE_T attributeBytes = 0;
    if (error == ERROR_SUCCESS && cli) {
        const DWORD identifiers[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
        // Preserve inherited redirection before AttachConsole may initialize
        // console defaults. Only the duplicated standard handles reach child.
        for (unsigned i = 0; i < 3; ++i) {
            HANDLE source = GetStdHandle(identifiers[i]);
            if (source && source != INVALID_HANDLE_VALUE)
                DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &standard[i], 0, TRUE, DUPLICATE_SAME_ACCESS);
        }
        AttachConsole(ATTACH_PARENT_PROCESS);
        BOOL all = TRUE;
        BOOL someRedirected = standard[0] || standard[1] || standard[2];
        for (unsigned i = 0; i < 3; ++i) {
            if (standard[i]) continue;
            HANDLE source = GetStdHandle(identifiers[i]);
            BOOL temporary = FALSE;
            if ((!source || source == INVALID_HANDLE_VALUE) && someRedirected) {
                source = CreateFileW(L"NUL", i == 0 ? GENERIC_READ : GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                temporary = source != INVALID_HANDLE_VALUE;
                if (!temporary) { error = GetLastError(); all = FALSE; break; }
            }
            if (!source || source == INVALID_HANDLE_VALUE ||
                !DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &standard[i], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
                if (someRedirected) error = GetLastError();
                if (temporary) CloseHandle(source);
                all = FALSE; break;
            }
            if (temporary) CloseHandle(source);
        }
        if (all) {
            InitializeProcThreadAttributeList(NULL, 1, 0, &attributeBytes);
            startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attributeBytes);
            if (!startup.lpAttributeList) error = ERROR_NOT_ENOUGH_MEMORY;
            else if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeBytes)) {
                error = GetLastError(); HeapFree(GetProcessHeap(), 0, startup.lpAttributeList); startup.lpAttributeList = NULL;
            } else if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                  standard, sizeof(standard), NULL, NULL)) error = GetLastError();
            if (error == ERROR_SUCCESS) {
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = standard[0];
                startup.StartupInfo.hStdOutput = standard[1];
                startup.StartupInfo.hStdError = standard[2];
            }
        }
    }
    PROCESS_INFORMATION process = {0};
    if (error == ERROR_SUCCESS && !CreateProcessW(executable, command, NULL, NULL,
            startup.lpAttributeList != NULL, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startup.StartupInfo, &process))
        error = GetLastError();
    if (startup.lpAttributeList) {
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    }
    for (unsigned i = 0; i < 3; ++i) if (standard[i]) CloseHandle(standard[i]);
    if (command) HeapFree(GetProcessHeap(), 0, command);
    // Core independently takes the update guard and rechecks active selection.
    // An update racing launcher validation cannot activate a stale Core.
    pb_payload_close(&payload);
    if (error == ERROR_SUCCESS) {
        CloseHandle(process.hThread);
        if (cli) {
            if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0) error = GetLastError();
            else if (!GetExitCodeProcess(process.hProcess, &error)) error = GetLastError();
        }
        CloseHandle(process.hProcess);
    }
    return error;
}

int wmain(int argc, WCHAR **argv)
{
    BOOL cli = argc > 1 && !wcscmp(argv[1], L"--cli");
    DWORD error = launch_selected(argc, argv, cli);
    if (error && !cli) {
        WCHAR message[240];
        swprintf_s(message, ARRAYSIZE(message), L"ProxyBridge could not start (error %lu).\nComplete or recover the installation and try again.", error);
        MessageBoxW(NULL, message, L"ProxyBridge", MB_OK | MB_ICONERROR);
    }
    return (int)error;
}
