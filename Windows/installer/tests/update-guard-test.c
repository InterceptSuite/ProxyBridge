#include "../../shared/update-guard.h"
#include <stdio.h>

// Run locking tests without elevation in a per-process Local namespace. Only
// this test grants the object owner access; production remains SYSTEM/admin.
#define pb_update_guard_acquire_named(name, guard) \
    pb_update_guard_acquire_with_security(name, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)", guard)

static DWORD WINAPI release_on_worker(void *context)
{
    pb_update_guard_release((HANDLE *)context);
    return 0;
}
int wmain(int argc, WCHAR **argv)
{
    if (argc == 2) {
        HANDLE held;
        DWORD error = pb_update_guard_acquire_named(argv[1], &held);
        // Deliberately omit release: process exit must not leave a permanent lock.
        return (int)error;
    }
    WCHAR name[100];
    swprintf_s(name, ARRAYSIZE(name), L"Local\\ProxyBridge.UpdateGuard.Test.%lu", GetCurrentProcessId());
    HANDLE first = NULL, second = NULL;
    DWORD error = pb_update_guard_acquire_named(name, &first);
    if (error) { printf("First acquire error %lu\n", error); return 1; }
    error = pb_update_guard_acquire_named(name, &second);
    if (error != ERROR_BUSY || second) { printf("Contention error %lu\n", error); return 1; }
    HANDLE worker = CreateThread(NULL, 0, release_on_worker, &first, 0, NULL);
    if (!worker) return 1;
    WaitForSingleObject(worker, INFINITE); CloseHandle(worker);
    if (first || pb_update_guard_acquire_named(name, &second)) return 1;
    pb_update_guard_release(&second);
    WCHAR executable[MAX_PATH], command[2 * MAX_PATH];
    if (!GetModuleFileNameW(NULL, executable, MAX_PATH)) return 1;
    swprintf_s(command, ARRAYSIZE(command), L"\"%s\" %s", executable, name);
    STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) return 1;
    DWORD waited = WaitForSingleObject(process.hProcess, 10000), code = 1;
    if (waited == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    if (code || pb_update_guard_acquire_named(name, &first)) return 1;
    pb_update_guard_release(&first);
    puts("Runtime/update gate contention, cross-thread release and process-exit checks passed.");
    return 0;
}
