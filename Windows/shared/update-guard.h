#pragma once
#include <windows.h>
#include <sddl.h>

// A nonblocking, process-lifetime gate. A semaphore permits Stop on a different
// thread from Start. Contenders close their handle immediately: no waiter keeps
// the object alive after an owning process crashes. A racing contender may get
// ERROR_BUSY once; a later retry creates a fresh object after the last close.
static __inline DWORD pb_update_guard_acquire_with_security(const WCHAR *name, const WCHAR *security, HANDLE *guard)
{
    if (!guard) return ERROR_INVALID_PARAMETER;
    *guard = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security, SDDL_REVISION_1, &descriptor, NULL))
        return GetLastError();
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
    HANDLE handle = CreateSemaphoreExW(&attributes, 1, 1, name, 0, SYNCHRONIZE | SEMAPHORE_MODIFY_STATE);
    DWORD error = handle ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (!handle) return error;
    DWORD wait = WaitForSingleObject(handle, 0);
    if (wait != WAIT_OBJECT_0) {
        error = wait == WAIT_FAILED ? GetLastError() : ERROR_BUSY;
        CloseHandle(handle);
        return error;
    }
    *guard = handle;
    return ERROR_SUCCESS;
}

static __inline DWORD pb_update_guard_acquire(HANDLE *guard)
{
    return pb_update_guard_acquire_with_security(L"Global\\InterceptSuite.ProxyBridge.RuntimeUpdate",
                                                 L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", guard);
}

static __inline void pb_update_guard_release(HANDLE *guard)
{
    if (!guard || !*guard) return;
    ReleaseSemaphore(*guard, 1, NULL);
    CloseHandle(*guard);
    *guard = NULL;
}
