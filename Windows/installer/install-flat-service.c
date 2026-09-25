#include "install-flat-service.h"
#include "install-payload.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>

static DWORD same_bytes(HANDLE a, HANDLE b)
{
    LARGE_INTEGER x, y, zero = {0};
    if (!GetFileSizeEx(a, &x) || !GetFileSizeEx(b, &y)) return GetLastError();
    if (!x.QuadPart || x.QuadPart != y.QuadPart) return ERROR_REVISION_MISMATCH;
    if (!SetFilePointerEx(a, zero, NULL, FILE_BEGIN) || !SetFilePointerEx(b, zero, NULL, FILE_BEGIN)) return GetLastError();
    BYTE left[16384], right[16384];
    for (;;) {
        DWORD n, m;
        if (!ReadFile(a, left, sizeof(left), &n, NULL) || !ReadFile(b, right, sizeof(right), &m, NULL)) return GetLastError();
        if (n != m || memcmp(left, right, n)) return ERROR_REVISION_MISMATCH;
        if (!n) return 0;
    }
}

DWORD pb_flat_service_check(HANDLE expectedDriver)
{
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) return GetLastError();
    SC_HANDLE service = OpenServiceW(manager, L"ProxyBridgeDrv", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    DWORD error = service ? 0 : GetLastError();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) error = 0;
    if (error == ERROR_SERVICE_MARKED_FOR_DELETE) error = ERROR_SUCCESS_REBOOT_REQUIRED;
    if (!service) { CloseServiceHandle(manager); return error; }
    BYTE storage[8192]; DWORD needed = 0;
    QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)storage;
    if (!QueryServiceConfigW(service, config, sizeof(storage), &needed)) error = GetLastError();
    if (!error && (config->dwServiceType != SERVICE_KERNEL_DRIVER || config->dwStartType != SERVICE_DEMAND_START)) error = ERROR_REVISION_MISMATCH;
    WCHAR windows[MAX_PATH], path[MAX_PATH] = {0};
    UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
    if (!error && (!length || length >= MAX_PATH - 60)) error = ERROR_INVALID_NAME;
    if (!error) {
        const WCHAR *binary = config->lpBinaryPathName;
        if (!_wcsnicmp(binary, L"\\SystemRoot\\", 12)) {
            if (swprintf_s(path, MAX_PATH, L"%s\\%s", windows, binary + 12) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        } else if (!_wcsnicmp(binary, L"\\??\\", 4)) {
            if (wcscpy_s(path, MAX_PATH, binary + 4)) error = ERROR_FILENAME_EXCED_RANGE;
        } else if (wcscpy_s(path, MAX_PATH, binary)) error = ERROR_FILENAME_EXCED_RANGE;
        WCHAR driverRoot[MAX_PATH], legacy[MAX_PATH];
        swprintf_s(driverRoot, MAX_PATH, L"%s\\System32\\DriverStore\\FileRepository\\", windows);
        swprintf_s(legacy, MAX_PATH, L"%s\\System32\\drivers\\ProxyBridgeDrv.sys", windows);
        const WCHAR *name = wcsrchr(path, L'\\');
        if (!error && (!name || _wcsicmp(name, L"\\ProxyBridgeDrv.sys") ||
            (_wcsnicmp(path, driverRoot, wcslen(driverRoot)) && _wcsicmp(path, legacy)))) error = ERROR_REVISION_MISMATCH;
    }
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE image = INVALID_HANDLE_VALUE;
    if (!error) {
        wprintf(L"ServiceImage=%s\n", path);
        WCHAR parent[MAX_PATH]; wcscpy_s(parent, MAX_PATH, path); *wcsrchr(parent, L'\\') = 0;
        error = pb_payload_lock_directory(parent, &guard);
        if (!error) {
            image = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (image == INVALID_HANDLE_VALUE) error = GetLastError();
        }
        FILE_ATTRIBUTE_TAG_INFO info = {0};
        if (!error && !GetFileInformationByHandleEx(image, FileAttributeTagInfo, &info, sizeof(info))) error = GetLastError();
        if (!error && (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) error = ERROR_INVALID_NAME;
        if (!error) error = same_bytes(expectedDriver, image);
    }
    if (image != INVALID_HANDLE_VALUE) CloseHandle(image);
    pb_payload_close(&guard); CloseServiceHandle(service); CloseServiceHandle(manager);
    // A retained SCM record may reference a just-removed PnP image. It cannot
    // be adopted without byte proof; require Windows to finish removal first.
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) error = ERROR_SUCCESS_REBOOT_REQUIRED;
    if (!error) wprintf(L"ExistingService=verified matching driver image\n");
    return error;
}

DWORD pb_flat_service_removal_pending(void)
{
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) return GetLastError();
    SC_HANDLE service = OpenServiceW(manager, L"ProxyBridgeDrv", SERVICE_QUERY_STATUS);
    DWORD error = service ? ERROR_SUCCESS_REBOOT_REQUIRED : GetLastError();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) error = ERROR_SUCCESS;
    else if (error == ERROR_SERVICE_MARKED_FOR_DELETE) error = ERROR_SUCCESS_REBOOT_REQUIRED;
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return error;
}
