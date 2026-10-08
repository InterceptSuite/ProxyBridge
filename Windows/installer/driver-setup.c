// Setup-only PnP operations. The NSIS wizard extracts this helper to its private
// temporary directory; the application has no installer or polling dependency.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <devpkey.h>
#include <stdio.h>
#include <wchar.h>

static const WCHAR hardwareId[] = L"ROOT\\InterceptSuite_ProxyBridge";
static const WCHAR uninstallKey[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ProxyBridge";

static BOOL IsPublishedInf(const WCHAR *name)
{
    if (wcslen(name) < 8 || _wcsnicmp(name, L"oem", 3)) return FALSE;
    name += 3;
    if (*name < L'0' || *name > L'9') return FALSE;
    while (*name >= L'0' && *name <= L'9') ++name;
    return _wcsicmp(name, L".inf") == 0;
}

static DWORD FindDevice(HDEVINFO set, SP_DEVINFO_DATA *found, BOOL *exists)
{
    *exists = FALSE;
    for (DWORD index = 0; ; ++index) {
        SP_DEVINFO_DATA device = { sizeof(device) };
        if (!SetupDiEnumDeviceInfo(set, index, &device)) {
            DWORD error = GetLastError();
            return error == ERROR_NO_MORE_ITEMS ? ERROR_SUCCESS : error;
        }
        DWORD bytes = 0, type = 0;
        SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID,
                                         &type, NULL, 0, &bytes);
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_DATA) continue;
        if (error != ERROR_INSUFFICIENT_BUFFER) return error;
        WCHAR *ids = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                              (SIZE_T)bytes + 2 * sizeof(WCHAR));
        if (!ids) return ERROR_NOT_ENOUGH_MEMORY;
        BOOL match = FALSE;
        if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID,
                                              &type, (BYTE *)ids, bytes, NULL))
            error = GetLastError();
        else {
            error = ERROR_SUCCESS;
            if (type == REG_MULTI_SZ)
                for (const WCHAR *id = ids; *id; id += wcslen(id) + 1)
                    if (_wcsicmp(id, hardwareId) == 0) match = TRUE;
        }
        HeapFree(GetProcessHeap(), 0, ids);
        if (error) return error;
        if (match) {
            if (*exists) return ERROR_ALREADY_EXISTS; // Never create/use a duplicate.
            *exists = TRUE;
            *found = device;
        }
    }
}

static DWORD RememberInf(HDEVINFO set, SP_DEVINFO_DATA *device, WCHAR *name)
{
    DEVPROPTYPE type;
    DWORD bytes = 0;
    if (!SetupDiGetDevicePropertyW(set, device, &DEVPKEY_Device_DriverInfPath,
                                  &type, (BYTE *)name, MAX_PATH * sizeof(WCHAR), &bytes, 0))
        return GetLastError();
    if (type != DEVPROP_TYPE_STRING || bytes < sizeof(WCHAR) ||
        bytes % sizeof(WCHAR) || name[bytes / sizeof(WCHAR) - 1] != 0 ||
        !IsPublishedInf(name)) return ERROR_INVALID_DATA;
    HKEY key;
    // Match the existing NSIS uninstall registration's 32-bit registry view.
    LSTATUS error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, uninstallKey, 0, NULL, 0,
                                   KEY_SET_VALUE | KEY_WOW64_32KEY, NULL, &key, NULL);
    if (error) return (DWORD)error;
    error = RegSetValueExW(key, L"DriverInf", 0, REG_SZ, (const BYTE *)name,
                          (DWORD)((wcslen(name) + 1) * sizeof(WCHAR)));
    RegCloseKey(key);
    return (DWORD)error;
}

static DWORD RetireLegacyService(const WCHAR *inf)
{
    WCHAR expected[MAX_PATH];
    if (wcscpy_s(expected, MAX_PATH, inf)) return ERROR_FILENAME_EXCED_RANGE;
    WCHAR *slash = wcsrchr(expected, L'\\');
    if (!slash) return ERROR_INVALID_NAME;
    *slash = 0; // driver directory
    slash = wcsrchr(expected, L'\\');
    if (!slash || wcscpy_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - expected),
                          L"ProxyBridgeDrv.sys")) return ERROR_INVALID_NAME;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    SC_HANDLE service = OpenServiceW(scm, L"ProxyBridgeDrv",
                                    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
    DWORD error = ERROR_SUCCESS;
    if (!service) {
        error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) error = ERROR_SUCCESS;
        goto done;
    }
    DWORD bytes = 0;
    if (QueryServiceConfigW(service, NULL, 0, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = ERROR_INVALID_DATA;
        goto close;
    }
    QUERY_SERVICE_CONFIGW *config = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!config) { error = ERROR_NOT_ENOUGH_MEMORY; goto close; }
    if (!QueryServiceConfigW(service, config, bytes, &bytes)) error = GetLastError();
    else {
        WCHAR path[MAX_PATH];
        const WCHAR *image = config->lpBinaryPathName;
        size_t length = wcslen(image);
        if (length >= 2 && image[0] == L'"' && image[length - 1] == L'"') {
            if (wcsncpy_s(path, MAX_PATH, image + 1, length - 2)) error = ERROR_INVALID_DATA;
        } else if (wcscpy_s(path, MAX_PATH, image)) error = ERROR_INVALID_DATA;
        if (!error && (config->dwServiceType != SERVICE_KERNEL_DRIVER ||
                       _wcsicmp(path, expected))) error = ERROR_SERVICE_EXISTS;
    }
    HeapFree(GetProcessHeap(), 0, config);
    if (error) goto close;
    SERVICE_STATUS status;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
        GetLastError() != ERROR_SERVICE_NOT_ACTIVE) { error = GetLastError(); goto close; }
    for (DWORD attempt = 0; attempt < 50; ++attempt) {
        if (!QueryServiceStatus(service, &status)) { error = GetLastError(); goto close; }
        if (status.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(100);
    }
    if (status.dwCurrentState != SERVICE_STOPPED) { error = ERROR_BUSY; goto close; }
    if (!DeleteService(service)) error = GetLastError();
close:
    CloseServiceHandle(service);
    if (!error) {
        service = OpenServiceW(scm, L"ProxyBridgeDrv", SERVICE_QUERY_STATUS);
        if (service) { CloseServiceHandle(service); error = ERROR_SERVICE_MARKED_FOR_DELETE; }
        else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) error = GetLastError();
    }
done:
    CloseServiceHandle(scm);
    return error;
}

static DWORD Install(HDEVINFO set, SP_DEVINFO_DATA *device, BOOL exists, const WCHAR *inf)
{
    DWORD error = exists ? ERROR_SUCCESS : RetireLegacyService(inf);
    if (error) return error;
    BOOL created = FALSE, reboot = FALSE;
    if (!exists) {
        if (!SetupDiCreateDeviceInfoW(set, L"InterceptSuite_ProxyBridge", &GUID_DEVCLASS_SYSTEM,
                                     L"ProxyBridge WFP Redirect", NULL, DICD_GENERATE_ID, device))
            return GetLastError();
        // sizeof includes one NUL; the extra explicit NUL makes a MULTI_SZ.
        static const WCHAR ids[] = L"ROOT\\InterceptSuite_ProxyBridge\0";
        if (!SetupDiSetDeviceRegistryPropertyW(set, device, SPDRP_HARDWAREID,
                                               (const BYTE *)ids, sizeof(ids)) ||
            !SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, device)) {
            error = GetLastError();
            (void)SetupDiRemoveDevice(set, device);
            return error;
        }
        created = TRUE;
    }
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, hardwareId, inf,
                                            INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &reboot)) {
        error = GetLastError();
        if (created && !SetupDiRemoveDevice(set, device))
            wprintf(L"Driver rollback failed: %lu\n", GetLastError());
        return error;
    }
    WCHAR published[MAX_PATH] = {0};
    error = RememberInf(set, device, published);
    if (error) return error;
    if (reboot) return ERROR_SUCCESS_REBOOT_REQUIRED;
    ULONG status, problem;
    CONFIGRET result = CM_Get_DevNode_Status(&status, &problem, device->DevInst, 0);
    if (result != CR_SUCCESS) return CM_MapCrToWin32Err(result, ERROR_NOT_READY);
    if (!(status & DN_STARTED) || problem) {
        wprintf(L"Driver device status: 0x%08lX, problem: %lu\n", status, problem);
        return ERROR_NOT_READY;
    }
    return ERROR_SUCCESS;
}

static DWORD Remove(HDEVINFO set, SP_DEVINFO_DATA *device, BOOL exists, const WCHAR *inf)
{
    WCHAR published[MAX_PATH] = {0};
    DWORD error;
    BOOL reboot = FALSE;
    if (exists) {
        error = RememberInf(set, device, published);
        // A root node whose installation failed may not have a driver yet.
        if (error && error != ERROR_NOT_FOUND) return error;
        // Microsoft documents hwndParent as optional; newdev.h omits _In_opt_.
#pragma warning(suppress: 6387)
        if (!DiUninstallDevice(NULL, set, device, 0, &reboot)) return GetLastError();
    }
    if (!published[0]) {
        DWORD bytes = sizeof(published);
        error = (DWORD)RegGetValueW(HKEY_LOCAL_MACHINE, uninstallKey, L"DriverInf",
                                   RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY, NULL, published, &bytes);
        if (error == ERROR_FILE_NOT_FOUND) {
            error = RetireLegacyService(inf);
            return error == ERROR_SERVICE_MARKED_FOR_DELETE || (!error && reboot)
                ? ERROR_SUCCESS_REBOOT_REQUIRED : error;
        }
        if (error) return error;
    }
    if (!IsPublishedInf(published)) return ERROR_INVALID_DATA;
    WCHAR path[MAX_PATH];
    UINT length = GetWindowsDirectoryW(path, MAX_PATH);
    if (!length || length >= MAX_PATH || wcscat_s(path, MAX_PATH, L"\\INF\\") ||
        wcscat_s(path, MAX_PATH, published)) return ERROR_INVALID_NAME;
    BOOL packageReboot = FALSE;
    if (!DiUninstallDriverW(NULL, path, 0, &packageReboot)) {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) return error;
    }
    if (reboot || packageReboot) return ERROR_SUCCESS_REBOOT_REQUIRED;
    // SCM may still retain the PnP service while another process holds it open.
    // Do not delete a PnP-owned service directly; report the required restart.
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    SC_HANDLE service = OpenServiceW(scm, L"ProxyBridgeDrv", SERVICE_QUERY_STATUS);
    error = service ? ERROR_SUCCESS_REBOOT_REQUIRED : GetLastError();
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(scm);
    if (error == ERROR_SERVICE_MARKED_FOR_DELETE) return ERROR_SUCCESS_REBOOT_REQUIRED;
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? ERROR_SUCCESS : error;
}

int wmain(int argc, WCHAR **argv)
{
    DWORD error = ERROR_INVALID_PARAMETER;
    WCHAR inf[MAX_PATH];
    if (argc == 3 && (!_wcsicmp(argv[1], L"install") || !_wcsicmp(argv[1], L"remove"))) {
        DWORD length = GetFullPathNameW(argv[2], MAX_PATH, inf, NULL);
        if (length && length < MAX_PATH) {
            HDEVINFO set = SetupDiGetClassDevsW(&GUID_DEVCLASS_SYSTEM, L"ROOT", NULL, 0);
            if (set == INVALID_HANDLE_VALUE) error = GetLastError();
            else {
                SP_DEVINFO_DATA device = { sizeof(device) };
                BOOL exists;
                error = FindDevice(set, &device, &exists);
                if (!error) error = !_wcsicmp(argv[1], L"install")
                    ? Install(set, &device, exists, inf) : Remove(set, &device, exists, inf);
                SetupDiDestroyDeviceInfoList(set);
            }
        }
    }
    wprintf(L"Driver operation result: %lu\n", error);
    return (int)error;
}
