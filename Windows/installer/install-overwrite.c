#include "install-overwrite.h"
#include "install-stage.h"
#include "startup-installed.h"
#include "install-trace.h"
#include <aclapi.h>
#include <stdio.h>
#include <wchar.h>

#define PRODUCT_FILE_COUNT (PB_PAYLOAD_FILES + 3)
static const WCHAR *product_file_name(unsigned i)
{
    return i <= PB_PAYLOAD_FILES ? pb_payload_file_name(i) :
        i == PB_PAYLOAD_FILES + 1 ? L"ProxyBridgeLauncher.exe" : L"uninstall.exe";
}

static DWORD overwrite_file_open(const WCHAR *directory, const WCHAR *name, HANDLE *out)
{
    WCHAR path[MAX_PATH];
    if (swprintf_s(path, MAX_PATH, L"%s\\%s", directory, name) < 0) return ERROR_FILENAME_EXCED_RANGE;
    *out = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, NULL,
        OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (*out == INVALID_HANDLE_VALUE) { *out = NULL; return GetLastError(); }
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(*out, &info)) return GetLastError();
    // Never truncate a junction, directory or an alias to a file elsewhere.
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks != 1)
        return ERROR_INVALID_NAME;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetSecurityInfo(*out, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &descriptor);
    if (!error) error = pb_startup_file_security(descriptor);
    if (descriptor) LocalFree(descriptor);
    return error;
}

DWORD pb_product_overwrite(PB_VERIFIED_PAYLOAD *source, HANDLE launcher,
                           HANDLE uninstaller, const BYTE manifestHash[32])
{
    if (!source || !manifestHash || !launcher || launcher == INVALID_HANDLE_VALUE ||
        !uninstaller || uninstaller == INVALID_HANDLE_VALUE) return ERROR_INVALID_PARAMETER;
    for (unsigned i = 0; i <= PB_PAYLOAD_FILES; ++i)
        if (!source->files[i] || source->files[i] == INVALID_HANDLE_VALUE) return ERROR_INVALID_PARAMETER;
    PB_VERIFIED_PAYLOAD directories = {0}; HANDLE root = NULL;
    DWORD error = pb_product_driver_open(TRUE, &directories, &root);
    WCHAR directory[MAX_PATH] = {0};
    if (!error) {
        WCHAR raw[MAX_PATH];
        DWORD n = GetFinalPathNameByHandleW(root, raw, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n < 11 || n >= MAX_PATH || wcsncmp(raw, L"\\\\?\\", 4) || _wcsicmp(raw + n - 7, L"\\driver"))
            error = ERROR_INVALID_NAME;
        else { raw[n - 7] = 0; wcscpy_s(directory, MAX_PATH, raw + 4); }
    }
    HANDLE targets[PRODUCT_FILE_COUNT] = {0};
    // Acquire every destination BEFORE truncating any file. In particular a
    // loaded GUI/DLL/helper must fail here, leaving old bytes intact.
    for (unsigned i = 0; !error && i < PRODUCT_FILE_COUNT; ++i) {
        error = overwrite_file_open(directory, product_file_name(i), &targets[i]);
        if (error) { wprintf(L"SetupFile=%s\n", product_file_name(i)); pb_install_trace(L"open-overwrite", error); }
    }
    for (unsigned i = 0; !error && i < PRODUCT_FILE_COUNT; ++i) {
        HANDLE input = i <= PB_PAYLOAD_FILES ? source->files[i] :
            i == PB_PAYLOAD_FILES + 1 ? launcher : uninstaller;
        LARGE_INTEGER zero = {0};
        if (!SetFilePointerEx(targets[i], zero, NULL, FILE_BEGIN) || !SetEndOfFile(targets[i])) error = GetLastError();
        if (!error) error = pb_stage_copy_file(input, targets[i]);
        if (error) { wprintf(L"SetupFile=%s\n", product_file_name(i)); pb_install_trace(L"overwrite", error); }
    }
    for (unsigned i = 0; i < PRODUCT_FILE_COUNT; ++i) if (targets[i]) CloseHandle(targets[i]);
    if (!error) {
        PB_VERIFIED_PAYLOAD verified = {0};
        error = pb_payload_open(directory, manifestHash, source->manifest.protocol, source->manifest.driverVersion, &verified);
        pb_payload_close(&verified);
    }
    pb_payload_close(&directories);
    return error;
}
