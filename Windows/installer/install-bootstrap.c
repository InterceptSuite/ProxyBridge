#include "install-bootstrap.h"
#include "install-stage.h"
#include "startup-installed.h"
#include <aclapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>

static DWORD bootstrap_file_open(const WCHAR *path, BOOL protectedFile, HANDLE *out)
{
    *out = CreateFileW(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (*out == INVALID_HANDLE_VALUE) { *out = NULL; return GetLastError(); }
    FILE_ATTRIBUTE_TAG_INFO info;
    if (!GetFileInformationByHandleEx(*out, FileAttributeTagInfo, &info, sizeof(info))) return GetLastError();
    if (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_INVALID_NAME;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(*out, &size)) return GetLastError();
    if (!size.QuadPart) return ERROR_INVALID_DATA;
    if (!protectedFile) return 0;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetSecurityInfo(*out, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &descriptor);
    if (!error) error = pb_startup_file_security(descriptor);
    if (descriptor) LocalFree(descriptor);
    return error;
}

static DWORD bootstrap_equal(HANDLE source, HANDLE target)
{
    LARGE_INTEGER zero = {0}, a, b;
    if (!GetFileSizeEx(source, &a) || !GetFileSizeEx(target, &b)) return GetLastError();
    if (a.QuadPart != b.QuadPart) return ERROR_CRC;
    if (!SetFilePointerEx(source, zero, NULL, FILE_BEGIN) || !SetFilePointerEx(target, zero, NULL, FILE_BEGIN)) return GetLastError();
    BYTE left[16384], right[16384];
    for (;;) {
        DWORD n = 0, m = 0;
        if (!ReadFile(source, left, sizeof(left), &n, NULL) || !ReadFile(target, right, sizeof(right), &m, NULL)) return GetLastError();
        if (n != m || memcmp(left, right, n)) return ERROR_CRC;
        if (!n) return 0;
    }
}

// Called with the installation mutex and protected directory ancestors pinned.
// Only unpublished GUID temporaries belong to this sweep. Published files may
// still be referenced by recovery/startup, even when this package is obsolete.
static DWORD bootstrap_cleanup_temporary(const WCHAR *directory)
{
    WCHAR pattern[MAX_PATH];
    if (swprintf_s(pattern, MAX_PATH, L"%s\\*.bootstrap.tmp", directory) < 0) return ERROR_FILENAME_EXCED_RANGE;
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND ? 0 : error;
    }
    DWORD error = 0;
    do {
        const size_t guidLength = 38;
        if (wcslen(entry.cFileName) != guidLength + wcslen(L".bootstrap.tmp") ||
            wcscmp(entry.cFileName + guidLength, L".bootstrap.tmp") ||
            (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) continue;
        WCHAR name[40], canonical[40], path[MAX_PATH]; GUID id;
        wcsncpy_s(name, ARRAYSIZE(name), entry.cFileName, guidLength);
        if (FAILED(CLSIDFromString(name, &id)) || !StringFromGUID2(&id, canonical, ARRAYSIZE(canonical)) ||
            _wcsicmp(name, canonical)) continue;
        if (swprintf_s(path, MAX_PATH, L"%s\\%s", directory, entry.cFileName) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
        HANDLE file = CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL, 0, NULL,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_SHARING_VIOLATION) { error = 0; continue; }
            break;
        }
        FILE_ATTRIBUTE_TAG_INFO info;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &info, sizeof(info))) error = GetLastError();
        else if (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) error = ERROR_INVALID_NAME;
        else error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            NULL, NULL, NULL, NULL, &descriptor);
        if (!error) error = pb_startup_file_security(descriptor);
        if (!error) {
            FILE_DISPOSITION_INFO disposition = {TRUE};
            if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition))) error = GetLastError();
        }
        if (descriptor) LocalFree(descriptor);
        CloseHandle(file);
        if (error) break;
    } while (FindNextFileW(search, &entry));
    if (!error) { error = GetLastError(); if (error == ERROR_NO_MORE_FILES) error = 0; }
    FindClose(search);
    return error;
}

static DWORD bootstrap_publish_file(HANDLE source, const WCHAR *directory, const WCHAR *name, HANDLE *held)
{
    WCHAR path[MAX_PATH], temporary[MAX_PATH], id[40];
    if (swprintf_s(path, MAX_PATH, L"%s\\%s", directory, name) < 0) return ERROR_FILENAME_EXCED_RANGE;
    DWORD error = bootstrap_file_open(path, TRUE, held);
    if (!error) return bootstrap_equal(source, *held);
    if (error != ERROR_FILE_NOT_FOUND) return error;
    GUID guid;
    if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(&guid, id, ARRAYSIZE(id))) return ERROR_GEN_FAILURE;
    if (swprintf_s(temporary, MAX_PATH, L"%s\\%s.bootstrap.tmp", directory, id) < 0) return ERROR_FILENAME_EXCED_RANGE;
    HANDLE output = CreateFileW(temporary, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) return GetLastError();
    error = pb_stage_copy_file(source, output);
    CloseHandle(output);
    // Never replace a published file, including when another actor raced us.
    if (!error && !MoveFileExW(temporary, path, MOVEFILE_WRITE_THROUGH)) error = GetLastError();
    if (error) { DeleteFileW(temporary); return error; }
    error = bootstrap_file_open(path, TRUE, held);
    return error ? error : bootstrap_equal(source, *held);
}

DWORD pb_bootstrap_publish(const WCHAR *source, const WCHAR *hash)
{
    static const WCHAR *names[] = {L"ProxyBridgeDriverSetup.exe", L"ProxyBridgeLauncher.exe", L"uninstall.exe"};
    if (!source || !hash) return ERROR_INVALID_PARAMETER;
    PB_VERIFIED_PAYLOAD input = {0}, target = {0}; HANDLE root = NULL;
    DWORD error = pb_payload_lock_directory(source, &input);
    WCHAR path[MAX_PATH], directory[MAX_PATH];
    for (unsigned i = 0; !error && i < ARRAYSIZE(names); ++i) {
        if (swprintf_s(path, MAX_PATH, L"%s\\%s", source, names[i]) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        else error = bootstrap_file_open(path, FALSE, &input.files[i]);
    }
    if (!error) error = pb_bootstrap_root_open(hash, &target, &root);
    if (!error) {
        DWORD length = GetFinalPathNameByHandleW(root, directory, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (!length) error = GetLastError();
        else if (length >= MAX_PATH || wcsncmp(directory, L"\\\\?\\", 4)) error = ERROR_INVALID_NAME;
    }
    if (!error) error = bootstrap_cleanup_temporary(directory);
    for (unsigned i = 0; !error && i < ARRAYSIZE(names); ++i)
        error = bootstrap_publish_file(input.files[i], directory, names[i], &target.files[i]);
    pb_payload_close(&target);
    pb_payload_close(&input);
    return error;
}
