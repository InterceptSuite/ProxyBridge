#include "install-stage.h"
#include "install-layout.h"
#include "startup-installed.h"
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

static const WCHAR directorySecurity[] = L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

static DWORD cleanup_root(HANDLE supplied, const WCHAR *directory,
                          PB_VERIFIED_PAYLOAD *guard, HANDLE *selected);

DWORD pb_stage_copy_file(HANDLE source, HANDLE destination)
{
    LARGE_INTEGER zero = {0}, size = {0};
    if (!GetFileSizeEx(destination, &size)) return GetLastError();
    if (size.QuadPart) return ERROR_ALREADY_EXISTS;
    if (!SetFilePointerEx(source, zero, NULL, FILE_BEGIN) ||
        !SetFilePointerEx(destination, zero, NULL, FILE_BEGIN)) return GetLastError();
    BYTE buffer[65536];
    for (;;) {
        DWORD bytes = 0;
        if (!ReadFile(source, buffer, sizeof(buffer), &bytes, NULL)) return GetLastError();
        if (!bytes) break;
        DWORD offset = 0;
        while (offset < bytes) {
            DWORD written = 0;
            if (!WriteFile(destination, buffer + offset, bytes - offset, &written, NULL)) return GetLastError();
            if (!written) return ERROR_WRITE_FAULT;
            offset += written;
        }
    }
    return FlushFileBuffers(destination) ? ERROR_SUCCESS : GetLastError();
}

static DWORD check_object(HANDLE root, PSECURITY_DESCRIPTOR expected, BOOL directory)
{
    FILE_ATTRIBUTE_TAG_INFO attributes;
    if (!GetFileInformationByHandleEx(root, FileAttributeTagInfo, &attributes, sizeof(attributes))) return GetLastError();
    if (((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return ERROR_INVALID_NAME;
    PSID owner = NULL; PACL actual = NULL, wanted = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetSecurityInfo(root, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                  &owner, NULL, &actual, NULL, &descriptor);
    if (error != ERROR_SUCCESS) return error;
    BOOL present, defaulted; SECURITY_DESCRIPTOR_CONTROL control; DWORD revision;
    if (!owner || (!IsWellKnownSid(owner, WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner, WinLocalSystemSid)) ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) || !(control & SE_DACL_PROTECTED) || !actual ||
        !GetSecurityDescriptorDacl(expected, &present, &wanted, &defaulted) || !wanted ||
        actual->AclSize != wanted->AclSize || memcmp(actual, wanted, wanted->AclSize)) error = ERROR_ACCESS_DENIED;
    LocalFree(descriptor);
    return error;
}

static DWORD check_root(HANDLE root, PSECURITY_DESCRIPTOR expected)
{ return check_object(root, expected, TRUE); }

DWORD pb_stage_target_path(HANDLE root, const GUID *transaction, WCHAR destination[MAX_PATH])
{
    static const GUID empty = {0};
    if (!transaction || !destination || IsEqualGUID(transaction, &empty)) return ERROR_INVALID_PARAMETER;
    destination[0] = 0;
    WCHAR path[MAX_PATH], guid[40];
    DWORD length = GetFinalPathNameByHandleW(root, path, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length < 7 || length >= MAX_PATH || wcsncmp(path, L"\\\\?\\", 4) || path[5] != L':' || path[6] != L'\\')
        return ERROR_INVALID_NAME;
    if (!StringFromGUID2(transaction, guid, ARRAYSIZE(guid)) ||
        swprintf_s(destination, MAX_PATH, L"%s\\%s", path + 4, guid) < 0) return ERROR_FILENAME_EXCED_RANGE;
    return 0;
}

static DWORD cleanup_partial_at_root(HANDLE root, const GUID *transaction, const WCHAR *directory)
{
    WCHAR expectedPath[MAX_PATH];
    DWORD error = pb_stage_target_path(root, transaction, expectedPath);
    if (error) return error;
    if (!directory || _wcsicmp(directory, expectedPath)) return ERROR_INVALID_NAME;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &descriptor, NULL)) return GetLastError();
    error = check_root(root, descriptor);
    PB_VERIFIED_PAYLOAD guard = {0};
    BOOL missing = FALSE;
    // Keep every ancestor pinned, including the optional driver directory.
    if (!error) {
        error = pb_payload_lock_directory(directory, &guard);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { error = 0; missing = TRUE; }
    }
    if (!error && !missing) error = check_root(guard.directories[guard.directoryCount - 1], descriptor);
    for (unsigned level = 0; !error && !missing && level < 2; ++level) {
        WCHAR folder[MAX_PATH], pattern[MAX_PATH];
        if (swprintf_s(folder, MAX_PATH, L"%s%s", directory, level ? L"\\driver" : L"") < 0 ||
            swprintf_s(pattern, MAX_PATH, L"%s\\*", folder) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
        if (level) {
            HANDLE sub = CreateFileW(folder, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (sub == INVALID_HANDLE_VALUE) {
                error = GetLastError(); if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) error = 0;
                break;
            }
            if (guard.directoryCount == ARRAYSIZE(guard.directories)) { CloseHandle(sub); error = ERROR_INVALID_NAME; break; }
            guard.directories[guard.directoryCount++] = sub;
            error = check_root(sub, descriptor); if (error) break;
        }
        WIN32_FIND_DATAW entry; HANDLE search = FindFirstFileW(pattern, &entry);
        if (search == INVALID_HANDLE_VALUE) { error = GetLastError(); break; }
        do {
            if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
            if (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { error = ERROR_INVALID_NAME; break; }
            if (!level && !_wcsicmp(entry.cFileName, L"driver") && (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            unsigned index;
            for (index = 0; index <= PB_PAYLOAD_FILES; ++index) {
                const WCHAR *name = pb_payload_file_name(index), *slash = wcschr(name, L'\\');
                if ((level && slash && !_wcsicmp(entry.cFileName, slash + 1)) ||
                    (!level && !slash && !_wcsicmp(entry.cFileName, name))) break;
            }
            if (index > PB_PAYLOAD_FILES || guard.files[index] || (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { error = ERROR_INVALID_DATA; break; }
            WCHAR path[MAX_PATH];
            if (swprintf_s(path, MAX_PATH, L"%s\\%s", folder, entry.cFileName) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
            HANDLE file = CreateFileW(path, DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, NULL,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); break; }
            guard.files[index] = file;
            error = check_object(file, descriptor, FALSE); if (error) break;
        } while (FindNextFileW(search, &entry));
        if (!error && GetLastError() != ERROR_NO_MORE_FILES) error = GetLastError();
        FindClose(search);
    }
    // Validate/open the complete known inventory BEFORE deleting any bytes.
    // Retain empty directories; no recursive deletion and no name-based reopen.
    for (unsigned i = 0; !error && i <= PB_PAYLOAD_FILES; ++i) if (guard.files[i]) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        if (!SetFileInformationByHandle(guard.files[i], FileDispositionInfo, &disposition, sizeof(disposition))) error = GetLastError();
        if (!error) { CloseHandle(guard.files[i]); guard.files[i] = NULL; }
    }
    pb_payload_close(&guard); LocalFree(descriptor); return error;
}

static DWORD protected_folder_open(int folder, const WCHAR *product, PB_VERIFIED_PAYLOAD *guard, HANDLE *root, const WCHAR *branch, const WCHAR *leaf, BOOL create)
{
    if (!guard || !root) return ERROR_INVALID_PARAMETER;
    ZeroMemory(guard, sizeof(*guard)); *root = NULL;
    WCHAR path[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, folder, NULL, SHGFP_TYPE_CURRENT, path);
    if (FAILED(result)) return ERROR_PATH_NOT_FOUND;
    DWORD error = pb_payload_lock_directory(path, guard);
    if (error) return error;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &descriptor, NULL)) {
        error = GetLastError(); pb_payload_close(guard); return error;
    }
    SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
    const WCHAR *parts[] = {product, branch, leaf};
    for (unsigned i = 0; error == ERROR_SUCCESS && i < ARRAYSIZE(parts) && parts[i]; ++i) {
        if (wcscat_s(path, MAX_PATH, parts[i])) { error = ERROR_FILENAME_EXCED_RANGE; break; }
        if (create && !CreateDirectoryW(path, &security) && GetLastError() != ERROR_ALREADY_EXISTS) { error = GetLastError(); break; }
        HANDLE directory = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (directory == INVALID_HANDLE_VALUE) { error = GetLastError(); break; }
        error = check_root(directory, descriptor);
        if (error || guard->directoryCount == ARRAYSIZE(guard->directories)) {
            CloseHandle(directory); if (!error) error = ERROR_FILENAME_EXCED_RANGE; break;
        }
        guard->directories[guard->directoryCount++] = directory;
    }
    LocalFree(descriptor);
    if (error) pb_payload_close(guard);
    else *root = guard->directories[guard->directoryCount - 1];
    return error;
}

DWORD pb_stage_root_open(PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    return protected_folder_open(CSIDL_PROGRAM_FILES, L"\\InterceptSuite", guard, root, L"\\ProxyBridge", L"\\versions", TRUE);
}

DWORD pb_product_root_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    return protected_folder_open(CSIDL_PROGRAM_FILES, L"\\InterceptSuite", guard, root,
                                 L"\\ProxyBridge", NULL, create);
}

DWORD pb_product_driver_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    if (!guard || !root) return ERROR_INVALID_PARAMETER;
    ZeroMemory(guard, sizeof(*guard)); *root = NULL;
    PB_VERIFIED_PAYLOAD parent = {0}; HANDLE parentRoot = NULL;
    DWORD error = pb_product_root_open(create, &parent, &parentRoot);
    if (!error) error = protected_folder_open(CSIDL_PROGRAM_FILES,
        L"\\InterceptSuite\\ProxyBridge", guard, root, L"\\driver", NULL, create);
    pb_payload_close(&parent);
    return error;
}

DWORD pb_programs_root_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    return protected_folder_open(CSIDL_COMMON_PROGRAMS, L"\\ProxyBridge", guard, root, NULL, NULL, create);
}

DWORD pb_stage_root_read(PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    DWORD error = protected_folder_open(CSIDL_PROGRAM_FILES, L"\\InterceptSuite", guard, root, L"\\ProxyBridge", L"\\versions", FALSE);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        return protected_folder_open(CSIDL_COMMON_APPDATA, L"\\InterceptSuite.ProxyBridge", guard, root, L"\\versions", NULL, FALSE);
    return error;
}

static BOOL direct_version_child(HANDLE root, const WCHAR *directory)
{
    WCHAR path[MAX_PATH], canonical[40]; GUID id;
    DWORD length = GetFinalPathNameByHandleW(root, path, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length < 7 || length >= MAX_PATH || wcsncmp(path, L"\\\\?\\", 4) || !directory) return FALSE;
    size_t prefix = wcslen(path + 4);
    if (wcsnlen_s(directory, MAX_PATH) != prefix + 39 ||
        _wcsnicmp(directory, path + 4, prefix) || directory[prefix] != L'\\') return FALSE;
    return SUCCEEDED(CLSIDFromString(directory + prefix + 1, &id)) &&
        StringFromGUID2(&id, canonical, ARRAYSIZE(canonical)) &&
        !_wcsicmp(directory + prefix + 1, canonical);
}

static DWORD cleanup_root(HANDLE supplied, const WCHAR *directory,
                          PB_VERIFIED_PAYLOAD *guard, HANDLE *selected)
{
    ZeroMemory(guard, sizeof(*guard)); *selected = supplied;
    if (direct_version_child(supplied, directory)) return 0;
    WCHAR legacy[MAX_PATH];
    if (!directory || FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, legacy)))
        return ERROR_INVALID_NAME;
    if (wcscat_s(legacy, MAX_PATH, L"\\InterceptSuite.ProxyBridge\\versions")) return ERROR_FILENAME_EXCED_RANGE;
    size_t prefix = wcslen(legacy);
    if (wcsnlen_s(directory, MAX_PATH) != prefix + 39 ||
        _wcsnicmp(directory, legacy, prefix) || directory[prefix] != L'\\') return ERROR_INVALID_NAME;
    // Compatibility is restricted to the old protected root, never a parent
    // inferred from an arbitrary journal path. Keep its ancestor handles pinned.
    DWORD error = protected_folder_open(CSIDL_COMMON_APPDATA, L"\\InterceptSuite.ProxyBridge",
        guard, selected, L"\\versions", NULL, FALSE);
    if (error) return error;
    if (!direct_version_child(*selected, directory)) {
        pb_payload_close(guard); return ERROR_INVALID_NAME;
    }
    return 0;
}

DWORD pb_stage_validate_target(HANDLE root, const GUID *transaction, const WCHAR *directory)
{
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE selected = NULL; WCHAR expected[MAX_PATH];
    DWORD error = cleanup_root(root, directory, &guard, &selected);
    if (!error) error = pb_stage_target_path(selected, transaction, expected);
    if (!error && _wcsicmp(expected, directory)) error = ERROR_INVALID_NAME;
    pb_payload_close(&guard);
    return error;
}

DWORD pb_stage_cleanup_partial(HANDLE root, const GUID *transaction, const WCHAR *directory)
{
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE selected = NULL;
    DWORD error = cleanup_root(root, directory, &guard, &selected);
    if (!error) error = cleanup_partial_at_root(selected, transaction, directory);
    pb_payload_close(&guard);
    return error;
}

static DWORD bootstrap_open(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root, BOOL create)
{
    if (!hash || wcsnlen_s(hash, 65) != 64) return ERROR_INVALID_PARAMETER;
    WCHAR leaf[66] = L"\\";
    for (unsigned i = 0; i < 64; ++i) {
        WCHAR c = hash[i];
        if (c >= L'a' && c <= L'f') c -= L'a' - L'A';
        if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F'))) return ERROR_INVALID_PARAMETER;
        leaf[i + 1] = c;
    }
    return protected_folder_open(CSIDL_COMMON_APPDATA, L"\\InterceptSuite.ProxyBridge", guard, root, L"\\bootstrap", leaf, create);
}

DWORD pb_bootstrap_root_open(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    return bootstrap_open(hash, guard, root, TRUE);
}

DWORD pb_bootstrap_root_read(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    return bootstrap_open(hash, guard, root, FALSE);
}

static DWORD cleanup_files_at_root(HANDLE root, const WCHAR *directory, const BYTE hash[32], DWORD protocol, DWORD version)
{
    if (!directory || !hash) return ERROR_INVALID_PARAMETER;
    WCHAR rootPath[MAX_PATH];
    DWORD length = GetFinalPathNameByHandleW(root, rootPath, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length < 7 || length >= MAX_PATH || wcsncmp(rootPath, L"\\\\?\\", 4)) return ERROR_INVALID_NAME;
    size_t prefix = wcslen(rootPath + 4);
    size_t size = wcsnlen_s(directory, MAX_PATH);
    if (size != prefix + 39 || _wcsnicmp(directory, rootPath + 4, prefix) || directory[prefix] != L'\\')
        return ERROR_INVALID_NAME;
    GUID id; WCHAR canonical[40];
    if (FAILED(CLSIDFromString(directory + prefix + 1, &id)) || !StringFromGUID2(&id, canonical, ARRAYSIZE(canonical)) ||
        _wcsicmp(canonical, directory + prefix + 1)) return ERROR_INVALID_NAME;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &descriptor, NULL)) return GetLastError();
    DWORD error = check_root(root, descriptor);
    PB_VERIFIED_PAYLOAD payload = {0};
    if (!error) error = pb_payload_open_remaining(directory, hash, protocol, version, &payload);
    if (!error && payload.directoryCount < 2) error = ERROR_INVALID_DATA;
    if (!error) error = check_root(payload.directories[payload.directoryCount - 2], descriptor);
    if (!error) error = check_root(payload.directories[payload.directoryCount - 1], descriptor);
    LocalFree(descriptor);
    // DELETE access was acquired before hashing. Delete through those same
    // handles, never reopen names after validation. No recursive removal.
    for (unsigned i = 0; !error && i < PB_PAYLOAD_FILES; ++i) {
        if (!payload.files[i]) continue;
        FILE_DISPOSITION_INFO disposition = {TRUE};
        if (!SetFileInformationByHandle(payload.files[i], FileDispositionInfo, &disposition, sizeof(disposition)))
            error = GetLastError();
        if (!error) { CloseHandle(payload.files[i]); payload.files[i] = NULL; }
    }
    pb_payload_close(&payload);
    return error;
}

DWORD pb_stage_cleanup_files(HANDLE root, const WCHAR *directory, const BYTE hash[32], DWORD protocol, DWORD version)
{
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE selected = NULL;
    DWORD error = cleanup_root(root, directory, &guard, &selected);
    if (!error) error = cleanup_files_at_root(selected, directory, hash, protocol, version);
    pb_payload_close(&guard);
    return error;
}

DWORD pb_stage_payload(HANDLE root, const GUID *transaction, PB_VERIFIED_PAYLOAD *source,
                        const BYTE manifestHash[32], WCHAR destination[MAX_PATH])
{
    static const GUID empty = {0};
    if (!destination) return ERROR_INVALID_PARAMETER;
    destination[0] = 0;
    if (!transaction || IsEqualGUID(transaction, &empty) || !source || !manifestHash) return ERROR_INVALID_PARAMETER;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &descriptor, NULL))
        return GetLastError();
    DWORD error = check_root(root, descriptor);
    WCHAR target[MAX_PATH] = {0};
    if (error == ERROR_SUCCESS) error = pb_stage_target_path(root, transaction, target);
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
    if (error == ERROR_SUCCESS && !CreateDirectoryW(target, &attributes)) error = GetLastError();
    if (error == ERROR_SUCCESS) {
        WCHAR driver[MAX_PATH];
        if (swprintf_s(driver, MAX_PATH, L"%s\\driver", target) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        else if (!CreateDirectoryW(driver, &attributes)) error = GetLastError();
    }
    // Manifest is last. Every destination is new and closed only after flush.
    for (unsigned i = 0; error == ERROR_SUCCESS && i <= PB_PAYLOAD_FILES; ++i) {
        WCHAR file[MAX_PATH];
        if (swprintf_s(file, MAX_PATH, L"%s\\%s", target, pb_payload_file_name(i)) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
        HANDLE output = CreateFileW(file, GENERIC_READ | GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (output == INVALID_HANDLE_VALUE) { error = GetLastError(); break; }
        error = pb_stage_copy_file(source->files[i], output);
        CloseHandle(output);
    }
    LocalFree(descriptor);
    if (error == ERROR_SUCCESS) {
        PB_VERIFIED_PAYLOAD verified;
        error = pb_payload_open(target, manifestHash, source->manifest.protocol, source->manifest.driverVersion, &verified);
        pb_payload_close(&verified);
    }
    if (error == ERROR_SUCCESS) wcscpy_s(destination, MAX_PATH, target);
    return error;
}
#include "install-flat-cleanup.inc"
