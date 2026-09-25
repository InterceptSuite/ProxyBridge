#include "install-payload.h"
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

static const WCHAR *const fileNames[PB_PAYLOAD_FILES + 1] = {
    L"ProxyBridge.exe", L"ProxyBridge_CLI.exe", L"ProxyBridgeCore.dll",
    L"ProxyBridgeDriverSetup.exe", L"driver\\ProxyBridgeDrv.inf",
    L"driver\\ProxyBridgeDrv.cat", L"driver\\ProxyBridgeDrv.sys", L"payload.manifest"
};
C_ASSERT(sizeof(PB_PAYLOAD_MANIFEST) == 260);

const WCHAR *pb_payload_file_name(unsigned index)
{
    return index < ARRAYSIZE(fileNames) ? fileNames[index] : NULL;
}

static DWORD lock_directory(const WCHAR *path, PB_VERIFIED_PAYLOAD *payload)
{
    if (payload->directoryCount == ARRAYSIZE(payload->directories)) return ERROR_FILENAME_EXCED_RANGE;
    HANDLE directory = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (directory == INVALID_HANDLE_VALUE) return GetLastError();
    FILE_ATTRIBUTE_TAG_INFO attributes;
    DWORD error = ERROR_SUCCESS;
    if (!GetFileInformationByHandleEx(directory, FileAttributeTagInfo, &attributes, sizeof(attributes)))
        error = GetLastError();
    else if (!(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
             (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        error = ERROR_INVALID_NAME;
    if (error) { CloseHandle(directory); return error; }
    payload->directories[payload->directoryCount++] = directory;
    return ERROR_SUCCESS;
}

static DWORD lock_payload_path(const WCHAR *path, PB_VERIFIED_PAYLOAD *payload, BOOL includeDriver)
{
    // Deliberately accept only canonical local DOS paths. UNC, device paths,
    // alternate streams, relative segments and junctions are not staging roots.
    size_t length = wcsnlen_s(path, MAX_PATH);
    if (length < 4 || length >= MAX_PATH || path[1] != L':' || path[2] != L'\\' ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
        return ERROR_INVALID_NAME;
    WCHAR copy[MAX_PATH];
    wcscpy_s(copy, MAX_PATH, path);
    copy[3] = 0;
    if (GetDriveTypeW(copy) != DRIVE_FIXED) return ERROR_NOT_SUPPORTED;
    DWORD error = lock_directory(copy, payload);
    if (error) return error;
    wcscpy_s(copy, MAX_PATH, path);
    size_t start = 3;
    for (size_t i = 3; i <= length; ++i) {
        if (copy[i] == L':' || copy[i] == L'/' || copy[i] == L'*' || copy[i] == L'?') return ERROR_INVALID_NAME;
        if (copy[i] != L'\\' && copy[i] != 0) continue;
        if (i == start || copy[i - 1] == L'.' || copy[i - 1] == L' ') return ERROR_INVALID_NAME;
        WCHAR separator = copy[i]; copy[i] = 0;
        error = lock_directory(copy, payload);
        copy[i] = separator;
        if (error) return error;
        start = i + 1;
    }
    if (!includeDriver) return ERROR_SUCCESS;
    if (swprintf_s(copy, MAX_PATH, L"%s\\driver", path) < 0) return ERROR_FILENAME_EXCED_RANGE;
    return lock_directory(copy, payload);
}

DWORD pb_payload_lock_directory(const WCHAR *directory, PB_VERIFIED_PAYLOAD *guard)
{
    if (!guard) return ERROR_INVALID_PARAMETER;
    ZeroMemory(guard, sizeof(*guard));
    if (!directory) return ERROR_INVALID_PARAMETER;
    DWORD error = lock_payload_path(directory, guard, FALSE);
    if (error) pb_payload_close(guard);
    return error;
}

static DWORD hash_file(HANDLE file, BYTE digest[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD error = ERROR_SUCCESS;
    LARGE_INTEGER zero = {0};
    if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) return GetLastError();
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return ERROR_GEN_FAILURE;
    if (BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) < 0) error = ERROR_GEN_FAILURE;
    BYTE buffer[65536];
    while (error == ERROR_SUCCESS) {
        DWORD bytes = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &bytes, NULL)) { error = GetLastError(); break; }
        if (!bytes) break;
        if (BCryptHashData(hash, buffer, bytes, 0) < 0) error = ERROR_GEN_FAILURE;
    }
    if (error == ERROR_SUCCESS && BCryptFinishHash(hash, digest, 32, 0) < 0) error = ERROR_GEN_FAILURE;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return error;
}

void pb_payload_close(PB_VERIFIED_PAYLOAD *payload)
{
    if (!payload) return;
    for (unsigned i = 0; i < ARRAYSIZE(payload->files); ++i) {
        if (payload->files[i] && payload->files[i] != INVALID_HANDLE_VALUE)
            CloseHandle(payload->files[i]);
        payload->files[i] = NULL;
    }
    ZeroMemory(&payload->manifest, sizeof(payload->manifest));
    while (payload->directoryCount) {
        DWORD index = --payload->directoryCount;
        CloseHandle(payload->directories[index]);
        payload->directories[index] = NULL;
    }
}

DWORD pb_payload_check_inventory(const WCHAR *directory)
{
    if (!directory || !*directory) return ERROR_INVALID_PARAMETER;
    for (unsigned level = 0; level < 2; ++level) {
        WCHAR pattern[MAX_PATH];
        if (swprintf_s(pattern, MAX_PATH, L"%s\\%s*", directory, level ? L"driver\\" : L"") < 0)
            return ERROR_FILENAME_EXCED_RANGE;
        WIN32_FIND_DATAW entry;
        HANDLE search = FindFirstFileW(pattern, &entry);
        if (search == INVALID_HANDLE_VALUE) return GetLastError();
        DWORD error = 0;
        do {
            if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
            BOOL allowed = FALSE;
            if (!level && !_wcsicmp(entry.cFileName, L"driver"))
                allowed = (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            else if (!(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                for (unsigned i = 0; i <= PB_PAYLOAD_FILES; ++i) {
                    const WCHAR *name = fileNames[i];
                    const WCHAR *slash = wcschr(name, L'\\');
                    if ((level && slash && !_wcsicmp(entry.cFileName, slash + 1)) ||
                        (!level && !slash && !_wcsicmp(entry.cFileName, name))) allowed = TRUE;
                }
            }
            if (!allowed || (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                error = ERROR_INVALID_DATA; break;
            }
        } while (FindNextFileW(search, &entry));
        if (!error && GetLastError() != ERROR_NO_MORE_FILES) error = GetLastError();
        FindClose(search);
        if (error) return error;
    }
    return 0;
}

static DWORD open_payload(const WCHAR *directory, const BYTE expectedHash[32],
                       DWORD protocol, DWORD driverVersion, PB_VERIFIED_PAYLOAD *payload, BOOL cleanup)
{
    if (!payload) return ERROR_INVALID_PARAMETER;
    ZeroMemory(payload, sizeof(*payload));
    if (!directory || !*directory || !expectedHash || !protocol || !driverVersion)
        return ERROR_INVALID_PARAMETER;
    DWORD error = lock_payload_path(directory, payload, TRUE);
    if (error != ERROR_SUCCESS) { pb_payload_close(payload); return error; }
    // Open every fixed-name file first. No relative names from the manifest are
    // ever used as paths. Final-component links/directories are rejected.
    for (unsigned i = 0; i < ARRAYSIZE(payload->files); ++i) {
        WCHAR path[MAX_PATH];
        if (swprintf_s(path, MAX_PATH, L"%s\\%s", directory, fileNames[i]) < 0) {
            error = ERROR_FILENAME_EXCED_RANGE; break;
        }
        HANDLE file = CreateFileW(path, GENERIC_READ | (cleanup && i < PB_PAYLOAD_FILES ? DELETE : 0), FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            // Only already-removed payload files may be absent. The manifest
            // remains mandatory and is deleted last by the cleanup coordinator.
            if (cleanup && i < PB_PAYLOAD_FILES && error == ERROR_FILE_NOT_FOUND) { error = 0; continue; }
            break;
        }
        payload->files[i] = file;
        FILE_ATTRIBUTE_TAG_INFO attributes;
        if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes))) {
            error = GetLastError(); break;
        }
        if (GetFileType(file) != FILE_TYPE_DISK ||
            attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) {
            error = ERROR_INVALID_DATA; break;
        }
    }
    HANDLE manifestFile = payload->files[PB_PAYLOAD_FILES];
    BYTE digest[32];
    LARGE_INTEGER size = {0};
    if (error == ERROR_SUCCESS && !GetFileSizeEx(manifestFile, &size)) error = GetLastError();
    if (error == ERROR_SUCCESS && size.QuadPart != sizeof(payload->manifest)) error = ERROR_INVALID_DATA;
    if (error == ERROR_SUCCESS) error = hash_file(manifestFile, digest);
    if (error == ERROR_SUCCESS && memcmp(digest, expectedHash, 32)) error = ERROR_CRC;
    if (error == ERROR_SUCCESS) {
        LARGE_INTEGER zero = {0};
        DWORD bytes;
        if (!SetFilePointerEx(manifestFile, zero, NULL, FILE_BEGIN) ||
            !ReadFile(manifestFile, &payload->manifest, sizeof(payload->manifest), &bytes, NULL))
            error = GetLastError();
        else if (bytes != sizeof(payload->manifest)) error = ERROR_INVALID_DATA;
    }
    const PB_PAYLOAD_MANIFEST *manifest = &payload->manifest;
    if (error == ERROR_SUCCESS && (manifest->magic != PB_MANIFEST_MAGIC || manifest->format != 1 ||
        manifest->size != sizeof(*manifest) || manifest->protocol != protocol || manifest->driverVersion != driverVersion))
        error = ERROR_REVISION_MISMATCH;
    for (unsigned i = 0; error == ERROR_SUCCESS && i < PB_PAYLOAD_FILES; ++i) {
        if (cleanup && !payload->files[i]) continue;
        error = hash_file(payload->files[i], digest);
        if (error == ERROR_SUCCESS && memcmp(digest, manifest->hashes[i], 32)) error = ERROR_CRC;
    }
    if (error != ERROR_SUCCESS) pb_payload_close(payload);
    return error;
}

DWORD pb_payload_open(const WCHAR *directory, const BYTE expectedHash[32],
                       DWORD protocol, DWORD driverVersion, PB_VERIFIED_PAYLOAD *payload)
{
    return open_payload(directory, expectedHash, protocol, driverVersion, payload, FALSE);
}

DWORD pb_payload_open_remaining(const WCHAR *directory, const BYTE expectedHash[32],
                       DWORD protocol, DWORD driverVersion, PB_VERIFIED_PAYLOAD *payload)
{
    DWORD error = open_payload(directory, expectedHash, protocol, driverVersion, payload, TRUE);
    if (!error) error = pb_payload_check_inventory(directory);
    if (error) pb_payload_close(payload);
    return error;
}
