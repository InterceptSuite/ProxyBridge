// Included by install-stage.c to share protected_folder_open/check_root.
// Fixed inventories only: no recursive traversal, no paths from registry.
static DWORD flat_cleanup_leaf(const WCHAR *path, BOOL bootstrap)
{
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE files[PB_PAYLOAD_FILES + 3] = {0};
    DWORD error = pb_payload_lock_directory(path, &guard);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 0;
    PSECURITY_DESCRIPTOR expected = NULL;
    if (!error && !ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &expected, NULL)) error = GetLastError();
    if (!error) error = check_root(guard.directories[guard.directoryCount - 1], expected);
    WCHAR driver[MAX_PATH];
    if (swprintf_s(driver, MAX_PATH, L"%s\\driver", path) < 0) error = ERROR_FILENAME_EXCED_RANGE;
    BOOL driverExists = FALSE;
    if (!error && !bootstrap) {
        DWORD attributes = GetFileAttributesW(driver);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) error = ERROR_INVALID_NAME;
            else {
                HANDLE directory = CreateFileW(driver, FILE_LIST_DIRECTORY | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
                if (directory == INVALID_HANDLE_VALUE) error = GetLastError();
                else {
                    // Older stage directories are protected; new driver directories are too.
                    error = check_root(directory, expected);
                    if (error || guard.directoryCount == ARRAYSIZE(guard.directories)) CloseHandle(directory);
                    else { guard.directories[guard.directoryCount++] = directory; driverExists = TRUE; }
                }
            }
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) error = GetLastError();
    }
    for (unsigned level = 0; !error && level < (driverExists ? 2u : 1u); ++level) {
        WCHAR pattern[MAX_PATH];
        if (swprintf_s(pattern, MAX_PATH, L"%s\\*", level ? driver : path) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
        WIN32_FIND_DATAW entry; HANDLE search = FindFirstFileW(pattern, &entry);
        if (search == INVALID_HANDLE_VALUE) { error = GetLastError(); if (error == ERROR_FILE_NOT_FOUND) error = 0; continue; }
        do {
            if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
            if (!level && driverExists && !wcscmp(entry.cFileName, L"driver")) continue;
            WCHAR relative[MAX_PATH], full[MAX_PATH];
            if (swprintf_s(relative, MAX_PATH, L"%s%s", level ? L"driver\\" : L"", entry.cFileName) < 0) { error = ERROR_INVALID_NAME; break; }
            unsigned slot;
            for (slot = 0; slot < ARRAYSIZE(files); ++slot) {
                const WCHAR *name = slot <= PB_PAYLOAD_FILES ? pb_payload_file_name(slot) :
                    slot == PB_PAYLOAD_FILES + 1 ? L"ProxyBridgeLauncher.exe" : L"uninstall.exe";
                if (!_wcsicmp(relative, name)) break;
            }
            if (slot == ARRAYSIZE(files) || files[slot] || (bootstrap && slot != 3 && slot < PB_PAYLOAD_FILES + 1) ||
                (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
                wprintf(L"CleanupBlocked=%s\\%s\n", path, relative); error = ERROR_INVALID_DATA; break;
            }
            if (swprintf_s(full, MAX_PATH, L"%s\\%s", path, relative) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
            HANDLE file = CreateFileW(full, DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (file == INVALID_HANDLE_VALUE) { error = GetLastError(); break; }
            files[slot] = file;
            BY_HANDLE_FILE_INFORMATION info; PSECURITY_DESCRIPTOR descriptor = NULL;
            if (!GetFileInformationByHandle(file, &info)) error = GetLastError();
            if (!error && ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks != 1)) error = ERROR_INVALID_NAME;
            if (!error) error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                NULL, NULL, NULL, NULL, &descriptor);
            if (!error) error = pb_startup_file_security(descriptor);
            if (descriptor) LocalFree(descriptor);
            if (error) break;
        } while (FindNextFileW(search, &entry));
        if (!error && GetLastError() != ERROR_NO_MORE_FILES) error = GetLastError();
        FindClose(search);
    }
    // Inventory and all file identities validated before deleting any byte.
    for (unsigned i = 0; !error && i < ARRAYSIZE(files); ++i) if (files[i]) {
        FILE_DISPOSITION_INFO remove = {TRUE};
        if (!SetFileInformationByHandle(files[i], FileDispositionInfo, &remove, sizeof(remove))) error = GetLastError();
    }
    for (unsigned i = 0; i < ARRAYSIZE(files); ++i) if (files[i]) CloseHandle(files[i]);
    // Keep the product/branch parent pinned in the caller while removing these
    // now-empty directories. No recursive delete and no delayed delete at reboot.
    pb_payload_close(&guard); if (expected) LocalFree(expected);
    if (!error && driverExists && !RemoveDirectoryW(driver)) error = GetLastError();
    if (!error && !RemoveDirectoryW(path)) error = GetLastError();
    return error;
}

DWORD pb_product_remove_files(void)
{
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
    DWORD error = protected_folder_open(CSIDL_PROGRAM_FILES, L"\\InterceptSuite", &guard, &root, NULL, NULL, FALSE);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 0;
    WCHAR path[MAX_PATH];
    if (!error) {
        WCHAR raw[MAX_PATH]; DWORD n = GetFinalPathNameByHandleW(root, raw, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n < 7 || n >= MAX_PATH || wcsncmp(raw, L"\\\\?\\", 4)) error = ERROR_INVALID_NAME;
        else if (swprintf_s(path, MAX_PATH, L"%s\\ProxyBridge", raw + 4) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        else error = flat_cleanup_leaf(path, FALSE);
    }
    pb_payload_close(&guard); return error;
}

DWORD pb_product_legacy_cleanup(void)
{
    for (unsigned kind = 0; kind < 3; ++kind) {
        PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
        DWORD error = kind == 0 ? protected_folder_open(CSIDL_PROGRAM_FILES, L"\\InterceptSuite", &guard, &root, L"\\ProxyBridge", L"\\versions", FALSE) :
            protected_folder_open(CSIDL_COMMON_APPDATA, L"\\InterceptSuite.ProxyBridge", &guard, &root, kind == 1 ? L"\\versions" : L"\\bootstrap", NULL, FALSE);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) continue;
        if (error) return error;
        WCHAR raw[MAX_PATH], pattern[MAX_PATH];
        DWORD n = GetFinalPathNameByHandleW(root, raw, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n < 7 || n >= MAX_PATH || wcsncmp(raw, L"\\\\?\\", 4)) error = ERROR_INVALID_NAME;
        if (!error && swprintf_s(pattern, MAX_PATH, L"%s\\*", raw + 4) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        WIN32_FIND_DATAW entry; HANDLE scan = error ? INVALID_HANDLE_VALUE : FindFirstFileW(pattern, &entry);
        if (!error && scan == INVALID_HANDLE_VALUE) { error = GetLastError(); if (error == ERROR_FILE_NOT_FOUND) error = 0; }
        if (scan != INVALID_HANDLE_VALUE) {
            do {
                if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
                BOOL valid = FALSE;
                if (kind == 2) {
                    valid = wcslen(entry.cFileName) == 64;
                    for (unsigned i = 0; valid && i < 64; ++i) {
                        WCHAR c = entry.cFileName[i];
                        valid = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
                    }
                } else {
                    GUID id; WCHAR canonical[40];
                    valid = SUCCEEDED(CLSIDFromString(entry.cFileName, &id)) && StringFromGUID2(&id, canonical, ARRAYSIZE(canonical)) && !_wcsicmp(canonical, entry.cFileName);
                }
                if (!valid || !(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { error = ERROR_INVALID_DATA; break; }
                WCHAR path[MAX_PATH];
                if (swprintf_s(path, MAX_PATH, L"%s\\%s", raw + 4, entry.cFileName) < 0) { error = ERROR_FILENAME_EXCED_RANGE; break; }
                error = flat_cleanup_leaf(path, kind == 2); if (error) break;
            } while (FindNextFileW(scan, &entry));
            if (!error && GetLastError() != ERROR_NO_MORE_FILES) error = GetLastError();
            FindClose(scan);
        }
        if (!error) {
            // Release only the branch handle; its ancestors remain pinned.
            CloseHandle(guard.directories[--guard.directoryCount]);
            if (!RemoveDirectoryW(raw + 4)) error = GetLastError();
        }
        pb_payload_close(&guard); if (error) return error;
    }
    return 0;
}
