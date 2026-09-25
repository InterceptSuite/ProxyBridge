#include "../install-stage.h"
#include <shlobj.h>
#include <stdio.h>
#include <wchar.h>
static const WCHAR *testDirectory;
static HRESULT test_folder(HWND w, int id, HANDLE token, DWORD flags, LPWSTR path)
{
    (void)w; (void)token; (void)flags;
    if (id != CSIDL_COMMON_APPDATA) return E_INVALIDARG;
    return wcscpy_s(path, MAX_PATH, testDirectory) ? E_FAIL : S_OK;
}
// Only location resolution changes; directory open/create and ACL checks are
// actual Windows calls. The caller supplies a fresh isolated test directory.
#define SHGetFolderPathW test_folder
#include "../install-stage.c"
int wmain(int argc, WCHAR **argv)
{
    if (argc != 2 && argc != 3) return 1;
    testDirectory = argv[1];
    if (argc == 3) {
        if (wcscmp(argv[2], L"--positive")) return 1;
        PB_VERIFIED_PAYLOAD first = {0}, second = {0};
        HANDLE firstRoot = NULL, secondRoot = NULL;
        const WCHAR *hash = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        DWORD error = pb_bootstrap_root_open(hash, &first, &firstRoot);
        if (error) { printf("Create failed: %lu\n", error); return 1; }
        error = pb_bootstrap_root_open(hash, &second, &secondRoot);
        if (error) { printf("Reopen failed: %lu\n", error); pb_payload_close(&first); return 1; }
        BY_HANDLE_FILE_INFORMATION a, b;
        BOOL same = GetFileInformationByHandle(firstRoot, &a) && GetFileInformationByHandle(secondRoot, &b) &&
            a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
        pb_payload_close(&second); pb_payload_close(&first);
        if (!same) return 1;
        puts("Elevated bootstrap create/reopen identity and production ACL checks passed. Fixture retained.");
        return 0;
    }
    WCHAR product[MAX_PATH], bootstrap[MAX_PATH];
    if (swprintf_s(product, MAX_PATH, L"%s\\InterceptSuite.ProxyBridge", testDirectory) < 0 ||
        swprintf_s(bootstrap, MAX_PATH, L"%s\\bootstrap", product) < 0) return 1;
    // A pre-existing directory with inherited permissions is not trusted and
    // must not be silently repaired or used for persistent executable files.
    if (!CreateDirectoryW(product, NULL)) return 1;
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
    DWORD error = pb_bootstrap_root_open(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &guard, &root);
    if (error != ERROR_ACCESS_DENIED || root || guard.directoryCount ||
        GetFileAttributesW(bootstrap) != INVALID_FILE_ATTRIBUTES) {
        printf("Unexpected result %lu\n", error); return 1;
    }
    puts("Actual Windows bootstrap path rejected inherited ACL; no child created. Fixture retained.");
    return 0;
}
