#include "../install-overwrite.h"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
static WCHAR programs[MAX_PATH], dataRoot[MAX_PATH];
static BOOL denySecurity;
static int failCopy = -1;
static HRESULT fixture_folder(HWND w, int id, HANDLE token, DWORD flags, LPWSTR out) {
    (void)w; (void)token; (void)flags;
    const WCHAR *path = id == CSIDL_PROGRAM_FILES ? programs : id == CSIDL_COMMON_APPDATA ? dataRoot : NULL;
    return path && !wcscpy_s(out, MAX_PATH, path) ? S_OK : E_FAIL;
}
static DWORD fixture_security(HANDLE h, SE_OBJECT_TYPE t, SECURITY_INFORMATION f,
    PSID *o, PSID *g, PACL *d, PACL *s, PSECURITY_DESCRIPTOR *out) {
    (void)h; (void)t; (void)f; (void)g; (void)s;
    if (denySecurity) return ERROR_ACCESS_DENIED;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1, out, NULL)) return GetLastError();
    BOOL present, defaulted;
    if (o) GetSecurityDescriptorOwner(*out, o, &defaulted);
    if (d) GetSecurityDescriptorDacl(*out, &present, d, &defaulted);
    return 0;
}
static BOOL WINAPI fixture_create(LPCWSTR path, LPSECURITY_ATTRIBUTES attributes) {
    (void)attributes; return CreateDirectoryW(path, NULL);
}
#define SHGetFolderPathW fixture_folder
#define GetSecurityInfo fixture_security
#define CreateDirectoryW fixture_create
#include "../install-stage.c"
static DWORD fixture_copy(HANDLE source, HANDLE target) {
    if (!failCopy) return ERROR_DISK_FULL;
    if (failCopy > 0) --failCopy;
    return pb_stage_copy_file(source, target);
}
#define pb_stage_copy_file fixture_copy
#include "../install-overwrite.c"
#undef pb_stage_copy_file
// ACL retrieval is adapted above; production descriptor validation is tested
// separately by startup-installed-security-test. Never touches the real roots.
DWORD pb_startup_file_security(PSECURITY_DESCRIPTOR descriptor) { return descriptor ? 0 : ERROR_ACCESS_DENIED; }
#define CHECK(x) do {if (!(x)) {printf("FAIL %d: %s (%lu)\n", __LINE__, #x, GetLastError()); return 1;}} while(0)
static void hash_parse(const WCHAR *text, BYTE hash[32]) {
    for (unsigned i = 0; i < 32; ++i) { unsigned x = 0; swscanf_s(text + i * 2, L"%2x", &x); hash[i] = (BYTE)x; }
}
static DWORD overwrite(PB_VERIFIED_PAYLOAD *source, BYTE hash[32]) {
    return pb_product_overwrite(source, source->files[0], source->files[1], hash);
}
static DWORD verify(const WCHAR *directory, PB_VERIFIED_PAYLOAD *source, BYTE hash[32]) {
    PB_VERIFIED_PAYLOAD output = {0};
    DWORD error = pb_payload_open(directory, hash, source->manifest.protocol, source->manifest.driverVersion, &output);
    pb_payload_close(&output); return error;
}
int wmain(int argc, WCHAR **argv) {
    CHECK(argc == 6);
    CHECK(swprintf_s(programs, MAX_PATH, L"%s\\Program Files", argv[1]) > 0);
    CHECK(CreateDirectoryW(programs, NULL));
    CHECK(swprintf_s(dataRoot, MAX_PATH, L"%s\\ProgramData", argv[1]) > 0);
    CHECK(CreateDirectoryW(dataRoot, NULL));
    PB_PRODUCT_LAYOUT layout;
    CHECK(!pb_product_layout(programs, &layout));
    CHECK(pb_product_layout(L"C:\\Program Files\\..", &layout) == ERROR_INVALID_NAME);
    CHECK(pb_product_layout(L"C:\\Program Files\\", &layout) == ERROR_INVALID_NAME);
    CHECK(pb_product_layout(L"\\\\server\\share", &layout) == ERROR_INVALID_NAME);
    CHECK(pb_product_layout(L"C:\\bad//path", &layout) == ERROR_INVALID_NAME);
    CHECK(!pb_product_layout(programs, &layout));
    BYTE hashA[32], hashB[32]; hash_parse(argv[3], hashA); hash_parse(argv[5], hashB);
    PB_VERIFIED_PAYLOAD a = {0}, b = {0};
    CHECK(!pb_payload_open(argv[2], hashA, 4, 65537, &a));
    CHECK(!pb_payload_open(argv[4], hashB, 4, 65537, &b));
    CHECK(!overwrite(&a, hashA)); CHECK(!verify(layout.application, &a, hashA));
    // A sharing collision anywhere is detected before any old file is truncated.
    WCHAR file[MAX_PATH];
    swprintf_s(file, MAX_PATH, L"%s\\ProxyBridgeCore.dll", layout.application);
    HANDLE busy = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(busy != INVALID_HANDLE_VALUE);
    CHECK(overwrite(&b, hashB) == ERROR_SHARING_VIOLATION); CloseHandle(busy);
    CHECK(!verify(layout.application, &a, hashA));
    denySecurity = TRUE; CHECK(overwrite(&b, hashB) == ERROR_ACCESS_DENIED); denySecurity = FALSE;
    CHECK(!verify(layout.application, &a, hashA));
    CHECK(!overwrite(&b, hashB)); CHECK(!verify(layout.application, &b, hashB));
    CHECK(!overwrite(&b, hashB)); // Same-version reinstall is idempotent.
    for (int i = 0; i < PRODUCT_FILE_COUNT; ++i) {
        CHECK(!overwrite(&a, hashA)); failCopy = i;
        CHECK(overwrite(&b, hashB) == ERROR_DISK_FULL); failCopy = -1;
        CHECK(!overwrite(&b, hashB)); CHECK(!verify(layout.application, &b, hashB));
    }
    // Hardlink aliases must not let an installer truncate a different file.
    WCHAR alias[MAX_PATH]; swprintf_s(alias, MAX_PATH, L"%s\\outside.dll", argv[1]);
    CHECK(CreateHardLinkW(alias, file, NULL));
    CHECK(overwrite(&a, hashA) == ERROR_INVALID_NAME);
    CHECK(!verify(layout.application, &b, hashB)); CHECK(DeleteFileW(alias));
    // Only the ten product files and driver directory; no historical copies.
    WCHAR pattern[MAX_PATH]; swprintf_s(pattern, MAX_PATH, L"%s\\*", layout.application);
    WIN32_FIND_DATAW entry; HANDLE scan = FindFirstFileW(pattern, &entry); CHECK(scan != INVALID_HANDLE_VALUE);
    unsigned files = 0, dirs = 0;
    do {
        if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { CHECK(!wcscmp(entry.cFileName, L"driver")); ++dirs; }
        else ++files;
    } while (FindNextFileW(scan, &entry));
    CHECK(GetLastError() == ERROR_NO_MORE_FILES); FindClose(scan);
    CHECK(dirs == 1 && files == PRODUCT_FILE_COUNT - 3);
    // Migration deletes only exact product inventories inside canonical old
    // GUID/hash directories. Unknown files block that leaf before any deletion.
    PB_VERIFIED_PAYLOAD old = {0}; HANDLE oldRoot = NULL;
    CHECK(!pb_stage_root_open(&old, &oldRoot));
    WCHAR legacy[MAX_PATH], legacyDriver[MAX_PATH], input[MAX_PATH], output[MAX_PATH];
    GUID id = {123,0,0,{0}};
    CHECK(!pb_stage_target_path(oldRoot, &id, legacy)); CHECK(CreateDirectoryW(legacy, NULL));
    swprintf_s(legacyDriver, MAX_PATH, L"%s\\driver", legacy); CHECK(CreateDirectoryW(legacyDriver, NULL));
    for (unsigned i = 0; i <= PB_PAYLOAD_FILES; ++i) {
        swprintf_s(input, MAX_PATH, L"%s\\%s", argv[4], pb_payload_file_name(i));
        swprintf_s(output, MAX_PATH, L"%s\\%s", legacy, pb_payload_file_name(i));
        CHECK(CopyFileW(input, output, TRUE));
    }
    swprintf_s(output, MAX_PATH, L"%s\\foreign.txt", legacy);
    swprintf_s(input, MAX_PATH, L"%s\\ProxyBridge.exe", argv[4]); CHECK(CopyFileW(input, output, TRUE));
    pb_payload_close(&old);
    CHECK(pb_product_legacy_cleanup() == ERROR_INVALID_DATA);
    CHECK(!verify(legacy, &b, hashB)); CHECK(DeleteFileW(output));
    const WCHAR *bootstrapHash = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    CHECK(!pb_bootstrap_root_open(bootstrapHash, &old, &oldRoot));
    const WCHAR *supportNames[] = {L"ProxyBridgeDriverSetup.exe", L"ProxyBridgeLauncher.exe", L"uninstall.exe"};
    for (unsigned i = 0; i < ARRAYSIZE(supportNames); ++i) {
        swprintf_s(output, MAX_PATH, L"%s\\InterceptSuite.ProxyBridge\\bootstrap\\%s\\%s", dataRoot, bootstrapHash, supportNames[i]);
        CHECK(CopyFileW(input, output, TRUE));
    }
    pb_payload_close(&old);
    CHECK(!pb_product_legacy_cleanup()); CHECK(GetFileAttributesW(legacy) == INVALID_FILE_ATTRIBUTES);
    CHECK(GetFileAttributesW(output) == INVALID_FILE_ATTRIBUTES); CHECK(!pb_product_legacy_cleanup());
    CHECK(!verify(layout.application, &b, hashB)); // Migration did not delete current files.
    busy = CreateFileW(layout.uninstaller, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(busy != INVALID_HANDLE_VALUE); CHECK(pb_product_remove_files() == ERROR_SHARING_VIOLATION); CloseHandle(busy);
    CHECK(!verify(layout.application, &b, hashB));
    CHECK(!pb_product_remove_files()); CHECK(GetFileAttributesW(layout.application) == INVALID_FILE_ATTRIBUTES);
    CHECK(!pb_product_remove_files()); CHECK(!overwrite(&b, hashB)); CHECK(!verify(layout.application, &b, hashB));
    pb_payload_close(&a); pb_payload_close(&b);
    puts("PASS fixed path, overwrite/retry, locks/ACL/hardlink refusal, migration of old versions/bootstrap with foreign-file refusal, removal/reinstall, no retained versions. Real files; known-folder and security adapters.");
    return 0;
}
