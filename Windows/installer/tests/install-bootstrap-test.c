#include "../install-bootstrap.h"
#include "../install-stage.h"
#include "../startup-installed.h"
#include <aclapi.h>
#include <objbase.h>
#include <stdio.h>
static WCHAR destination[MAX_PATH];
static BOOL denySecurity, failCopy;
static unsigned rootCalls;
static DWORD fixture_root(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root)
{
    (void)hash; ++rootCalls;
    DWORD error = pb_payload_lock_directory(destination, guard);
    if (!error) *root = guard->directories[guard->directoryCount - 1];
    return error;
}
static DWORD fixture_security(PSECURITY_DESCRIPTOR descriptor)
{ (void)descriptor; return denySecurity ? ERROR_ACCESS_DENIED : 0; }
static DWORD fixture_copy(HANDLE source, HANDLE target)
{
    if (failCopy) {
        DWORD written; WriteFile(target, "partial", 7, &written, NULL);
        return ERROR_WRITE_FAULT;
    }
    return pb_stage_copy_file(source, target);
}
#define pb_bootstrap_root_open fixture_root
#define pb_startup_file_security fixture_security
#define pb_stage_copy_file fixture_copy
#include "../install-bootstrap.c"
#undef pb_stage_copy_file
#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s (%lu)\n", __LINE__, #x, GetLastError()); return 1; } } while (0)
static BOOL write_fixture(const WCHAR *folder, const WCHAR *name, BYTE value, DWORD size)
{
    WCHAR path[MAX_PATH]; swprintf_s(path, MAX_PATH, L"%s\\%s", folder, name);
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BYTE data[20000]; memset(data, value, sizeof(data));
    DWORD written; BOOL ok = WriteFile(file, data, size, &written, NULL);
    CloseHandle(file); return ok && written == size;
}
int wmain(int argc, WCHAR **argv)
{
    CHECK(argc == 2);
    WCHAR source[MAX_PATH], path[MAX_PATH];
    swprintf_s(source, MAX_PATH, L"%s\\source", argv[1]);
    swprintf_s(destination, MAX_PATH, L"%s\\published", argv[1]);
    CHECK(CreateDirectoryW(source, NULL)); CHECK(CreateDirectoryW(destination, NULL));
    CHECK(write_fixture(source, L"ProxyBridgeDriverSetup.exe", 1, 20000));
    CHECK(write_fixture(source, L"ProxyBridgeLauncher.exe", 2, 20000));
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_FILE_NOT_FOUND && rootCalls == 0);
    CHECK(write_fixture(source, L"uninstall.exe", 3, 20000));
    failCopy = TRUE;
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_WRITE_FAULT);
    swprintf_s(path, MAX_PATH, L"%s\\ProxyBridgeDriverSetup.exe", destination);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    failCopy = FALSE;
    const WCHAR *stale = L"{11111111-1111-1111-1111-111111111111}.bootstrap.tmp";
    const WCHAR *empty = L"{22222222-2222-2222-2222-222222222222}.bootstrap.tmp";
    const WCHAR *busy = L"{33333333-3333-3333-3333-333333333333}.bootstrap.tmp";
    const WCHAR *folder = L"{44444444-4444-4444-4444-444444444444}.bootstrap.tmp";
    CHECK(write_fixture(destination, stale, 4, 7));
    CHECK(write_fixture(destination, empty, 0, 0));
    CHECK(write_fixture(destination, busy, 5, 7));
    CHECK(write_fixture(destination, L"foreign.bootstrap.tmp", 6, 7));
    swprintf_s(path, MAX_PATH, L"%s\\%s", destination, folder);
    CHECK(CreateDirectoryW(path, NULL));
    CHECK(write_fixture(path, L"retained.txt", 7, 7));
    swprintf_s(path, MAX_PATH, L"%s\\%s", destination, busy);
    HANDLE busyFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(busyFile != INVALID_HANDLE_VALUE);
    CHECK(pb_bootstrap_publish(source, L"fixture") == 0);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    CloseHandle(busyFile);
    CHECK(pb_bootstrap_publish(source, L"fixture") == 0);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, MAX_PATH, L"%s\\%s", destination, stale);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, MAX_PATH, L"%s\\%s", destination, empty);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, MAX_PATH, L"%s\\foreign.bootstrap.tmp", destination);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, MAX_PATH, L"%s\\%s\\retained.txt", destination, folder);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, MAX_PATH, L"%s\\ProxyBridgeDriverSetup.exe", destination);
    HANDLE pinned = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(pinned != INVALID_HANDLE_VALUE);
    CHECK(pb_bootstrap_publish(source, L"fixture") == 0); // No overwrite even while in use.
    CHECK(write_fixture(source, L"ProxyBridgeDriverSetup.exe", 9, 20000));
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_CRC);
    BYTE value = 0; DWORD count = 0;
    CHECK(ReadFile(pinned, &value, 1, &count, NULL) && count == 1 && value == 1);
    CloseHandle(pinned);
    CHECK(write_fixture(source, L"ProxyBridgeDriverSetup.exe", 1, 20000));
    denySecurity = TRUE;
    CHECK(write_fixture(destination, stale, 4, 7));
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_ACCESS_DENIED);
    swprintf_s(path, MAX_PATH, L"%s\\%s", destination, stale);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    denySecurity = FALSE;
    CHECK(pb_bootstrap_publish(source, L"fixture") == 0);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    CHECK(write_fixture(source, L"uninstall.exe", 3, 12));
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_CRC);
    CHECK(write_fixture(source, L"uninstall.exe", 3, 0));
    CHECK(pb_bootstrap_publish(source, L"fixture") == ERROR_INVALID_DATA);
    puts("PASS bootstrap: missing/empty source, failed copy retry, multi-buffer identity, pinned immutable files, mismatch/ACL refusal; stale/empty temporary cleanup, busy retry, foreign file/directory preservation, cleanup ACL refusal. Fixture paths/security gate mocked; real file IO.");
    return 0;
}
