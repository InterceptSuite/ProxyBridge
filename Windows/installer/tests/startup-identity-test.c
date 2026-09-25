#include "../startup-identity.h"
#include <stdio.h>
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    const WCHAR *root = L"C:\\ProgramData";
    WCHAR path[MAX_PATH], changed[MAX_PATH];
    const WCHAR *hash = L"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
    swprintf_s(path, MAX_PATH, L"%s\\InterceptSuite.ProxyBridge\\bootstrap\\%s\\ProxyBridgeLauncher.exe", root, hash);
    CHECK(pb_startup_launcher_path(root, path));
    CHECK(pb_startup_launcher_path(L"c:\\programdata", path));
    CHECK(pb_startup_task_owned(root, PB_STARTUP_TASK_URI, 1, path, PB_STARTUP_ARGUMENTS));
    CHECK(!pb_startup_task_owned(root, L"ProxyBridge", 1, path, PB_STARTUP_ARGUMENTS));
    CHECK(!pb_startup_task_owned(root, NULL, 1, path, PB_STARTUP_ARGUMENTS));
    CHECK(!pb_startup_task_owned(root, PB_STARTUP_TASK_URI, 0, path, PB_STARTUP_ARGUMENTS));
    CHECK(!pb_startup_task_owned(root, PB_STARTUP_TASK_URI, 2, path, PB_STARTUP_ARGUMENTS));
    CHECK(!pb_startup_task_owned(root, PB_STARTUP_TASK_URI, 1, path, L"--minimized --extra"));
    CHECK(!pb_startup_task_owned(root, PB_STARTUP_TASK_URI, 1, path, NULL));
    const WCHAR *badRoots[] = {L"", L"C:\\", L"C:relative", L"\\\\server\\share", L"C:\\ProgramData\\",
        L"C:\\..\\ProgramData", L"C:\\ProgramData ", L"C:\\ProgramData.", L"C:\\bad:root", L"C:/ProgramData"};
    for (unsigned i = 0; i < ARRAYSIZE(badRoots); ++i) CHECK(!pb_startup_launcher_path(badRoots[i], path));
    CHECK(!pb_startup_launcher_path(NULL, path)); CHECK(!pb_startup_launcher_path(root, NULL));
    wcscpy_s(changed, MAX_PATH, path); changed[0] = L'D'; CHECK(!pb_startup_launcher_path(root, changed));
    wcscpy_s(changed, MAX_PATH, path); wcscat_s(changed, MAX_PATH, L":stream"); CHECK(!pb_startup_launcher_path(root, changed));
    wcscpy_s(changed, MAX_PATH, path); wcscat_s(changed, MAX_PATH, L".exe"); CHECK(!pb_startup_launcher_path(root, changed));
    wcscpy_s(changed, MAX_PATH, path); wcscat_s(changed, MAX_PATH, L" "); CHECK(!pb_startup_launcher_path(root, changed));
    WCHAR *leaf = wcsstr(path, hash); CHECK(leaf != NULL);
    size_t offset = (size_t)(leaf - path);
    for (size_t i = 0; i < 64; ++i) {
        wcscpy_s(changed, MAX_PATH, path); changed[offset+i] = L'G';
        CHECK(!pb_startup_launcher_path(root, changed));
    }
    swprintf_s(changed, MAX_PATH, L"%s\\InterceptSuite.ProxyBridge\\bootstrap\\%s\\ProxyBridge.exe", root, hash);
    CHECK(!pb_startup_launcher_path(root, changed));
    swprintf_s(changed, MAX_PATH, L"%s\\InterceptSuite.ProxyBridge\\versions\\%s\\ProxyBridgeLauncher.exe", root, hash);
    CHECK(!pb_startup_launcher_path(root, changed));
    puts("PASS startup identity: marker/actions/arguments, canonical bootstrap boundary, all 64 hash positions");
    return 0;
}
