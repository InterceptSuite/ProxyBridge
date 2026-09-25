#include "startup-identity.h"
#include <wchar.h>
#include <shlobj.h>
#include <stdio.h>
#pragma comment(lib,"shell32.lib")

BOOL pb_startup_launcher_path(const WCHAR *programData, const WCHAR *path)
{
    // Fixed layout and legacy bootstrap tasks share the same owned action.
    // The native Program Files location comes from Windows, never metadata.
    WCHAR programs[MAX_PATH], fixed[MAX_PATH];
    if (path && SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, programs)) &&
        wcslen(programs) < MAX_PATH - 60 &&
        swprintf_s(fixed, MAX_PATH, L"%s\\InterceptSuite\\ProxyBridge\\ProxyBridgeLauncher.exe", programs) > 0 &&
        !_wcsicmp(path, fixed)) return TRUE;
    static const WCHAR branch[] = L"\\InterceptSuite.ProxyBridge\\bootstrap\\";
    static const WCHAR file[] = L"\\ProxyBridgeLauncher.exe";
    if (!programData || !path) return FALSE;
    size_t root = wcsnlen_s(programData, MAX_PATH), length = wcsnlen_s(path, MAX_PATH);
    if (root < 3 || root >= MAX_PATH || length >= MAX_PATH ||
        programData[1] != L':' || programData[2] != L'\\' ||
        !((programData[0] >= L'A' && programData[0] <= L'Z') ||
          (programData[0] >= L'a' && programData[0] <= L'z'))) return FALSE;
    // ProgramData comes from Windows, but reject ambiguous inputs explicitly.
    for (size_t i = 3, segment = 3; i <= root; ++i) {
        WCHAR c = programData[i];
        if (c == L'/' || c == L':' || c == L'"' || c == L'*' || c == L'?') return FALSE;
        if (!c || c == L'\\') {
            if (i == segment || programData[i-1] == L'.' || programData[i-1] == L' ') return FALSE;
            segment = i + 1;
        }
    }
    const size_t prefix = root + ARRAYSIZE(branch) - 1;
    if (length != prefix + 64 + ARRAYSIZE(file) - 1 ||
        _wcsnicmp(path, programData, root) ||
        _wcsnicmp(path + root, branch, ARRAYSIZE(branch) - 1) ||
        _wcsicmp(path + prefix + 64, file)) return FALSE;
    for (size_t i = prefix; i < prefix + 64; ++i) {
        WCHAR c = path[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
              (c >= L'A' && c <= L'F'))) return FALSE;
    }
    return TRUE;
}

BOOL pb_startup_task_owned(const WCHAR *programData, const WCHAR *uri,
                          LONG actionCount, const WCHAR *path, const WCHAR *arguments)
{
    return uri && arguments && actionCount == 1 &&
        !wcscmp(uri, PB_STARTUP_TASK_URI) && !wcscmp(arguments, PB_STARTUP_ARGUMENTS) &&
        pb_startup_launcher_path(programData, path);
}
