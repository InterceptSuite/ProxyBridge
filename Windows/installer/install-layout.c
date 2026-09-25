#include "install-layout.h"
#include <stdio.h>
#include <wchar.h>

DWORD pb_product_layout(const WCHAR *programFiles, PB_PRODUCT_LAYOUT *layout)
{
    if (!layout) return ERROR_INVALID_PARAMETER;
    ZeroMemory(layout, sizeof(*layout));
    if (!programFiles) return ERROR_INVALID_PARAMETER;
    size_t n = wcsnlen_s(programFiles, MAX_PATH);
    if (n < 4 || n >= MAX_PATH || programFiles[1] != L':' || programFiles[2] != L'\\' ||
        !((programFiles[0] >= L'A' && programFiles[0] <= L'Z') ||
          (programFiles[0] >= L'a' && programFiles[0] <= L'z'))) return ERROR_INVALID_NAME;
    for (size_t i = 3, start = 3; i <= n; ++i) {
        WCHAR c = programFiles[i];
        if (c == L'/' || c == L':' || c == L'"' || c == L'*' || c == L'?' || (c && c < 32))
            return ERROR_INVALID_NAME;
        if (!c || c == L'\\') {
            if (i == start || programFiles[i-1] == L'.' || programFiles[i-1] == L' ')
                return ERROR_INVALID_NAME;
            start = i + 1;
        }
    }
    static const WCHAR suffix[] = L"\\InterceptSuite\\ProxyBridge";
    // Check the longest path before writing any output (MSVC secure printf
    // must not receive an undersized destination).
    if (n + wcslen(suffix) + wcslen(L"\\ProxyBridgeDriverSetup.exe") >= MAX_PATH)
        return ERROR_FILENAME_EXCED_RANGE;
    swprintf_s(layout->application, MAX_PATH, L"%s%s", programFiles, suffix);
    swprintf_s(layout->driver, MAX_PATH, L"%s\\driver", layout->application);
    swprintf_s(layout->launcher, MAX_PATH, L"%s\\ProxyBridgeLauncher.exe", layout->application);
    swprintf_s(layout->helper, MAX_PATH, L"%s\\ProxyBridgeDriverSetup.exe", layout->application);
    swprintf_s(layout->uninstaller, MAX_PATH, L"%s\\uninstall.exe", layout->application);
    return 0;
}
