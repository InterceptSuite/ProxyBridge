#include "../launch-command.h"
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

int main(void)
{
    const WCHAR *arguments[] = {L"C:\\Program Files\\ProxyBridge.exe", L"", L"plain", L"two words",
        L"quoted\"value", L"C:\\ends with slash\\", L"\\\\\"", L"профиль.pbprofile", L"&|>%PATH%"};
    WCHAR *command = NULL;
    if (pb_launch_command(ARRAYSIZE(arguments), arguments, &command)) return 1;
    int count = 0;
    WCHAR **decoded = CommandLineToArgvW(command, &count);
    if (!decoded || count != ARRAYSIZE(arguments)) return 1;
    for (int i = 0; i < count; ++i) if (wcscmp(arguments[i], decoded[i])) return 1;
    LocalFree(decoded); HeapFree(GetProcessHeap(), 0, command);
    WCHAR *large = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 33000 * sizeof(WCHAR));
    if (!large) return 1;
    for (unsigned i = 0; i < 32999; ++i) large[i] = L'x';
    const WCHAR *oversize[] = {L"program.exe", large};
    DWORD result = pb_launch_command(2, oversize, &command);
    HeapFree(GetProcessHeap(), 0, large);
    if (result != ERROR_FILENAME_EXCED_RANGE || command) return 1;
    puts("Launch argument roundtrip and length checks passed; no application launched.");
    return 0;
}
