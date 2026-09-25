#include "launch-command.h"
#include <wchar.h>

DWORD pb_launch_command(int argc, const WCHAR *const *argv, WCHAR **command)
{
    if (!command) return ERROR_INVALID_PARAMETER;
    *command = NULL;
    if (argc < 1 || !argv) return ERROR_INVALID_PARAMETER;
    WCHAR *buffer = HeapAlloc(GetProcessHeap(), 0, 32767 * sizeof(WCHAR));
    if (!buffer) return ERROR_NOT_ENOUGH_MEMORY;
    size_t used = 0;
#define APPEND(ch) do { if (used >= 32766) goto too_long; buffer[used++] = (ch); } while (0)
    for (int argument = 0; argument < argc; ++argument) {
        if (!argv[argument]) { HeapFree(GetProcessHeap(), 0, buffer); return ERROR_INVALID_PARAMETER; }
        if (argument) APPEND(L' ');
        APPEND(L'"');
        const WCHAR *input = argv[argument];
        while (*input) {
            size_t slashes = 0;
            while (*input == L'\\') { ++slashes; ++input; }
            size_t copies = (*input == L'"' || !*input) ? slashes * 2 : slashes;
            while (copies--) APPEND(L'\\');
            if (!*input) break;
            if (*input == L'"') APPEND(L'\\');
            APPEND(*input++);
        }
        APPEND(L'"');
    }
    buffer[used] = 0;
    *command = buffer;
    return ERROR_SUCCESS;
too_long:
    HeapFree(GetProcessHeap(), 0, buffer);
    return ERROR_FILENAME_EXCED_RANGE;
#undef APPEND
}
