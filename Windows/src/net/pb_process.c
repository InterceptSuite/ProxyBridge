#include "pb_internal.h"

// Process resolution. The WFP driver delivers the PID with every redirected connection,
// so there are no owner-PID table scans and no PID cache - only PID -> image name.

BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size)
{
    HANDLE hProcess;
    WCHAR full_path_w[MAX_PATH];
    DWORD path_len = MAX_PATH;

    if (pid == 0)
        return FALSE;

    // PID 4 is the System process (SMB etc.); it can't be opened for a name.
    if (pid == 4)
    {
        strncpy_s(name, name_size, "System", _TRUNCATE);
        return TRUE;
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL)
        return FALSE;

    if (QueryFullProcessImageNameW(hProcess, 0, full_path_w, &path_len))
    {
        // UTF-8 so non-ASCII (e.g. CJK) paths are preserved.
        int converted = WideCharToMultiByte(CP_UTF8, 0, full_path_w, -1, name, (int)name_size, NULL, NULL);
        CloseHandle(hProcess);
        return converted > 0;
    }

    CloseHandle(hProcess);
    return FALSE;
}
