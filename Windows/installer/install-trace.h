#pragma once
#include <windows.h>
#include <stdio.h>

// Stable stage identifiers are captured by NSIS. Do not include user data,
// credentials or arbitrary file contents. Preserve the original return code.
static __inline DWORD pb_install_trace(const WCHAR *stage, DWORD result)
{
    wprintf(L"SetupStep=%s Result=%lu (0x%08lX)\n", stage, result, result);
    fflush(stdout);
    return result;
}
