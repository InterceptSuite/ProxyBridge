#pragma once
#include <windows.h>
// Caller holds the installation mutex. Sources come from the trusted installer
// extraction; this checks identity on retries, not Authenticode trust.
DWORD pb_bootstrap_publish(const WCHAR *source, const WCHAR *hash);
