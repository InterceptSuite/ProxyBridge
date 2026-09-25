#pragma once
#include <windows.h>

// Returns a HeapAlloc buffer for CreateProcessW; caller uses HeapFree.
DWORD pb_launch_command(int argc, const WCHAR *const *argv, WCHAR **command);
