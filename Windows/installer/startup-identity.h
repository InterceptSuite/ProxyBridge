#pragma once
#include <windows.h>

// The task marker alone is insufficient: also require our single launcher
// action inside the canonical protected bootstrap tree. The caller validates
// directory security and retains the launcher before registering an action.
#define PB_STARTUP_TASK_URI L"urn:InterceptSuite:ProxyBridge:GuiStartup:1"
#define PB_STARTUP_ARGUMENTS L"--minimized"
BOOL pb_startup_launcher_path(const WCHAR *programData, const WCHAR *path);
BOOL pb_startup_task_owned(const WCHAR *programData, const WCHAR *uri,
                          LONG actionCount, const WCHAR *path, const WCHAR *arguments);
