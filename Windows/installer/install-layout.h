#pragma once
#include "install-payload.h"

// One stable installation, overwritten in place. No version/backup/rollback
// directories and no fallback to ProgramData.
typedef struct PB_PRODUCT_LAYOUT {
    WCHAR application[MAX_PATH];
    WCHAR driver[MAX_PATH];
    WCHAR launcher[MAX_PATH];
    WCHAR helper[MAX_PATH];
    WCHAR uninstaller[MAX_PATH];
} PB_PRODUCT_LAYOUT;

// Pure path planning; programFiles is the native x64 known folder, not input
// from InstallLocation or a user-controlled environment variable.
DWORD pb_product_layout(const WCHAR *programFiles, PB_PRODUCT_LAYOUT *layout);
// Returned ancestor handles prevent rename/reparse swaps. Existing roots must
// have the product ACL. Read mode never creates or repairs a missing root.
DWORD pb_product_root_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
DWORD pb_product_driver_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
// Removes only fixed known files below protected product roots. Unknown
// entries/reparse points block cleanup; user data is never recursively erased.
DWORD pb_product_remove_files(void);
DWORD pb_product_legacy_cleanup(void);
