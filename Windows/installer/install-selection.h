#pragma once
#include "install-journal.h"

typedef struct PB_APP_SELECTION {
    DWORD protocol, driverVersion;
    WCHAR directory[MAX_PATH];
    BYTE manifestHash[32];
} PB_APP_SELECTION;

// The terminal journal record is also the active-version pointer. No separate
// registry value can get out of sync with transaction completion.
DWORD pb_select_application(const PB_INSTALL_JOURNAL *record, PB_APP_SELECTION *selection);
