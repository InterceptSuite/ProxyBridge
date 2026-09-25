#pragma once
#include <windows.h>
// Read-only orphan service gate. Absence is allowed; an existing kernel service
// is adoptable only when its protected Windows image matches the signed input.
DWORD pb_flat_service_check(HANDLE expectedDriver);
DWORD pb_flat_service_removal_pending(void);
