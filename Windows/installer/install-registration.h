#pragma once
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif
// Caller owns the installation mutex; operation1 publishes application
// registration, operation2 removes it, operation0 publishes recovery only.
// Hash is trusted installer metadata, already bound to the journal by caller
// for operations1/2. This module never mutates the driver or starts a task.
DWORD pb_registration_apply(const WCHAR *hash, unsigned operation);
DWORD pb_registration_flat(BOOL remove);
#ifdef __cplusplus
}
#endif
