#pragma once
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum PB_STARTUP_OPERATION {
    PB_STARTUP_QUERY, PB_STARTUP_ENABLE, PB_STARTUP_DISABLE,
    PB_STARTUP_RETARGET, PB_STARTUP_REMOVE
} PB_STARTUP_OPERATION;

// Mutating callers MUST own the native installation mutex and retain
// verified bootstrap directory/file handles. programData is the canonical OS
// location. This adapter does not authenticate an executable from its path.
// RETARGET preserves enabled state and never creates a missing task.
// On failure enabled is only the last observed state; registration may have
// partially succeeded. Re-query before deciding recovery or reporting state.
DWORD pb_startup_task_apply(PB_STARTUP_OPERATION operation, const WCHAR *programData,
                            const WCHAR *launcher, BOOL *enabled);

typedef struct PB_STARTUP_SNAPSHOT {
    BOOL exists, owned, enabled;
} PB_STARTUP_SNAPSHOT;
typedef struct PB_STARTUP_BACKEND {
    void *context;
    DWORD (*read)(void *, PB_STARTUP_SNAPSHOT *);
    DWORD (*write)(void *, PB_STARTUP_OPERATION, BOOL create, const WCHAR *launcher);
} PB_STARTUP_BACKEND;
// Shared dispatch used by the native COM adapter and fault-injection tests.
DWORD pb_startup_dispatch(const PB_STARTUP_BACKEND *backend, PB_STARTUP_OPERATION operation,
                          const WCHAR *programData, const WCHAR *launcher, BOOL *enabled);
#ifdef __cplusplus
}
#endif
