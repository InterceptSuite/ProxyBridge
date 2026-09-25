#include "startup-task.h"
#include "startup-identity.h"

DWORD pb_startup_dispatch(const PB_STARTUP_BACKEND *backend, PB_STARTUP_OPERATION operation,
                          const WCHAR *programData, const WCHAR *launcher, BOOL *enabled)
{
    if (enabled) *enabled = FALSE;
    if (!backend || !backend->read || !backend->write || !enabled ||
        operation < PB_STARTUP_QUERY || operation > PB_STARTUP_REMOVE) return ERROR_INVALID_PARAMETER;
    PB_STARTUP_SNAPSHOT state = {0};
    DWORD error = backend->read(backend->context, &state);
    if (error) return error;
    if (state.exists && !state.owned) return ERROR_ACCESS_DENIED;
    *enabled = state.exists && state.enabled;
    if (operation == PB_STARTUP_QUERY) return ERROR_SUCCESS;
    if (!state.exists && operation != PB_STARTUP_ENABLE) return ERROR_SUCCESS;
    if ((operation == PB_STARTUP_ENABLE || operation == PB_STARTUP_RETARGET) &&
        !pb_startup_launcher_path(programData, launcher)) return ERROR_INVALID_NAME;
    error = backend->write(backend->context, operation, !state.exists, launcher);
    if (error) return error; // Keep the observed state; never claim mutation success.
    if (operation == PB_STARTUP_ENABLE) *enabled = TRUE;
    if (operation == PB_STARTUP_DISABLE || operation == PB_STARTUP_REMOVE) *enabled = FALSE;
    return ERROR_SUCCESS;
}
