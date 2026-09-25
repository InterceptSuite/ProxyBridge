#include "install-resume.h"

DWORD pb_resume_install(const PB_INSTALL_STEPS *steps)
{
    if (!steps || !steps->read || !steps->apply || !steps->verifyPending || !steps->publish ||
        !steps->rollback || !steps->restore || !steps->markRollback) return ERROR_INVALID_PARAMETER;
    DWORD previousPhase = 0;
    for (unsigned iteration = 0; iteration < 8; ++iteration) {
        PB_INSTALL_JOURNAL record;
        DWORD error = steps->read(&record);
        if (error) return error;
        // Do not repeat a mutating primitive that reported success without
        // durably advancing the transaction.
        if (record.phase == previousPhase) return ERROR_INVALID_STATE;
        previousPhase = record.phase;
        switch (record.phase) {
        case PB_INSTALL_COMMITTED: return ERROR_SUCCESS;
        case PB_INSTALL_ROLLED_BACK: return record.lastError ? record.lastError : ERROR_INSTALL_FAILURE;
        case PB_INSTALL_PREPARED: error = steps->apply(); break;
        case PB_INSTALL_DRIVER_PENDING: error = steps->verifyPending(); break;
        case PB_INSTALL_DRIVER_VERIFIED: error = steps->publish(); break;
        case PB_INSTALL_DRIVER_CHANGING:
        case PB_INSTALL_APP_CHANGING:
        case PB_INSTALL_ROLLING_BACK:
        case PB_INSTALL_ROLLBACK_PENDING:
        case PB_INSTALL_RECOVERY_REQUIRED:
            error = steps->rollback();
            if (error) return error; // Includes 3010, never spin on failed recovery.
            error = steps->restore();
            if (error) return error;
            return record.lastError ? record.lastError : ERROR_INSTALL_FAILURE;
        default: return ERROR_INVALID_STATE;
        }
        if (error == ERROR_SUCCESS_REBOOT_REQUIRED) return error;
        if (error != ERROR_SUCCESS) {
            // Re-read/transition inside primitive: a failed flush may have made
            // a terminal record visible. Never overwrite that with stale state.
            DWORD marked = steps->markRollback(error);
            if (marked) return error;
        }
    }
    return ERROR_INVALID_STATE; // A successful primitive must advance its phase.
}
