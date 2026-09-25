// Called while holding the installation mutex through the scheduler operation.
// In particular, a delayed uninstall must not remove a new install's task.
static DWORD startup_recorded(PB_STARTUP_OPERATION operation, BOOL *enabled)
{
    if (!enabled || operation < PB_STARTUP_QUERY || operation > PB_STARTUP_REMOVE) return ERROR_INVALID_PARAMETER;
    *enabled = FALSE;
    if (operation == PB_STARTUP_ENABLE || operation == PB_STARTUP_RETARGET || operation == PB_STARTUP_REMOVE) {
        PB_INSTALL_JOURNAL record;
        DWORD error = read_transaction(&record);
        if (error) return error;
        BOOL allowed;
        if (operation == PB_STARTUP_REMOVE)
            allowed = record.phase == PB_INSTALL_REMOVED || record.phase == PB_INSTALL_CLEANED;
        else {
            allowed = record.phase == PB_INSTALL_COMMITTED || record.phase == PB_INSTALL_ROLLED_BACK;
            if (operation == PB_STARTUP_RETARGET)
                allowed = allowed || record.phase == PB_INSTALL_DRIVER_PENDING || record.phase == PB_INSTALL_ROLLBACK_PENDING;
        }
        if (!allowed) return ERROR_INSTALL_SUSPEND;
    }
    return pb_startup_installed(operation, enabled);
}
