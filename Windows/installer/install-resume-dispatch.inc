// Caller owns the installation mutex and update guard. The installer must not
// interpret a successful removal recovery as an accepted installation.
static DWORD resume_recorded_install(BOOL installationOnly)
{
    PB_INSTALL_JOURNAL record;
    DWORD error = read_transaction(&record);
    if (error) return error;
    switch (record.phase) {
    case PB_INSTALL_REMOVING:
    case PB_INSTALL_REMOVE_PENDING:
    case PB_INSTALL_REMOVED:
        return installationOnly ? ERROR_INVALID_STATE : uninstall_recorded();
    case PB_INSTALL_CLEANING:
    case PB_INSTALL_CLEANED:
        return installationOnly ? ERROR_INVALID_STATE : cleanup_recorded();
    default: break;
    }
    const PB_INSTALL_STEPS steps = {read_transaction, apply_recorded_driver, verify_pending_driver,
        publish_target, rollback_recorded_driver, restore_previous, mark_rollback};
    return pb_resume_install(&steps);
}
