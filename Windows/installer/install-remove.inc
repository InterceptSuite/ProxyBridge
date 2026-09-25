static DWORD uninstall_recorded(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (!error && record.phase >= PB_INSTALL_REMOVED) { RegCloseKey(key); return 0; }
    BOOL starting = !error && (record.phase == PB_INSTALL_COMMITTED || record.phase == PB_INSTALL_ROLLED_BACK);
    if (!error && !starting && record.phase != PB_INSTALL_REMOVING && record.phase != PB_INSTALL_REMOVE_PENDING)
        error = ERROR_INVALID_STATE;
    PB_APP_SELECTION selection;
    if (!error && starting) error = pb_select_application(&record, &selection);
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0}; BOOL exists = FALSE;
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    if (!error && exists) {
        WCHAR instance[200], inf[MAX_PATH];
        if (!SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL)) error = GetLastError();
        else error = pb_check_device_instance(&record, TRUE, instance);
        if (!error) error = check_service(devices, &device);
        if (!error) error = device_inf(devices, &device, inf);
        if (!error && starting) error = pb_journal_begin_remove(key, &record, inf);
        else if (!error && _wcsicmp(inf, record.removalInf)) error = ERROR_REVISION_MISMATCH;
        if (!error && record.phase == PB_INSTALL_REMOVE_PENDING) {
            ULONG status = 0, problem = 0;
            if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) != CR_SUCCESS) error = ERROR_NOT_READY;
            else if ((status & DN_NEED_RESTART) || problem == CM_PROB_NEED_RESTART) error = ERROR_SUCCESS_REBOOT_REQUIRED;
            else error = pb_journal_advance(key, &record, PB_INSTALL_REMOVING, 0);
        }
        if (!error) {
            BOOL reboot = FALSE;
            if (!DiUninstallDevice(NULL, devices, &device, 0, &reboot)) error = GetLastError();
            else if (reboot) {
                error = pb_journal_advance(key, &record, PB_INSTALL_REMOVE_PENDING, ERROR_SUCCESS_REBOOT_REQUIRED);
                if (!error) error = ERROR_SUCCESS_REBOOT_REQUIRED;
            }
        }
    } else if (!error && starting) error = ERROR_NOT_FOUND;
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    // Re-enumerate after removal. Do not erase packages while any matching node
    // remains, including a nonpresent node or a conflicting duplicate.
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else {
            error = find_device(devices, &device, &exists);
            if (!error && exists) error = ERROR_NOT_READY;
            SetupDiDestroyDeviceInfoList(devices);
        }
    }
    if (!error && !SetupUninstallOEMInfW(record.removalInf, 0, NULL)) {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) error = 0; // Prior attempt already removed it.
    }
    // The service entry can remain visible while Windows finishes unloading a
    // PnP kernel driver even though the verified devnode and its package are
    // already gone. It is not evidence of a separately installed legacy
    // service here: that check is only meaningful before an unowned install.
    if (!error) error = pb_journal_advance(key, &record, PB_INSTALL_REMOVED, 0);
    RegCloseKey(key);
    return error;
}
