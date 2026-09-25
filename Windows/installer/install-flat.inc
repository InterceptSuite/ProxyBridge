#include "install-layout.h"
#include "install-overwrite.h"
#include "install-flat-service.h"
#include <shlobj.h>

static DWORD flat_layout(PB_PRODUCT_LAYOUT *layout)
{
    WCHAR programs[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, programs))) return ERROR_PATH_NOT_FOUND;
    return pb_product_layout(programs, layout);
}
static DWORD flat_hash(const WCHAR *text, BYTE hash[32])
{
    if (!text || wcsnlen_s(text, 65) != 64) return ERROR_INVALID_PARAMETER;
    ZeroMemory(hash, 32);
    for (unsigned i = 0; i < 64; ++i) {
        WCHAR c = text[i]; unsigned n;
        if (c >= L'0' && c <= L'9') n = c - L'0';
        else if (c >= L'a' && c <= L'f') n = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') n = c - L'A' + 10;
        else return ERROR_INVALID_PARAMETER;
        hash[i / 2] = (BYTE)((hash[i / 2] << 4) | n);
    }
    return 0;
}
static DWORD flat_save(HKEY key, PB_INSTALL_JOURNAL *record, DWORD phase, DWORD failure)
{
    PB_INSTALL_JOURNAL next = *record; next.phase = phase; next.lastError = failure;
    DWORD error = pb_journal_replace_flat(key, record, &next);
    if (!error) *record = next;
    return error ? error : failure;
}
static DWORD flat_source_file(const WCHAR *directory, const WCHAR *name, HANDLE *file)
{
    WCHAR path[MAX_PATH];
    if (swprintf_s(path, MAX_PATH, L"%s\\%s", directory, name) < 0) return ERROR_FILENAME_EXCED_RANGE;
    *file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (*file == INVALID_HANDLE_VALUE) { *file = NULL; return GetLastError(); }
    FILE_ATTRIBUTE_TAG_INFO info;
    if (!GetFileInformationByHandleEx(*file, FileAttributeTagInfo, &info, sizeof(info))) return GetLastError();
    return info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) ? ERROR_INVALID_NAME : 0;
}

static DWORD flat_install(const WCHAR *directory, const WCHAR *hashText, const WCHAR *support)
{
    PB_PRODUCT_LAYOUT layout; BYTE hash[32];
    DWORD error = flat_layout(&layout); if (error) return error;
    error = flat_hash(hashText, hash); if (error) return error;
    PB_VERIFIED_PAYLOAD source = {0}, supportGuard = {0}; HANDLE launcher = NULL, uninstaller = NULL;
    HKEY key = NULL; HDEVINFO devices = INVALID_HANDLE_VALUE;
    PB_INSTALL_JOURNAL old = {0}, record = {0}; BOOL hadOld = FALSE, recorded = FALSE, exists = FALSE, unbound = FALSE;
    SP_DEVINFO_DATA device = {0};
    error = pb_install_trace(L"validate-source", pb_payload_open(directory, hash, PBDRV_PROTOCOL_VERSION, PBDRV_DRIVER_VERSION, &source));
    WCHAR inf[MAX_PATH];
    if (!error) {
        if (swprintf_s(inf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", directory) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        else error = pb_install_trace(L"verify-driver-signature", verify_inf(inf));
    }
    if (!error) error = pb_payload_lock_directory(support, &supportGuard);
    if (!error) error = flat_source_file(support, L"ProxyBridgeLauncher.exe", &launcher);
    if (!error) error = flat_source_file(support, L"uninstall.exe", &uninstaller);
    if (!error) error = pb_install_store_open(TRUE, &key);
    if (!error) {
        error = pb_journal_read(key, &old); hadOld = !error;
        if (error == ERROR_FILE_NOT_FOUND) error = 0;
    }
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        error = devices == INVALID_HANDLE_VALUE ? GetLastError() : find_device(devices, &device, &exists);
    }
    if (!error && !exists) error = pb_install_trace(L"check-orphan-service", pb_flat_service_check(source.files[6]));
    if (!error && exists) {
        error = check_service(devices, &device);
        // Interrupted between DIF_REGISTERDEVICE and binding the INF: only the
        // exact newly-created instance in the durable journal may be resumed.
        if ((error == ERROR_INVALID_DATA || error == ERROR_FILE_NOT_FOUND) && hadOld && !old.deviceExisted &&
            (old.phase == PB_INSTALL_FLAT_COPYING || old.phase == PB_INSTALL_FLAT_DRIVER || old.phase == PB_INSTALL_DRIVER_CHANGING || old.phase == PB_INSTALL_ROLLING_BACK)) {
            WCHAR actual[200];
            if (SetupDiGetDeviceInstanceIdW(devices, &device, actual, ARRAYSIZE(actual), NULL) && !_wcsicmp(actual, old.deviceInstance)) {
                unbound = TRUE; error = pb_flat_service_check(source.files[6]);
            }
        }
    }
    if (!error) {
        record.size = sizeof(record); record.version = PB_JOURNAL_VERSION;
        record.phase = PB_INSTALL_FLAT_COPYING; record.targetProtocol = PBDRV_PROTOCOL_VERSION;
        record.targetDriverVersion = PBDRV_DRIVER_VERSION; record.deviceExisted = exists && !unbound;
        wcscpy_s(record.targetDirectory, MAX_PATH, layout.application); memcpy(record.targetManifestHash, hash, 32);
        if (FAILED(CoCreateGuid(&record.transaction))) error = ERROR_GEN_FAILURE;
        if (!error && exists) {
            if (!SetupDiGetDeviceInstanceIdW(devices, &device, record.deviceInstance, ARRAYSIZE(record.deviceInstance), NULL)) error = GetLastError();
            if (!error && !unbound) error = device_inf(devices, &device, record.removalInf);
        } else if (!error) error = pb_plan_device_instance(&record.transaction, record.deviceInstance);
    }
    if (!error) {
        error = pb_install_trace(L"record-overwrite", pb_journal_replace_flat(key, hadOld ? &old : NULL, &record));
        recorded = !error;
    }
    if (!error) error = pb_install_trace(L"overwrite-files", pb_product_overwrite(&source, launcher, uninstaller, hash));
    if (!error) error = flat_save(key, &record, PB_INSTALL_FLAT_DRIVER, 0);
    if (!error) {
        // The absent-device gate above verified any orphan against this exact
        // locked, signed payload. Never turn the generic legacy gate off.
        error = pb_install_trace(L"install-pnp-driver", install_package(devices, &device, exists, inf,
            exists ? NULL : record.deviceInstance, FALSE, !exists, unbound));
        if (!error || error == ERROR_SUCCESS_REBOOT_REQUIRED) {
            DWORD result = error; WCHAR published[MAX_PATH];
            DWORD lookup = device_inf(devices, &device, published);
            if (!lookup) {
                PB_INSTALL_JOURNAL next = record; wcscpy_s(next.removalInf, MAX_PATH, published);
                lookup = pb_journal_replace_flat(key, &record, &next); if (!lookup) record = next;
            }
            error = lookup ? lookup : result;
        }
    }
    BOOL reboot = error == ERROR_SUCCESS_REBOOT_REQUIRED;
    if (recorded && (!error || reboot)) {
        error = flat_save(key, &record, reboot ? PB_INSTALL_FLAT_PENDING : PB_INSTALL_FLAT_REGISTERING, 0);
        if (!error) error = pb_install_trace(L"register-application", pb_registration_flat(FALSE));
        if (!error) error = pb_install_trace(L"remove-old-application-copies", pb_product_legacy_cleanup());
        if (!error) error = flat_save(key, &record, reboot ? PB_INSTALL_FLAT_PENDING : PB_INSTALL_COMMITTED,
            reboot ? ERROR_SUCCESS_REBOOT_REQUIRED : 0);
    }
    if (error && recorded) {
        DWORD saved = flat_save(key, &record, record.phase, error);
        if (saved != error) error = saved;
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    if (key) RegCloseKey(key);
    if (launcher) CloseHandle(launcher); if (uninstaller) CloseHandle(uninstaller);
    pb_payload_close(&supportGuard); pb_payload_close(&source);
    return error;
}

static DWORD flat_uninstall(const WCHAR *hashText)
{
    BYTE hash[32]; PB_PRODUCT_LAYOUT layout;
    DWORD error = flat_hash(hashText, hash); if (error) return error;
    error = flat_layout(&layout); if (error) return error;
    HKEY key; error = pb_install_store_open_existing_write(&key); if (error) return error;
    PB_INSTALL_JOURNAL record = {0}; BOOL serviceReboot = FALSE, removalCommitted = FALSE;
    error = pb_journal_read(key, &record);
    if (!error && (_wcsicmp(layout.application, record.targetDirectory) || memcmp(hash, record.targetManifestHash, 32))) error = ERROR_REVISION_MISMATCH;
    HDEVINFO devices = INVALID_HANDLE_VALUE; SP_DEVINFO_DATA device = {0}; BOOL exists = FALSE;
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        error = devices == INVALID_HANDLE_VALUE ? GetLastError() : find_device(devices, &device, &exists);
    }
    if (!error && exists) {
        WCHAR instance[200], published[MAX_PATH];
        if (!SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL)) error = GetLastError();
        if (!error && _wcsicmp(instance, record.deviceInstance)) error = ERROR_REVISION_MISMATCH;
        BOOL unbound = FALSE;
        if (!error) {
            error = check_service(devices, &device);
            if ((error == ERROR_INVALID_DATA || error == ERROR_FILE_NOT_FOUND) && !record.deviceExisted &&
                record.phase >= PB_INSTALL_FLAT_COPYING && !record.removalInf[0]) { error = 0; unbound = TRUE; }
        }
        published[0] = 0;
        if (!error && !unbound) error = device_inf(devices, &device, published);
        if (!error && record.removalInf[0] && _wcsicmp(published, record.removalInf)) error = ERROR_REVISION_MISMATCH;
        if (!error) {
            PB_INSTALL_JOURNAL next = record; wcscpy_s(next.removalInf, MAX_PATH, published); next.phase = PB_INSTALL_FLAT_REMOVING;
            error = pb_journal_replace_flat(key, &record, &next); if (!error) record = next;
        }
    }
    if (!error) error = flat_save(key, &record, PB_INSTALL_FLAT_REMOVING, 0);
    if (!error && exists) {
        BOOL reboot = FALSE;
        if (!DiUninstallDevice(NULL, devices, &device, 0, &reboot)) error = GetLastError();
        else if (reboot) error = ERROR_SUCCESS_REBOOT_REQUIRED;
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else {
            error = find_device(devices, &device, &exists);
            if (!error && exists) error = ERROR_SUCCESS_REBOOT_REQUIRED;
            SetupDiDestroyDeviceInfoList(devices);
        }
    }
    if (!error && record.removalInf[0] && !SetupUninstallOEMInfW(record.removalInf, 0, NULL)) {
        error = GetLastError(); if (error == ERROR_FILE_NOT_FOUND) error = 0;
    }
    // PnP can remove the device/package while SCM keeps its service record
    // until reboot. Finish removing the application now so it does not remain
    // launch-blocked after restart; the install path will refuse to reinstall
    // until SCM has dropped the stale service.
    if (!error) {
        DWORD pending = pb_install_trace(L"check-service-removal-pending", pb_flat_service_removal_pending());
        if (pending == ERROR_SUCCESS_REBOOT_REQUIRED) serviceReboot = TRUE;
        else error = pending;
    }
    if (!error) error = pb_install_trace(L"unregister-application", pb_registration_flat(TRUE));
    if (!error) error = pb_install_trace(L"remove-old-application-copies", pb_product_legacy_cleanup());
    if (!error) error = pb_install_trace(L"remove-application-files", pb_product_remove_files());
    if (!error) {
        error = flat_save(key, &record, PB_INSTALL_FLAT_REMOVED, 0);
        removalCommitted = !error;
        if (!error && serviceReboot) error = ERROR_SUCCESS_REBOOT_REQUIRED;
    }
    if (error && !removalCommitted && record.size == sizeof(record) &&
        !_wcsicmp(layout.application, record.targetDirectory) && !memcmp(hash, record.targetManifestHash, 32))
        error = flat_save(key, &record, record.phase, error);
    RegCloseKey(key); return error;
}
