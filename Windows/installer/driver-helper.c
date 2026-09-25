// Native x64 device/package operations. Never starts a legacy SCM service and
// never edits Driver Store or Services registry entries directly.
#include "../src/driver/ProxyBridgeDrv_user.h"
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "install-store.h"
#include "install-pair.h"
#include "install-device-identity.h"
#include "../shared/update-guard.h"
#include "install-stage.h"
#include "install-selection.h"
#include "install-resume.h"
#include "startup-installed.h"
#include "install-registration.h"
#include "install-owned.h"
#include "install-bootstrap.h"
#include "install-trace.h"
#include <objbase.h>

// INF trust is an early gate, not proof that every payload file is intact or
// that kernel signing policy will load it. Package installation enforces those
// checks; the application transaction must also verify its complete manifest.
static DWORD verify_inf(const WCHAR *source)
{
    // Root-enumerated KMDF function drivers use the registered System setup
    // class (GUID_DEVCLASS_SYSTEM). WFP describes functionality, not a PnP
    // device setup class.
    static const GUID expectedClass =
        {0x4d36e97d, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
    GUID actualClass;
    WCHAR className[256];
    if (!SetupDiGetINFClassW(source, &actualClass, className, ARRAYSIZE(className), NULL))
        return GetLastError();
    if (!IsEqualGUID(&actualClass, &expectedClass)) return ERROR_CLASS_MISMATCH;
    SP_INF_SIGNER_INFO_W signer = {0};
    signer.cbSize = sizeof(signer);
    if (!SetupVerifyInfFileW(source, NULL, &signer)) {
        // SetupVerifyInfFile reports a valid, non-WHQL Authenticode catalog
        // through FALSE plus this status.  Treating it as fatal rejects the
        // exact test/rehearsal package that PnP will accept silently.
        DWORD error = GetLastError();
        if (error != ERROR_AUTHENTICODE_TRUSTED_PUBLISHER) return error;
    }
    return ERROR_SUCCESS;
}

static DWORD find_device(HDEVINFO devices, SP_DEVINFO_DATA *found, BOOL *exists)
{
    *exists = FALSE;
    for (DWORD index = 0;; ++index) {
        SP_DEVINFO_DATA device = {0};
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
            DWORD error = GetLastError();
            return error == ERROR_NO_MORE_ITEMS ? ERROR_SUCCESS : error;
        }
        DWORD size = 0, type = 0;
        SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_HARDWAREID,
                                          &type, NULL, 0, &size);
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_DATA) continue; // device has no hardware IDs
        if (error != ERROR_INSUFFICIENT_BUFFER) return error;
        if (size > 65536 || size % sizeof(WCHAR) != 0) return ERROR_INVALID_DATA;
        WCHAR *ids = calloc(1, (size_t)size + 2 * sizeof(WCHAR));
        if (ids == NULL) return ERROR_NOT_ENOUGH_MEMORY;
        BOOL ok = SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_HARDWAREID,
                                                     &type, (PBYTE)ids, size, NULL);
        error = ok ? ERROR_SUCCESS : GetLastError();
        BOOL match = FALSE;
        if (ok && type == REG_MULTI_SZ) {
            for (WCHAR *id = ids; *id != 0; id += wcslen(id) + 1)
                if (_wcsicmp(id, PBDRV_HARDWARE_ID) == 0) match = TRUE;
        }
        free(ids);
        if (!ok) return error;
        if (!match) continue;
        if (*exists) return ERROR_DUP_NAME; // present AND nonpresent duplicates count
        *exists = TRUE;
        *found = device;
    }
}

static DWORD device_inf(HDEVINFO devices, SP_DEVINFO_DATA *device, WCHAR inf[MAX_PATH])
{
    DEVPROPTYPE type = 0;
    ZeroMemory(inf, MAX_PATH * sizeof(WCHAR));
    if (!SetupDiGetDevicePropertyW(devices, device, &DEVPKEY_Device_DriverInfPath,
                                   &type, (PBYTE)inf, MAX_PATH * sizeof(WCHAR), NULL, 0))
        return GetLastError();
    if (type != DEVPROP_TYPE_STRING || inf[MAX_PATH - 1] != 0 ||
        wcsncmp(inf, L"oem", 3) != 0 || wcschr(inf, L'\\') || wcschr(inf, L'/'))
        return ERROR_INVALID_DATA;
    const WCHAR *number = inf + 3;
    if (*number < L'0' || *number > L'9') return ERROR_INVALID_DATA;
    while (*number >= L'0' && *number <= L'9') ++number;
    if (_wcsicmp(number, L".inf") != 0) return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

static DWORD check_service(HDEVINFO devices, SP_DEVINFO_DATA *device)
{
    WCHAR service[256] = {0};
    DWORD type = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(devices, device, SPDRP_SERVICE, &type,
                                          (PBYTE)service, sizeof(service), NULL))
        return GetLastError();
    if (type != REG_SZ || service[255] != 0 || _wcsicmp(service, PBDRV_SERVICE_NAME) != 0)
        return ERROR_REVISION_MISMATCH;
    return ERROR_SUCCESS;
}

// Shared read-only identity gate. It deliberately does not call pbdrv_open:
// opening the exclusive controller would interfere with a running application.
static DWORD check_legacy_service(void)
{
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL) return GetLastError();
    SC_HANDLE service = OpenServiceW(manager, PBDRV_SERVICE_NAME, SERVICE_QUERY_CONFIG);
    DWORD error = service == NULL ? GetLastError() : ERROR_ALREADY_EXISTS;
    if (service != NULL) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? ERROR_SUCCESS : error;
}

static DWORD preflight(HDEVINFO devices, SP_DEVINFO_DATA *device, BOOL exists)
{
    if (!exists) {
        DWORD error = check_legacy_service();
        if (error == ERROR_SUCCESS) wprintf(L"DeviceState=absent\n");
        return error;
    }
    DWORD error = check_service(devices, device);
    if (error != ERROR_SUCCESS) return error;
    WCHAR inf[MAX_PATH], instance[MAX_DEVICE_ID_LEN];
    error = device_inf(devices, device, inf);
    if (error != ERROR_SUCCESS) return error;
    if (!SetupDiGetDeviceInstanceIdW(devices, device, instance, ARRAYSIZE(instance), NULL))
        return GetLastError();
    wprintf(L"DeviceState=present\nDeviceInstance=%s\nPreviousInf=%s\n", instance, inf);
    return ERROR_SUCCESS;
}

static DWORD install_selected(HDEVINFO devices, SP_DEVINFO_DATA *device,
                               const WCHAR *inf, BOOL *reboot)
{
    SP_DEVINSTALL_PARAMS_W parameters = {0};
    parameters.cbSize = sizeof(parameters);
    if (!SetupDiGetDeviceInstallParamsW(devices, device, &parameters)) return GetLastError();
    parameters.Flags |= DI_ENUMSINGLEINF;
    if (wcscpy_s(parameters.DriverPath, MAX_PATH, inf) != 0) return ERROR_FILENAME_EXCED_RANGE;
    if (!SetupDiSetDeviceInstallParamsW(devices, device, &parameters)) return GetLastError();
    SetupDiDestroyDriverInfoList(devices, device, SPDIT_COMPATDRIVER);
    if (!SetupDiBuildDriverInfoList(devices, device, SPDIT_COMPATDRIVER)) return GetLastError();
    SP_DRVINFO_DATA_W driver = {0};
    driver.cbSize = sizeof(driver);
    DWORD error = ERROR_SUCCESS;
    if (!SetupDiEnumDriverInfoW(devices, device, SPDIT_COMPATDRIVER, 0, &driver))
        error = GetLastError();
    else {
        SP_DRVINFO_DATA_W other = {0};
        other.cbSize = sizeof(other);
        // Do not silently choose an arbitrary compatible model from an INF.
        if (SetupDiEnumDriverInfoW(devices, device, SPDIT_COMPATDRIVER, 1, &other))
            error = ERROR_DUP_NAME;
        else if (GetLastError() != ERROR_NO_MORE_ITEMS)
            error = GetLastError();
        else if (!SetupDiSetSelectedDriverW(devices, device, &driver) ||
                 !DiInstallDevice(NULL, devices, device, &driver, 0, reboot))
            error = GetLastError();
    }
    SetupDiDestroyDriverInfoList(devices, device, SPDIT_COMPATDRIVER);
    return error;
}

// SetupCopyOEMInf can stage a package before creation of the root devnode.
// If that creation fails, the package has no associated device and must not
// remain as a higher-ranked candidate for a later corrected package.
static void discard_unbound_staged_package(const WCHAR *published)
{
    if (published == NULL || _wcsnicmp(published, L"oem", 3) != 0) return;
    const WCHAR *suffix = published + 3;
    if (*suffix < L'0' || *suffix > L'9') return;
    while (*suffix >= L'0' && *suffix <= L'9') ++suffix;
    if (_wcsicmp(suffix, L".inf") != 0) return;
    // Never force-delete: SetupAPI refuses a package still used by a device.
    (void)SetupUninstallOEMInfW(published, 0, NULL);
}

static DWORD verify_loaded_version(HDEVINFO devices, SP_DEVINFO_DATA *device, DWORD protocol, DWORD version)
{
    UNREFERENCED_PARAMETER(devices);
    // A changed protocol requires its own compatible verifier; never reinterpret
    // an unknown wire layout merely because its buffer happens to fit.
    if (protocol != PBDRV_PROTOCOL_VERSION) return ERROR_NOT_SUPPORTED;
    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, device->DevInst, 0) != CR_SUCCESS ||
        !(status & DN_STARTED) || problem != 0)
        return ERROR_NOT_READY;
    HANDLE handle = pbdrv_open();
    if (handle == INVALID_HANDLE_VALUE) return GetLastError();
    PBDRV_STATUS snapshot = {0};
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(handle, PBDRV_IOCTL_GET_STATUS, NULL, 0,
                              &snapshot, sizeof(snapshot), &bytes, NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && (bytes != sizeof(snapshot) || snapshot.size != sizeof(snapshot) || snapshot.reserved ||
               snapshot.protocolVersion != protocol || snapshot.driverVersion != version))
        error = ERROR_REVISION_MISMATCH;
    if (error == ERROR_SUCCESS && !(snapshot.flags & PBDRV_STATUS_READY)) error = ERROR_NOT_READY;
    CloseHandle(handle);
    return error;
}

static DWORD verify_loaded(HDEVINFO devices, SP_DEVINFO_DATA *device)
{
    return verify_loaded_version(devices, device, PBDRV_PROTOCOL_VERSION, PBDRV_DRIVER_VERSION);
}

static DWORD install_package(HDEVINFO devices, SP_DEVINFO_DATA *device, BOOL exists,
                              const WCHAR *source, const WCHAR *plannedInstance, BOOL rollbackOnFailure, BOOL verifiedOrphan, BOOL ownedUnbound)
{
    WCHAR full[MAX_PATH], previous[MAX_PATH] = {0}, staged[MAX_PATH], *published = NULL;
    DWORD length = GetFullPathNameW(source, MAX_PATH, full, NULL);
    if (length == 0 || length >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    DWORD validation = verify_inf(full);
    if (validation != ERROR_SUCCESS) return validation;
    if (exists && !ownedUnbound) {
        DWORD error = check_service(devices, device);
        if (error != ERROR_SUCCESS) return error;
        error = device_inf(devices, device, previous);
        if (error != ERROR_SUCCESS) return error;
    } else if (!exists) {
        DWORD error = verifiedOrphan ? ERROR_SUCCESS : check_legacy_service();
        pb_install_trace(L"install-driver.check-existing-service", error);
        if (error != ERROR_SUCCESS) return error;
    }
    // Stage the complete signed package before creating a device. Retain staged
    // prior packages for rollback; a package in the store is not a duplicate device.
    if (!SetupCopyOEMInfW(full, NULL, SPOST_PATH, 0, staged, MAX_PATH, NULL, &published))
        return GetLastError();
    BOOL created = FALSE;
    if (!exists) {
        GUID classGuid;
        WCHAR className[256];
        if (!SetupDiGetINFClassW(full, &classGuid, className, 256, NULL)) {
            DWORD error = GetLastError();
            discard_unbound_staged_package(published);
            return error;
        }
        ZeroMemory(device, sizeof(*device));
        device->cbSize = sizeof(*device);
        if (!SetupDiCreateDeviceInfoW(devices, plannedInstance ? plannedInstance : className,
                                      &classGuid, L"ProxyBridge WFP Redirect", NULL,
                                      plannedInstance ? 0 : DICD_GENERATE_ID, device)) {
            DWORD error = GetLastError();
            discard_unbound_staged_package(published);
            return error;
        }
        const WCHAR hardwareIds[] = PBDRV_HARDWARE_ID L"\0";
        if (!SetupDiSetDeviceRegistryPropertyW(devices, device, SPDRP_HARDWAREID,
                                                (const BYTE *)hardwareIds, sizeof(hardwareIds))) {
            DWORD error = GetLastError();
            SetupDiDeleteDeviceInfo(devices, device);
            discard_unbound_staged_package(published);
            return error;
        }
        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devices, device)) {
            DWORD error = GetLastError();
            BOOL reboot = FALSE;
            if (DiUninstallDevice(NULL, devices, device, 0, &reboot) && !reboot)
                discard_unbound_staged_package(published);
            return error;
        }
        created = TRUE;
    }
    BOOL reboot = FALSE;
    DWORD error = install_selected(devices, device, staged, &reboot);
    if (error == ERROR_SUCCESS) {
        WCHAR selected[MAX_PATH];
        error = device_inf(devices, device, selected);
        if (error == ERROR_SUCCESS && (published == NULL || _wcsicmp(selected, published) != 0))
            error = ERROR_REVISION_MISMATCH;
        if (error == ERROR_SUCCESS && reboot) return ERROR_SUCCESS_REBOOT_REQUIRED;
        if (error == ERROR_SUCCESS) error = verify_loaded(devices, device);
    }
    if (error == ERROR_SUCCESS) return error;
    if (!rollbackOnFailure) return error; // coordinator records and owns rollback

    // Best-effort driver rollback. The application installer must retain the old
    // application until this operation has succeeded or a pending state is saved.
    BOOL rollbackReboot = FALSE;
    DWORD rollback = ERROR_SUCCESS;
    if (created) {
        if (!DiUninstallDevice(NULL, devices, device, 0, &rollbackReboot)) rollback = GetLastError();
    } else {
        WCHAR windows[MAX_PATH], oldPath[MAX_PATH];
        UINT size = GetWindowsDirectoryW(windows, MAX_PATH);
        if (size == 0 || size >= MAX_PATH ||
            swprintf_s(oldPath, MAX_PATH, L"%s\\INF\\%s", windows, previous) < 0)
            rollback = ERROR_FILENAME_EXCED_RANGE;
        else {
            rollback = install_selected(devices, device, oldPath, &rollbackReboot);
            if (rollback == ERROR_SUCCESS && !rollbackReboot) {
                WCHAR selected[MAX_PATH];
                rollback = device_inf(devices, device, selected);
                if (rollback == ERROR_SUCCESS && _wcsicmp(selected, previous) != 0)
                    rollback = ERROR_REVISION_MISMATCH;
                // This helper can only verify the protocol it was built for.
                // A prior application's helper must verify a different protocol.
                if (rollback == ERROR_SUCCESS) rollback = verify_loaded(devices, device);
            }
        }
    }
    fwprintf(stderr, L"Install error=%lu; rollback API result=%lu; rollback reboot=%u\n",
             error, rollback, rollbackReboot);
    // An API success alone does not prove a matched application/driver rollback.
    return error;
}

static DWORD remove_package(HDEVINFO devices, SP_DEVINFO_DATA *device, BOOL exists)
{
    if (!exists) return ERROR_SUCCESS;
    DWORD error = check_service(devices, device);
    if (error != ERROR_SUCCESS) return error;
    WCHAR inf[MAX_PATH];
    error = device_inf(devices, device, inf);
    if (error != ERROR_SUCCESS) return error;
    BOOL reboot = FALSE;
    if (!DiUninstallDevice(NULL, devices, device, 0, &reboot)) return GetLastError();
    if (reboot) return ERROR_SUCCESS_REBOOT_REQUIRED;
    // No SUOI_FORCEDELETE: do not remove a package still used by another device.
    if (!SetupUninstallOEMInfW(inf, 0, NULL)) return GetLastError();
    return ERROR_SUCCESS;
}

static DWORD check_pending_transaction(void)
{
    HKEY key;
    DWORD error = pb_install_store_open(FALSE, &key);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    RegCloseKey(key);
    // An empty key can result from interruption before journal_begin. No device
    // mutation is allowed before that record is durable, so this is not pending.
    if (error == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if (error != ERROR_SUCCESS) return error;
    // Managed pairs must never be changed through the unjournaled lab commands.
    return pb_journal_blocks_launch(record.phase) ? ERROR_BUSY : ERROR_ACCESS_DENIED;
}

static DWORD recovery_preflight(void)
{
    HKEY key;
    DWORD error = pb_install_store_open(FALSE, &key);
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    RegCloseKey(key);
    if (error != ERROR_SUCCESS) return error;
    if (!pb_journal_blocks_launch(record.phase)) return ERROR_INVALID_STATE;
    HDEVINFO devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
    if (devices == INVALID_HANDLE_VALUE) return GetLastError();
    SP_DEVINFO_DATA device = {0};
    BOOL exists = FALSE;
    WCHAR instance[200] = {0};
    error = find_device(devices, &device, &exists);
    if (error == ERROR_SUCCESS && exists &&
        !SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL))
        error = GetLastError();
    if (error == ERROR_SUCCESS) error = pb_check_device_instance(&record, exists, instance);
    SetupDiDestroyDeviceInfoList(devices);
    if (error != ERROR_SUCCESS) return error;
    PB_TRANSACTION_PAYLOADS payloads;
    error = pb_rollback_payload_open(&record, &payloads);
    if (error == ERROR_SUCCESS && record.previousDirectory[0]) {
        WCHAR inf[MAX_PATH];
        if (swprintf_s(inf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", record.previousDirectory) < 0)
            error = ERROR_FILENAME_EXCED_RANGE;
        else
            error = verify_inf(inf);
    }
    pb_transaction_payloads_close(&payloads);
    // No previous app means first-install rollback. Device identity must be
    // checked by the eventual mutating adapter, not assumed from this result.
    if (error == ERROR_SUCCESS)
        wprintf(L"RecoveryPayloadVerified=1\nPreviousPayloadPresent=%u\n", record.previousDirectory[0] != 0);
    return error;
}

// Performs only the driver phase of a pre-existing, trusted transaction. The
// application remains pending until its coordinator publishes and verifies it.
// Caller owns the installation mutex throughout; there is no CLI-supplied path.
static DWORD apply_recorded_driver(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (error == ERROR_SUCCESS && (record.phase != PB_INSTALL_PREPARED ||
        record.targetProtocol != PBDRV_PROTOCOL_VERSION || record.targetDriverVersion != PBDRV_DRIVER_VERSION))
        error = ERROR_REVISION_MISMATCH;
    PB_TRANSACTION_PAYLOADS payloads = {0};
    if (error == ERROR_SUCCESS) error = pb_transaction_payloads_open(&record, &payloads);
    WCHAR targetInf[MAX_PATH] = {0};
    if (error == ERROR_SUCCESS) {
        if (swprintf_s(targetInf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", record.targetDirectory) < 0)
            error = ERROR_FILENAME_EXCED_RANGE;
        else error = verify_inf(targetInf);
    }
    if (error == ERROR_SUCCESS && record.previousDirectory[0]) {
        WCHAR previousInf[MAX_PATH];
        if (swprintf_s(previousInf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", record.previousDirectory) < 0)
            error = ERROR_FILENAME_EXCED_RANGE;
        else error = verify_inf(previousInf);
    }
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0};
    BOOL exists = FALSE;
    WCHAR instance[200] = {0}, currentInf[MAX_PATH] = {0};
    if (error == ERROR_SUCCESS) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    if (error == ERROR_SUCCESS && exists) {
        if (!SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL))
            error = GetLastError();
        else error = check_service(devices, &device);
        if (error == ERROR_SUCCESS) error = device_inf(devices, &device, currentInf);
    }
    if (error == ERROR_SUCCESS) error = pb_check_device_before_install(&record, exists, instance, currentInf);
    if (error == ERROR_SUCCESS) {
        error = pb_journal_advance(key, &record, PB_INSTALL_DRIVER_CHANGING, 0);
        if (error == ERROR_SUCCESS) {
            DWORD installed = install_package(devices, &device, exists, targetInf,
                                               exists ? NULL : record.deviceInstance, FALSE, FALSE, FALSE);
            DWORD next = installed == ERROR_SUCCESS ? PB_INSTALL_DRIVER_VERIFIED :
                         installed == ERROR_SUCCESS_REBOOT_REQUIRED ? PB_INSTALL_DRIVER_PENDING :
                         PB_INSTALL_ROLLING_BACK;
            error = pb_journal_advance(key, &record, next, installed);
            if (error == ERROR_SUCCESS) error = installed;
        }
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    pb_transaction_payloads_close(&payloads);
    RegCloseKey(key);
    return error;
}

static DWORD rollback_recorded_driver(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (error == ERROR_SUCCESS && record.phase != PB_INSTALL_ROLLING_BACK &&
        !pb_journal_transition_allowed(record.phase, PB_INSTALL_ROLLING_BACK)) error = ERROR_INVALID_STATE;
    if (error == ERROR_SUCCESS && record.deviceExisted &&
        (!record.previousDirectory[0] || record.previousProtocol != PBDRV_PROTOCOL_VERSION))
        error = ERROR_NOT_SUPPORTED;
    PB_TRANSACTION_PAYLOADS payloads = {0};
    if (error == ERROR_SUCCESS) error = pb_rollback_payload_open(&record, &payloads);
    WCHAR previousInf[MAX_PATH] = {0};
    if (error == ERROR_SUCCESS && record.deviceExisted) {
        if (swprintf_s(previousInf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", record.previousDirectory) < 0)
            error = ERROR_FILENAME_EXCED_RANGE;
        else error = verify_inf(previousInf);
    }
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0};
    BOOL exists = FALSE;
    WCHAR instance[200] = {0};
    if (error == ERROR_SUCCESS) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    if (error == ERROR_SUCCESS && exists &&
        !SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL)) error = GetLastError();
    if (error == ERROR_SUCCESS) error = pb_check_device_instance(&record, exists, instance);
    if (error == ERROR_SUCCESS && exists) {
        error = check_service(devices, &device);
        // An interrupted first registration can leave an unbound node. Its
        // recorded instance + hardware ID still identify it for removal.
        if (!record.deviceExisted && error == ERROR_INVALID_DATA) error = ERROR_SUCCESS;
    }
    if (error == ERROR_SUCCESS && !exists)
        error = pb_install_trace(L"rollback-driver.check-existing-service", check_legacy_service());
    if (error == ERROR_SUCCESS && record.phase != PB_INSTALL_ROLLING_BACK)
        error = pb_journal_advance(key, &record, PB_INSTALL_ROLLING_BACK, record.lastError);
    if (error == ERROR_SUCCESS) {
        BOOL reboot = FALSE;
        DWORD restored = ERROR_SUCCESS;
        if (record.deviceExisted) {
            WCHAR staged[MAX_PATH], *published = NULL;
            if (!SetupCopyOEMInfW(previousInf, NULL, SPOST_PATH, 0, staged, MAX_PATH, NULL, &published))
                restored = GetLastError();
            else {
                WCHAR selected[MAX_PATH];
                BOOL alreadyReady = device_inf(devices, &device, selected) == ERROR_SUCCESS && published &&
                    _wcsicmp(published, selected) == 0 &&
                    verify_loaded_version(devices, &device, record.previousProtocol, record.previousDriverVersion) == ERROR_SUCCESS;
                if (!alreadyReady) restored = install_selected(devices, &device, staged, &reboot);
                if (restored == ERROR_SUCCESS && !alreadyReady) {
                    restored = device_inf(devices, &device, selected);
                    if (restored == ERROR_SUCCESS && (!published || _wcsicmp(published, selected)))
                        restored = ERROR_REVISION_MISMATCH;
                }
                if (restored == ERROR_SUCCESS && !reboot && !alreadyReady)
                    restored = verify_loaded_version(devices, &device, record.previousProtocol, record.previousDriverVersion);
            }
        } else if (exists) {
            if (!DiUninstallDevice(NULL, devices, &device, 0, &reboot)) restored = GetLastError();
            if (restored == ERROR_SUCCESS && !reboot) {
                // Re-enumerate instead of treating API success as absence.
                HDEVINFO after = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
                if (after == INVALID_HANDLE_VALUE) restored = GetLastError();
                else {
                    SP_DEVINFO_DATA remaining = {0}; BOOL present = FALSE;
                    restored = find_device(after, &remaining, &present);
                    if (restored == ERROR_SUCCESS && present) restored = ERROR_NOT_READY;
                    SetupDiDestroyDeviceInfoList(after);
                }
            }
        }
        if (restored == ERROR_SUCCESS && reboot) {
            error = pb_journal_advance(key, &record, PB_INSTALL_ROLLBACK_PENDING, record.lastError);
            if (error == ERROR_SUCCESS) error = ERROR_SUCCESS_REBOOT_REQUIRED;
        } else if (restored != ERROR_SUCCESS) {
            error = pb_journal_advance(key, &record, PB_INSTALL_RECOVERY_REQUIRED, restored);
            if (error == ERROR_SUCCESS) error = restored;
        } else {
            // Deliberately remain ROLLING_BACK: only the full coordinator may
            // verify/restore the app and declare the previous pair restored.
            wprintf(L"DriverRollbackVerified=1\nApplicationRecoveryPending=1\n");
        }
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    pb_transaction_payloads_close(&payloads);
    RegCloseKey(key);
    return error;
}

// Publication changes only the terminal journal selection. Version directories
// are retained in place; the launcher resolves the selected directory later.
static DWORD publish_recorded_application(BOOL previous)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record = {0};
    error = pb_journal_read(key, &record);
    if (error == ERROR_SUCCESS && (previous ?
        (record.phase != PB_INSTALL_ROLLING_BACK && record.phase != PB_INSTALL_ROLLBACK_PENDING) :
        record.phase != PB_INSTALL_DRIVER_VERIFIED)) error = ERROR_INVALID_STATE;
    PB_TRANSACTION_PAYLOADS payloads = {0};
    if (error == ERROR_SUCCESS)
        error = previous ? pb_rollback_payload_open(&record, &payloads) : pb_transaction_payloads_open(&record, &payloads);
    const WCHAR *directory = previous ? record.previousDirectory : record.targetDirectory;
    DWORD protocol = previous ? record.previousProtocol : record.targetProtocol;
    DWORD version = previous ? record.previousDriverVersion : record.targetDriverVersion;
    if (error == ERROR_SUCCESS && directory[0]) {
        WCHAR inf[MAX_PATH];
        if (swprintf_s(inf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", directory) < 0)
            error = ERROR_FILENAME_EXCED_RANGE;
        else error = verify_inf(inf);
    }
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0};
    BOOL exists = FALSE;
    if (error == ERROR_SUCCESS) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    if (error == ERROR_SUCCESS && previous && !record.deviceExisted) {
        error = exists ? ERROR_ALREADY_EXISTS : check_legacy_service();
        if (error == ERROR_SUCCESS && directory[0]) error = ERROR_INVALID_DATA;
    } else if (error == ERROR_SUCCESS) {
        WCHAR instance[200];
        if (!exists) error = ERROR_NOT_FOUND;
        else if (!SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL)) error = GetLastError();
        else error = pb_check_device_instance(&record, TRUE, instance);
        if (error == ERROR_SUCCESS) error = check_service(devices, &device);
        if (error == ERROR_SUCCESS) error = verify_loaded_version(devices, &device, protocol, version);
    }
    if (error == ERROR_SUCCESS) {
        if (!previous) error = pb_journal_advance(key, &record, PB_INSTALL_APP_CHANGING, 0);
        else if (record.phase == PB_INSTALL_ROLLBACK_PENDING)
            error = pb_journal_advance(key, &record, PB_INSTALL_ROLLING_BACK, record.lastError);
        if (error == ERROR_SUCCESS)
            error = pb_journal_advance(key, &record, previous ? PB_INSTALL_ROLLED_BACK : PB_INSTALL_COMMITTED,
                                       previous ? record.lastError : 0);
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    pb_transaction_payloads_close(&payloads);
    RegCloseKey(key);
    return error;
}

static DWORD begin_recorded_install(const WCHAR *directory, const WCHAR *hashText, BOOL removedOwnedPackage)
{
    // Expected hash is supplied by the trusted/elevated installer, never read
    // from an adjacent checksum file. Signed installer packaging must bind it.
    if (wcsnlen_s(hashText, 65) != 64) return ERROR_INVALID_PARAMETER;
    BYTE hash[32] = {0};
    for (unsigned i = 0; i < 64; ++i) {
        WCHAR c = hashText[i];
        unsigned nibble;
        if (c >= L'0' && c <= L'9') nibble = c - L'0';
        else if (c >= L'a' && c <= L'f') nibble = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') nibble = c - L'A' + 10;
        else return ERROR_INVALID_PARAMETER;
        hash[i / 2] = (BYTE)((hash[i / 2] << 4) | nibble);
    }
    PB_VERIFIED_PAYLOAD source = {0}, priorPayload = {0}, rootGuard = {0};
    DWORD error = pb_payload_open(directory, hash, PBDRV_PROTOCOL_VERSION, PBDRV_DRIVER_VERSION, &source);
    WCHAR inf[MAX_PATH];
    if (error == ERROR_SUCCESS) {
        if (swprintf_s(inf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", directory) < 0) error = ERROR_FILENAME_EXCED_RANGE;
        else error = verify_inf(inf);
    }
    PB_APP_SELECTION prior = {0};
    PB_INSTALL_JOURNAL old = {0}, record = {0};
    HKEY key = NULL;
    if (error == ERROR_SUCCESS) {
        error = pb_install_store_open(FALSE, &key);
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) error = ERROR_SUCCESS;
        else if (error == ERROR_SUCCESS) {
            error = pb_journal_read(key, &old);
            if (error == ERROR_SUCCESS) error = pb_select_application(&old, &prior);
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_NOT_FOUND) error = ERROR_SUCCESS;
            RegCloseKey(key); key = NULL;
        }
    }
    if (error == ERROR_SUCCESS && prior.directory[0]) {
        error = pb_payload_open(prior.directory, prior.manifestHash, prior.protocol, prior.driverVersion, &priorPayload);
        if (error == ERROR_SUCCESS) {
            if (swprintf_s(inf, MAX_PATH, L"%s\\driver\\ProxyBridgeDrv.inf", prior.directory) < 0) error = ERROR_FILENAME_EXCED_RANGE;
            else error = verify_inf(inf);
        }
    }
    record.size = sizeof(record); record.version = PB_JOURNAL_VERSION; record.phase = PB_INSTALL_PREPARED;
    record.targetProtocol = PBDRV_PROTOCOL_VERSION; record.targetDriverVersion = PBDRV_DRIVER_VERSION;
    memcpy(record.targetManifestHash, hash, 32);
    if (error == ERROR_SUCCESS && FAILED(CoCreateGuid(&record.transaction))) error = ERROR_GEN_FAILURE;
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0}; BOOL exists = FALSE;
    if (error == ERROR_SUCCESS) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    if (error == ERROR_SUCCESS && exists) {
        if (!prior.directory[0]) error = ERROR_REVISION_MISMATCH;
        else if (!SetupDiGetDeviceInstanceIdW(devices, &device, record.deviceInstance, ARRAYSIZE(record.deviceInstance), NULL)) error = GetLastError();
        else error = pb_check_device_instance(&old, TRUE, record.deviceInstance);
        if (error == ERROR_SUCCESS) error = check_service(devices, &device);
        if (error == ERROR_SUCCESS) error = device_inf(devices, &device, record.previousInf);
        if (error == ERROR_SUCCESS) error = verify_loaded_version(devices, &device, prior.protocol, prior.driverVersion);
        record.deviceExisted = 1;
    } else if (error == ERROR_SUCCESS) {
        if (prior.directory[0]) error = ERROR_NOT_FOUND;
        else {
            error = check_legacy_service();
            // DiUninstallDevice can remove the owned devnode before SCM has
            // hidden its PnP service. This is allowed only after this package
            // completed the recorded, owned removal under the same mutex.
            if (removedOwnedPackage && error == ERROR_ALREADY_EXISTS) error = ERROR_SUCCESS;
        }
        if (error == ERROR_SUCCESS) error = pb_plan_device_instance(&record.transaction, record.deviceInstance);
    }
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    if (error == ERROR_SUCCESS && prior.directory[0]) {
        wcscpy_s(record.previousDirectory, MAX_PATH, prior.directory);
        memcpy(record.previousManifestHash, prior.manifestHash, 32);
        record.previousProtocol = prior.protocol; record.previousDriverVersion = prior.driverVersion;
    }
    HANDLE root = NULL;
    if (error == ERROR_SUCCESS) error = pb_stage_root_open(&rootGuard, &root);
    if (error == ERROR_SUCCESS) error = pb_install_store_open(TRUE, &key);
    if (error == ERROR_SUCCESS) error = pb_owned_stage_recover(key, root, &old);
    if (error == ERROR_SUCCESS) error = pb_owned_stage_prepare(key, root, &record);
    if (error == ERROR_SUCCESS) error = pb_stage_payload(root, &record.transaction, &source, hash, record.targetDirectory);
    if (error == ERROR_SUCCESS) error = pb_owned_begin(key, &old, &record);
    if (error == ERROR_SUCCESS) error = pb_owned_stage_recover(key, root, &record);
    if (key) RegCloseKey(key);
    pb_payload_close(&rootGuard); pb_payload_close(&priorPayload); pb_payload_close(&source);
    return error;
}

static DWORD read_transaction(PB_INSTALL_JOURNAL *record)
{
    HKEY key;
    DWORD error = pb_install_store_open(FALSE, &key);
    if (error) return error;
    error = pb_journal_read(key, record);
    RegCloseKey(key);
    return error;
}

static DWORD mark_rollback(DWORD failure)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (!error && record.phase != PB_INSTALL_ROLLING_BACK)
        error = pb_journal_advance(key, &record, PB_INSTALL_ROLLING_BACK, failure);
    RegCloseKey(key);
    return error;
}

static DWORD verify_pending_driver(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (!error && record.phase != PB_INSTALL_DRIVER_PENDING) error = ERROR_INVALID_STATE;
    PB_TRANSACTION_PAYLOADS payloads = {0};
    if (!error) error = pb_transaction_payloads_open(&record, &payloads);
    HDEVINFO devices = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA device = {0}; BOOL exists = FALSE;
    if (!error) {
        devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
        if (devices == INVALID_HANDLE_VALUE) error = GetLastError();
        else error = find_device(devices, &device, &exists);
    }
    WCHAR instance[200];
    if (!error) {
        if (!exists) error = ERROR_NOT_FOUND;
        else if (!SetupDiGetDeviceInstanceIdW(devices, &device, instance, ARRAYSIZE(instance), NULL)) error = GetLastError();
        else error = pb_check_device_instance(&record, TRUE, instance);
    }
    if (!error) error = check_service(devices, &device);
    if (!error) {
        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) != CR_SUCCESS) error = ERROR_NOT_READY;
        else if ((status & DN_NEED_RESTART) || problem == CM_PROB_NEED_RESTART) error = ERROR_SUCCESS_REBOOT_REQUIRED;
        else error = verify_loaded_version(devices, &device, record.targetProtocol, record.targetDriverVersion);
    }
    if (!error) error = pb_journal_advance(key, &record, PB_INSTALL_DRIVER_VERIFIED, 0);
    if (devices != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devices);
    pb_transaction_payloads_close(&payloads); RegCloseKey(key);
    return error;
}

static DWORD publish_target(void) { return publish_recorded_application(FALSE); }
static DWORD cleanup_preflight(void)
{
    PB_INSTALL_JOURNAL record;
    DWORD error = read_transaction(&record);
    if (error) return error;
    if (record.phase != PB_INSTALL_REMOVED) return ERROR_INVALID_STATE;
    PB_TRANSACTION_PAYLOADS payloads = {0};
    error = pb_transaction_payloads_open(&record, &payloads);
    if (!error) error = pb_payload_check_inventory(record.targetDirectory);
    if (!error && record.previousDirectory[0]) error = pb_payload_check_inventory(record.previousDirectory);
    pb_transaction_payloads_close(&payloads);
    return error;
}
static DWORD restore_previous(void) { return publish_recorded_application(TRUE); }
static DWORD cleanup_recorded(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    if (!error && record.phase == PB_INSTALL_CLEANED) { RegCloseKey(key); return 0; }
    if (!error && record.phase != PB_INSTALL_REMOVED && record.phase != PB_INSTALL_CLEANING) error = ERROR_INVALID_STATE;
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
    if (!error) error = pb_stage_root_open(&guard, &root);
    if (!error && record.phase == PB_INSTALL_REMOVED) error = pb_journal_advance(key, &record, PB_INSTALL_CLEANING, 0);
    if (!error) error = pb_stage_cleanup_files(root, record.targetDirectory, record.targetManifestHash, record.targetProtocol, record.targetDriverVersion);
    if (!error && record.previousDirectory[0])
        error = pb_stage_cleanup_files(root, record.previousDirectory, record.previousManifestHash, record.previousProtocol, record.previousDriverVersion);
    if (!error) error = pb_journal_advance(key, &record, PB_INSTALL_CLEANED, 0);
    pb_payload_close(&guard); RegCloseKey(key);
    return error;
}
#include "install-remove.inc"

#include "install-resume-dispatch.inc"
#include "startup-recorded.inc"
static DWORD cleanup_recorded_owned(void)
{
    HKEY key;
    DWORD error = pb_install_store_open_existing_write(&key);
    if (error) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
    if (!error) error = pb_stage_root_read(&guard, &root);
    if (!error) error = pb_owned_stage_recover(key, root, &record);
    if (!error) error = pb_owned_cleanup(key, root, &record);
    pb_payload_close(&guard); RegCloseKey(key);
    return error;
}
#include "install-package.inc"
#include "install-flat.inc"

static int run_command(int argc, WCHAR **argv)
{
    if (argc == 2 && wcscmp(argv[1], L"journal-status") == 0) {
        HKEY key;
        DWORD error = pb_install_store_open(FALSE, &key);
        if (error != ERROR_SUCCESS) return (int)error;
        PB_INSTALL_JOURNAL record;
        error = pb_journal_read(key, &record);
        RegCloseKey(key);
        if (error == ERROR_SUCCESS)
            wprintf(L"JournalPhase=%lu\nLastError=%lu\nLaunchBlocked=%u\n",
                     record.phase, record.lastError, pb_journal_blocks_launch(record.phase));
        return (int)error;
    }
    // Read-only validation may be used before taking transaction ownership.
    if (argc == 3 && wcscmp(argv[1], L"verify-inf") == 0) {
        DWORD error = verify_inf(argv[2]);
        wprintf(L"ProxyBridge INF verification result: %lu\n", error);
        return (int)error;
    }
    if (argc == 3 && !wcscmp(argv[1], L"prepare-bootstrap")) {
        PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
        DWORD error = pb_bootstrap_root_open(argv[2], &guard, &root);
        pb_payload_close(&guard);
        return (int)error;
    }
    if (argc < 2) return ERROR_INVALID_PARAMETER;
    BOOL flat = !wcscmp(argv[1], L"install-flat") || !wcscmp(argv[1], L"uninstall-flat");
    BOOL bootstrap = !wcscmp(argv[1], L"publish-bootstrap");
    BOOL package = !wcscmp(argv[1],L"update-package") || !wcscmp(argv[1],L"resume-package") ||
        !wcscmp(argv[1],L"uninstall-package") || !wcscmp(argv[1],L"prepare-recovery");
    if (flat ? argc != (!wcscmp(argv[1],L"install-flat") ? 5 : 3) : bootstrap ? argc != 4 : package ? argc != (!wcscmp(argv[1],L"update-package") ? 4 : 3) :
        ((!wcscmp(argv[1], L"begin") || !wcscmp(argv[1], L"update")) ? argc != 4 : !wcscmp(argv[1], L"install") ? argc != 3 : argc != 2))
        return ERROR_INVALID_PARAMETER;
    if (!flat && !bootstrap && !package && wcscmp(argv[1], L"install") && wcscmp(argv[1], L"remove") && wcscmp(argv[1], L"status") &&
        wcscmp(argv[1], L"preflight") && wcscmp(argv[1], L"recovery-preflight") &&
        wcscmp(argv[1], L"apply-driver") && wcscmp(argv[1], L"rollback-driver") &&
        wcscmp(argv[1], L"publish-app") && wcscmp(argv[1], L"restore-app") && wcscmp(argv[1], L"begin") &&
        wcscmp(argv[1], L"update") && wcscmp(argv[1], L"resume") && wcscmp(argv[1], L"resume-install") && wcscmp(argv[1], L"uninstall") && wcscmp(argv[1], L"cleanup-preflight") && wcscmp(argv[1], L"cleanup") &&
        wcscmp(argv[1], L"startup-query") && wcscmp(argv[1], L"startup-enable") && wcscmp(argv[1], L"startup-disable") &&
        wcscmp(argv[1], L"startup-retarget") && wcscmp(argv[1], L"startup-remove"))
        return ERROR_INVALID_PARAMETER;
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Global\\InterceptSuite.ProxyBridge.Install");
    if (mutex == NULL) return (int)GetLastError();
    DWORD wait = WaitForSingleObject(mutex, 0);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        DWORD error = wait == WAIT_FAILED ? GetLastError() : ERROR_BUSY;
        CloseHandle(mutex);
        pb_install_trace(L"acquire-install-mutex", error);
        return (int)error;
    }
    if (flat) {
        DWORD result = argc == 5 ? flat_install(argv[2], argv[3], argv[4]) : flat_uninstall(argv[2]);
        ReleaseMutex(mutex); CloseHandle(mutex); return (int)result;
    }
    // Never let old rollback/staging commands reinterpret a fixed-layout record.
    if (wcsncmp(argv[1], L"startup-", 8) && wcscmp(argv[1], L"status") && wcscmp(argv[1], L"preflight")) {
        PB_INSTALL_JOURNAL current; PB_PRODUCT_LAYOUT layout;
        if (!read_transaction(&current) && !flat_layout(&layout) && !_wcsicmp(current.targetDirectory, layout.application)) {
            ReleaseMutex(mutex); CloseHandle(mutex); return ERROR_NOT_SUPPORTED;
        }
    }
    if (bootstrap) {
        DWORD result = pb_bootstrap_publish(argv[2], argv[3]);
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (package) {
        DWORD result=package_recorded(argv[1],argc==4?argv[2]:NULL,argv[argc-1]);
        ReleaseMutex(mutex);CloseHandle(mutex);
        return (int)result;
    }
    if (!wcsncmp(argv[1], L"startup-", 8)) {
        PB_STARTUP_OPERATION operation = !wcscmp(argv[1], L"startup-query") ? PB_STARTUP_QUERY :
            !wcscmp(argv[1], L"startup-enable") ? PB_STARTUP_ENABLE :
            !wcscmp(argv[1], L"startup-disable") ? PB_STARTUP_DISABLE :
            !wcscmp(argv[1], L"startup-retarget") ? PB_STARTUP_RETARGET : PB_STARTUP_REMOVE;
        BOOL enabled = FALSE;
        DWORD result = startup_recorded(operation, &enabled);
        if (!result && operation == PB_STARTUP_QUERY && !enabled) result = ERROR_NOT_FOUND;
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (!wcscmp(argv[1], L"begin") || !wcscmp(argv[1], L"update")) {
        DWORD result = begin_recorded_install(argv[2], argv[3], FALSE);
        if (!result && !wcscmp(argv[1], L"update")) result = resume_recorded_install(TRUE);
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (!wcscmp(argv[1], L"cleanup-preflight")) {
        DWORD result = cleanup_preflight();
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (!wcscmp(argv[1], L"cleanup")) {
        DWORD result = cleanup_recorded();
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (!wcscmp(argv[1], L"resume") || !wcscmp(argv[1], L"resume-install") || !wcscmp(argv[1], L"uninstall")) {
        DWORD result = !wcscmp(argv[1], L"uninstall") ? uninstall_recorded() : resume_recorded_install(!wcscmp(argv[1], L"resume-install"));
        ReleaseMutex(mutex); CloseHandle(mutex);
        return (int)result;
    }
    if (wcscmp(argv[1], L"install") == 0 || wcscmp(argv[1], L"remove") == 0) {
        DWORD pending = check_pending_transaction();
        if (pending != ERROR_SUCCESS) {
            ReleaseMutex(mutex);
            CloseHandle(mutex);
            fwprintf(stderr, L"Installation journal requires recovery or cannot be read: %lu\n", pending);
            return (int)pending;
        }
    }
    if (wcscmp(argv[1], L"recovery-preflight") == 0) {
        DWORD result = recovery_preflight();
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return (int)result;
    }
    if (wcscmp(argv[1], L"apply-driver") == 0) {
        DWORD result = apply_recorded_driver();
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return (int)result;
    }
    if (wcscmp(argv[1], L"rollback-driver") == 0) {
        DWORD result = rollback_recorded_driver();
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return (int)result;
    }
    if (!wcscmp(argv[1], L"publish-app") || !wcscmp(argv[1], L"restore-app")) {
        DWORD result = publish_recorded_application(!wcscmp(argv[1], L"restore-app"));
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return (int)result;
    }
    // Include nonpresent instances. Moving the application directory must not
    // result in a second device or a second active driver service.
    HDEVINFO devices = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES);
    DWORD error = devices == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (error == ERROR_SUCCESS) {
        SP_DEVINFO_DATA device = {0};
        BOOL exists;
        error = find_device(devices, &device, &exists);
        if (error == ERROR_SUCCESS) {
            if (wcscmp(argv[1], L"preflight") == 0)
                error = preflight(devices, &device, exists);
            else if (wcscmp(argv[1], L"install") == 0)
                error = install_package(devices, &device, exists, argv[2], NULL, TRUE, FALSE, FALSE);
            else if (wcscmp(argv[1], L"remove") == 0)
                error = remove_package(devices, &device, exists);
            else
                error = exists ? verify_loaded(devices, &device) : ERROR_NOT_FOUND;
        }
        SetupDiDestroyDeviceInfoList(devices);
    }
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    wprintf(L"ProxyBridge driver operation result: %lu\n", error);
    return (int)error;
}

int wmain(int argc, WCHAR **argv)
{
    HANDLE guard = NULL;
    BOOL mutating = argc >= 2 && (!wcscmp(argv[1], L"install-flat") || !wcscmp(argv[1], L"uninstall-flat") || !wcscmp(argv[1], L"install") ||
                    !wcscmp(argv[1], L"remove") || !wcscmp(argv[1], L"apply-driver") ||
                    !wcscmp(argv[1], L"rollback-driver") || !wcscmp(argv[1], L"publish-app") ||
                    !wcscmp(argv[1], L"restore-app") || !wcscmp(argv[1], L"begin") ||
                    !wcscmp(argv[1], L"update") || !wcscmp(argv[1], L"resume") || !wcscmp(argv[1], L"resume-install") || !wcscmp(argv[1], L"uninstall") || !wcscmp(argv[1], L"cleanup") ||
                    !wcscmp(argv[1], L"update-package") || !wcscmp(argv[1], L"resume-package") || !wcscmp(argv[1], L"uninstall-package"));
    if (mutating) {
        DWORD error = pb_update_guard_acquire(&guard);
        if (error != ERROR_SUCCESS) return (int)pb_install_trace(L"acquire-runtime-guard", error);
    }
    int result = run_command(argc, argv);
    pb_install_trace(L"command-complete", (DWORD)result);
    pb_update_guard_release(&guard);
    return result;
}
