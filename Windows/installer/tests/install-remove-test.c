#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <wchar.h>
#include "../install-selection.h"

static PB_INSTALL_JOURNAL disk;
static BOOL node, needsReboot, remains;
static DWORD failure, packageFailure, journalFailure, nodeStatus;
static DWORD identityFailure, enumerationFailure, serviceFailure;
static unsigned removals, packages, enumerations, legacyChecks;
static DWORD pb_install_store_open_existing_write(HKEY *key) { *key = (HKEY)1; return 0; }
DWORD pb_journal_read(HKEY key, PB_INSTALL_JOURNAL *out) { (void)key; *out = disk; return 0; }
DWORD pb_select_application(const PB_INSTALL_JOURNAL *r, PB_APP_SELECTION *s) { (void)r; ZeroMemory(s, sizeof(*s)); return 0; }
DWORD pb_journal_begin_remove(HKEY key, PB_INSTALL_JOURNAL *r, const WCHAR *inf) {
    (void)key; if (journalFailure) return journalFailure;
    r->phase = PB_INSTALL_REMOVING; wcscpy_s(r->removalInf, MAX_PATH, inf); disk = *r; return 0;
}
DWORD pb_journal_advance(HKEY key, PB_INSTALL_JOURNAL *r, DWORD phase, DWORD error) {
    (void)key; if (journalFailure) return journalFailure;
    r->phase = phase; r->lastError = error; disk = *r; return 0;
}
static HDEVINFO mock_devices(const GUID *g, PCWSTR e, HWND w, DWORD f) {
    (void)g; (void)e; (void)w; (void)f; ++enumerations; return (HDEVINFO)1;
}
static DWORD find_device(HDEVINFO h, SP_DEVINFO_DATA *d, BOOL *exists) { (void)h; (void)d; *exists = node; return enumerationFailure; }
static BOOL mock_instance(HDEVINFO h, SP_DEVINFO_DATA *d, PWSTR out, DWORD size, PDWORD needed) {
    (void)h; (void)d; (void)needed; wcscpy_s(out, size, L"ROOT\\test"); return TRUE;
}
static DWORD pb_check_device_instance(const PB_INSTALL_JOURNAL *r, BOOL e, const WCHAR *s) { (void)r; (void)e; (void)s; return identityFailure; }
static DWORD check_service(HDEVINFO h, SP_DEVINFO_DATA *d) { (void)h; (void)d; return 0; }
static DWORD device_inf(HDEVINFO h, SP_DEVINFO_DATA *d, WCHAR *out) { (void)h; (void)d; wcscpy_s(out, MAX_PATH, L"oem12.inf"); return 0; }
static CONFIGRET mock_status(PULONG s, PULONG p, DEVINST d, ULONG f) { (void)d; (void)f; *s = nodeStatus; *p = 0; return CR_SUCCESS; }
static BOOL remove_device(HWND w, HDEVINFO h, SP_DEVINFO_DATA *d, DWORD f, PBOOL restart) {
    (void)w; (void)h; (void)d; (void)f; ++removals;
    if (disk.phase != PB_INSTALL_REMOVING) { SetLastError(ERROR_INVALID_STATE); return FALSE; }
    if (failure) { SetLastError(failure); return FALSE; }
    *restart = needsReboot; node = needsReboot || remains; return TRUE;
}
static BOOL destroy(HDEVINFO h) { (void)h; return TRUE; }
static BOOL remove_inf(PCWSTR inf, DWORD flags, PVOID reserved) {
    (void)reserved; ++packages;
    if (flags || wcscmp(inf, L"oem12.inf") || node) { SetLastError(ERROR_INVALID_STATE); return FALSE; }
    if (packageFailure) { SetLastError(packageFailure); return FALSE; } return TRUE;
}
static DWORD check_legacy_service(void) { ++legacyChecks; return serviceFailure; }
static LSTATUS close_key(HKEY key) { (void)key; return 0; }
#define SetupDiGetClassDevsW mock_devices
#define SetupDiGetDeviceInstanceIdW mock_instance
#define CM_Get_DevNode_Status mock_status
#define DiUninstallDevice remove_device
#define SetupDiDestroyDeviceInfoList destroy
#define SetupUninstallOEMInfW remove_inf
#define RegCloseKey close_key
// This is the exact native control flow included by driver-helper.c.
#include "../install-remove.inc"
static void reset(void) {
    ZeroMemory(&disk, sizeof(disk)); disk.phase = PB_INSTALL_COMMITTED;
    node = TRUE; needsReboot = remains = FALSE;
    failure = packageFailure = journalFailure = nodeStatus = 0;
    identityFailure = enumerationFailure = serviceFailure = 0;
    removals = packages = enumerations = legacyChecks = 0;
}
#define CHECK(x) do { if (!(x)) { printf("Failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    reset(); CHECK(uninstall_recorded() == 0 && disk.phase == PB_INSTALL_REMOVED && removals == 1 && packages == 1);
    CHECK(uninstall_recorded() == 0 && removals == 1 && packages == 1);
    reset(); journalFailure = ERROR_WRITE_FAULT;
    CHECK(uninstall_recorded() == ERROR_WRITE_FAULT && removals == 0 && packages == 0);
    reset(); failure = ERROR_ACCESS_DENIED;
    CHECK(uninstall_recorded() == ERROR_ACCESS_DENIED && disk.phase == PB_INSTALL_REMOVING && packages == 0);
    failure = 0; CHECK(uninstall_recorded() == 0 && disk.phase == PB_INSTALL_REMOVED);
    reset(); needsReboot = TRUE;
    CHECK(uninstall_recorded() == 3010 && disk.phase == PB_INSTALL_REMOVE_PENDING && packages == 0);
    nodeStatus = DN_NEED_RESTART;
    CHECK(uninstall_recorded() == 3010 && removals == 1 && packages == 0);
    node = FALSE; CHECK(uninstall_recorded() == 0 && removals == 1 && packages == 1);
    reset(); remains = TRUE;
    CHECK(uninstall_recorded() == ERROR_NOT_READY && disk.phase == PB_INSTALL_REMOVING && packages == 0);
    reset(); packageFailure = ERROR_ACCESS_DENIED;
    CHECK(uninstall_recorded() == ERROR_ACCESS_DENIED && disk.phase == PB_INSTALL_REMOVING);
    packageFailure = ERROR_FILE_NOT_FOUND;
    CHECK(uninstall_recorded() == 0 && removals == 1);
    reset(); disk.phase = PB_INSTALL_DRIVER_PENDING;
    CHECK(uninstall_recorded() == ERROR_INVALID_STATE && removals == 0 && enumerations == 0);
    reset(); node = FALSE; CHECK(uninstall_recorded() == ERROR_NOT_FOUND && packages == 0);
    reset(); identityFailure = ERROR_REVISION_MISMATCH;
    CHECK(uninstall_recorded() == ERROR_REVISION_MISMATCH && removals == 0 && packages == 0);
    reset(); enumerationFailure = ERROR_DUP_NAME;
    CHECK(uninstall_recorded() == ERROR_DUP_NAME && removals == 0 && packages == 0);
    reset(); serviceFailure = ERROR_ALREADY_EXISTS;
    CHECK(uninstall_recorded() == 0 && disk.phase == PB_INSTALL_REMOVED && legacyChecks == 0);
    puts("Native removal control-flow fault tests passed; post-PnP legacy service is not a removal failure; Windows mutations mocked."); return 0;
}
