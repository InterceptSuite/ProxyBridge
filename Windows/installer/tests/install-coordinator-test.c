#include "../install-coordinator.h"
#include <stdio.h>

static PB_INSTALL_JOURNAL stored;
static DWORD failPhase, installResult, verifyResult, publishResult, restoreResult, previousResult;
static unsigned installs, publications, restores;
static DWORD targetValidation, rollbackValidation;
static unsigned targetChecks;
DWORD pb_journal_read(HKEY key, PB_INSTALL_JOURNAL *record)
{ (void)key; *record = stored; return 0; }
BOOL pb_journal_blocks_launch(DWORD phase)
{ return phase != PB_INSTALL_COMMITTED && phase != PB_INSTALL_ROLLED_BACK; }
DWORD pb_journal_advance(HKEY key, PB_INSTALL_JOURNAL *record, DWORD phase, DWORD error)
{
    (void)key;
    if (phase == failPhase) return ERROR_WRITE_FAULT;
    record->phase = phase; record->lastError = error; stored = *record; return 0;
}
static DWORD validate(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; ++targetChecks; return targetValidation; }
static DWORD validateRollback(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; return rollbackValidation; }
static DWORD install(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; ++installs; return installResult; }
static DWORD verify(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; return verifyResult; }
static DWORD publish(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; ++publications; return publishResult; }
static DWORD restore(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; ++restores; return restoreResult; }
static DWORD previous(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; return previousResult; }
static void reset(void)
{
    ZeroMemory(&stored, sizeof(stored)); stored.phase = PB_INSTALL_PREPARED;
    failPhase = installResult = verifyResult = publishResult = restoreResult = previousResult = 0;
    installs = publications = restores = 0;
    targetValidation = rollbackValidation = targetChecks = 0;
}
#define CHECK(x) do { if (!(x)) { printf("Failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    PB_INSTALL_OPERATIONS op = {NULL, validate, install, verify, publish, verify, restore, previous, validateRollback};
    reset();
    CHECK(pb_install_continue(NULL, &op) == 0);
    CHECK(stored.phase == PB_INSTALL_COMMITTED && installs == 1 && publications == 1 && restores == 0);
    reset(); failPhase = PB_INSTALL_DRIVER_CHANGING;
    CHECK(pb_install_continue(NULL, &op) == ERROR_WRITE_FAULT);
    CHECK(installs == 0 && publications == 0 && restores == 0);
    reset(); installResult = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_install_continue(NULL, &op) == ERROR_SUCCESS_REBOOT_REQUIRED);
    CHECK(stored.phase == PB_INSTALL_DRIVER_PENDING && publications == 0);
    verifyResult = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_install_continue(NULL, &op) == ERROR_SUCCESS_REBOOT_REQUIRED);
    CHECK(installs == 1 && publications == 0);
    verifyResult = 0;
    CHECK(pb_install_continue(NULL, &op) == 0);
    CHECK(installs == 1 && publications == 1);
    reset(); stored.phase = PB_INSTALL_APP_CHANGING;
    CHECK(pb_install_continue(NULL, &op) == ERROR_OPERATION_ABORTED);
    CHECK(stored.phase == PB_INSTALL_ROLLED_BACK && publications == 0 && restores == 1);
    reset(); publishResult = ERROR_ACCESS_DENIED; restoreResult = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_install_continue(NULL, &op) == ERROR_SUCCESS_REBOOT_REQUIRED);
    CHECK(stored.phase == PB_INSTALL_ROLLBACK_PENDING);
    CHECK(pb_install_continue(NULL, &op) == ERROR_ACCESS_DENIED);
    CHECK(stored.phase == PB_INSTALL_ROLLED_BACK && restores == 1);
    CHECK(pb_install_continue(NULL, &op) == ERROR_ACCESS_DENIED);
    CHECK(restores == 1);
    reset(); installResult = ERROR_INSTALL_FAILURE; restoreResult = ERROR_ACCESS_DENIED;
    CHECK(pb_install_continue(NULL, &op) == ERROR_ACCESS_DENIED);
    CHECK(stored.phase == PB_INSTALL_RECOVERY_REQUIRED);
    reset(); failPhase = PB_INSTALL_APP_CHANGING;
    CHECK(pb_install_continue(NULL, &op) == ERROR_WRITE_FAULT);
    CHECK(publications == 0 && stored.phase == PB_INSTALL_DRIVER_VERIFIED);
    reset(); stored.phase = PB_INSTALL_DRIVER_PENDING; targetValidation = ERROR_CRC;
    CHECK(pb_install_continue(NULL, &op) == ERROR_CRC);
    CHECK(stored.phase == PB_INSTALL_ROLLED_BACK && installs == 0 && publications == 0 && restores == 1);
    reset(); stored.phase = PB_INSTALL_APP_CHANGING; targetValidation = ERROR_FILE_NOT_FOUND;
    CHECK(pb_install_continue(NULL, &op) == ERROR_OPERATION_ABORTED);
    CHECK(targetChecks == 0 && restores == 1 && stored.phase == PB_INSTALL_ROLLED_BACK);
    reset(); stored.phase = PB_INSTALL_DRIVER_PENDING; targetValidation = ERROR_CRC; rollbackValidation = ERROR_ACCESS_DENIED;
    CHECK(pb_install_continue(NULL, &op) == ERROR_ACCESS_DENIED);
    CHECK(restores == 0 && stored.phase == PB_INSTALL_RECOVERY_REQUIRED);
    puts("Coordinator fault/reboot/recovery checks passed (mock storage and operations).");
    return 0;
}
