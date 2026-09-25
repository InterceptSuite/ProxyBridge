#include "../install-resume.h"
#include <stdio.h>
static PB_INSTALL_JOURNAL testRecord;
static DWORD readError, operationError;
static unsigned removals, cleanups, mutations;
static DWORD read_transaction(PB_INSTALL_JOURNAL *out) { *out = testRecord; return readError; }
static DWORD uninstall_recorded(void) { ++removals; return operationError; }
static DWORD cleanup_recorded(void) { ++cleanups; return operationError; }
static DWORD apply_recorded_driver(void) { ++mutations; testRecord.phase = PB_INSTALL_DRIVER_VERIFIED; return 0; }
static DWORD verify_pending_driver(void) { ++mutations; return ERROR_SUCCESS_REBOOT_REQUIRED; }
static DWORD publish_target(void) { ++mutations; testRecord.phase = PB_INSTALL_COMMITTED; return 0; }
static DWORD rollback_recorded_driver(void) { ++mutations; return ERROR_ACCESS_DENIED; }
static DWORD restore_previous(void) { ++mutations; return 0; }
static DWORD mark_rollback(DWORD error) { ++mutations; return error; }
#include "../install-resume-dispatch.inc"
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    const DWORD errors[] = {0, ERROR_SUCCESS_REBOOT_REQUIRED, ERROR_ACCESS_DENIED};
    for (DWORD phase = PB_INSTALL_REMOVING; phase <= PB_INSTALL_CLEANED; ++phase) {
        for (unsigned i = 0; i < ARRAYSIZE(errors); ++i) {
            testRecord.phase = phase; operationError = errors[i];
            removals = cleanups = mutations = 0;
            CHECK(resume_recorded_install(TRUE) == ERROR_INVALID_STATE);
            CHECK(removals == 0 && cleanups == 0 && mutations == 0);
            CHECK(resume_recorded_install(FALSE) == operationError);
            CHECK(removals == (unsigned)(phase < PB_INSTALL_CLEANING));
            CHECK(cleanups == (unsigned)(phase >= PB_INSTALL_CLEANING));
            CHECK(mutations == 0);
        }
    }
    for (unsigned only = 0; only < 2; ++only) {
        testRecord.phase = PB_INSTALL_PREPARED; mutations = 0;
        CHECK(resume_recorded_install((BOOL)only) == 0 && mutations == 2);
        CHECK(resume_recorded_install((BOOL)only) == 0 && mutations == 2);
        testRecord.phase = PB_INSTALL_DRIVER_PENDING;
        CHECK(resume_recorded_install((BOOL)only) == ERROR_SUCCESS_REBOOT_REQUIRED);
        testRecord.phase = PB_INSTALL_ROLLED_BACK; testRecord.lastError = ERROR_WRITE_FAULT;
        CHECK(resume_recorded_install((BOOL)only) == ERROR_WRITE_FAULT);
        mutations = removals = cleanups = 0; readError = ERROR_INVALID_DATA;
        CHECK(resume_recorded_install((BOOL)only) == ERROR_INVALID_DATA);
        CHECK(mutations == 0 && removals == 0 && cleanups == 0);
        readError = 0; testRecord.phase = 999;
        CHECK(resume_recorded_install((BOOL)only) == ERROR_INVALID_STATE);
    }
    puts("PASS resume dispatch: 15 removal/error combinations, install/pending/rollback/read-error/unknown phases");
    return 0;
}
