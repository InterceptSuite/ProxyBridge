#include "../install-resume.h"
#include <stdio.h>

static PB_INSTALL_JOURNAL state;
static DWORD readError, applyError, pendingError, publishError, rollbackError, restoreError, markError;
static unsigned applies, verifies, publishes, rollbacks, restores, marks;
static BOOL stalled, visibleCommit;
static DWORD read_record(PB_INSTALL_JOURNAL *out) { *out = state; return readError; }
static DWORD apply(void) {
    ++applies;
    if (!stalled) state.phase = applyError == ERROR_SUCCESS_REBOOT_REQUIRED ? PB_INSTALL_DRIVER_PENDING : PB_INSTALL_DRIVER_VERIFIED;
    return applyError;
}
static DWORD verify(void) { ++verifies; if (!pendingError) state.phase = PB_INSTALL_DRIVER_VERIFIED; return pendingError; }
static DWORD publish(void) { ++publishes; if (!publishError || visibleCommit) state.phase = PB_INSTALL_COMMITTED; return publishError; }
static DWORD rollback(void) { ++rollbacks; if (!rollbackError) state.phase = PB_INSTALL_ROLLING_BACK; return rollbackError; }
static DWORD restore(void) { ++restores; if (!restoreError) state.phase = PB_INSTALL_ROLLED_BACK; return restoreError; }
static DWORD mark(DWORD error) {
    ++marks;
    if (markError) return markError;
    if (state.phase == PB_INSTALL_COMMITTED) return ERROR_INVALID_STATE;
    state.phase = PB_INSTALL_ROLLING_BACK; state.lastError = error; return 0;
}
static void reset(void) {
    ZeroMemory(&state, sizeof(state)); state.phase = PB_INSTALL_PREPARED;
    readError = applyError = pendingError = publishError = rollbackError = restoreError = markError = 0;
    applies = verifies = publishes = rollbacks = restores = marks = 0;
    stalled = visibleCommit = FALSE;
}
#define CHECK(x) do { if (!(x)) { printf("Failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    const PB_INSTALL_STEPS steps = {read_record, apply, verify, publish, rollback, restore, mark};
    CHECK(pb_resume_install(NULL) == ERROR_INVALID_PARAMETER);
    reset(); CHECK(pb_resume_install(&steps) == 0);
    CHECK(applies == 1 && publishes == 1 && rollbacks == 0);
    CHECK(pb_resume_install(&steps) == 0 && applies == 1 && publishes == 1);
    reset(); applyError = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_resume_install(&steps) == ERROR_SUCCESS_REBOOT_REQUIRED && publishes == 0);
    pendingError = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_resume_install(&steps) == ERROR_SUCCESS_REBOOT_REQUIRED && applies == 1 && marks == 0);
    pendingError = 0; CHECK(pb_resume_install(&steps) == 0 && applies == 1 && verifies == 2 && publishes == 1);
    reset(); publishError = ERROR_ACCESS_DENIED;
    CHECK(pb_resume_install(&steps) == ERROR_ACCESS_DENIED && state.phase == PB_INSTALL_ROLLED_BACK);
    CHECK(rollbacks == 1 && restores == 1);
    CHECK(pb_resume_install(&steps) == ERROR_ACCESS_DENIED && rollbacks == 1);
    reset(); state.phase = PB_INSTALL_DRIVER_CHANGING;
    rollbackError = ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(pb_resume_install(&steps) == ERROR_SUCCESS_REBOOT_REQUIRED && restores == 0 && applies == 0);
    rollbackError = 0; CHECK(pb_resume_install(&steps) == ERROR_INSTALL_FAILURE && restores == 1);
    reset(); state.phase = PB_INSTALL_APP_CHANGING; rollbackError = ERROR_ACCESS_DENIED;
    CHECK(pb_resume_install(&steps) == ERROR_ACCESS_DENIED && restores == 0 && publishes == 0);
    reset(); state.phase = PB_INSTALL_RECOVERY_REQUIRED; restoreError = ERROR_WRITE_FAULT;
    CHECK(pb_resume_install(&steps) == ERROR_WRITE_FAULT && rollbacks == 1 && restores == 1);
    reset(); readError = ERROR_INVALID_DATA;
    CHECK(pb_resume_install(&steps) == ERROR_INVALID_DATA && applies == 0 && rollbacks == 0);
    reset(); publishError = ERROR_WRITE_FAULT; visibleCommit = TRUE;
    CHECK(pb_resume_install(&steps) == ERROR_WRITE_FAULT && state.phase == PB_INSTALL_COMMITTED && rollbacks == 0);
    CHECK(pb_resume_install(&steps) == 0 && publishes == 1);
    reset(); applyError = ERROR_ACCESS_DENIED; markError = ERROR_WRITE_FAULT;
    CHECK(pb_resume_install(&steps) == ERROR_ACCESS_DENIED && rollbacks == 0);
    reset(); stalled = TRUE;
    CHECK(pb_resume_install(&steps) == ERROR_INVALID_STATE && applies == 1);
    puts("install resume tests passed"); return 0;
}
