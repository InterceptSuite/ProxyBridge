#include "../install-journal.h"
#include <stdio.h>

#define CHECK(test) do { if (!(test)) { printf("Failed line %d: %s\n", __LINE__, #test); return 1; } } while (0)

int main(void)
{
    const DWORD complete[] = {PB_INSTALL_COMMITTED, PB_INSTALL_ROLLED_BACK};
    for (DWORD phase = 0; phase <= PB_INSTALL_CLEANED + 1; ++phase) {
        CHECK(pb_journal_blocks_launch(phase) ==
              (phase != complete[0] && phase != complete[1]));
        CHECK(!pb_journal_transition_allowed(phase, phase));
        CHECK(!pb_journal_transition_allowed(phase, 0));
        CHECK(!pb_journal_transition_allowed(phase, PB_INSTALL_CLEANED + 1));
        CHECK(!pb_journal_transition_allowed(PB_INSTALL_COMMITTED, phase));
        CHECK(!pb_journal_transition_allowed(PB_INSTALL_ROLLED_BACK, phase));
    }
    CHECK(!pb_journal_transition_allowed(PB_INSTALL_DRIVER_PENDING, PB_INSTALL_COMMITTED));
    CHECK(!pb_journal_transition_allowed(PB_INSTALL_ROLLBACK_PENDING, PB_INSTALL_COMMITTED));
    CHECK(!pb_journal_transition_allowed(PB_INSTALL_RECOVERY_REQUIRED, PB_INSTALL_ROLLED_BACK));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_DRIVER_CHANGING, PB_INSTALL_DRIVER_PENDING));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_DRIVER_PENDING, PB_INSTALL_DRIVER_VERIFIED));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_DRIVER_VERIFIED, PB_INSTALL_APP_CHANGING));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_APP_CHANGING, PB_INSTALL_COMMITTED));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_ROLLING_BACK, PB_INSTALL_ROLLBACK_PENDING));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_ROLLBACK_PENDING, PB_INSTALL_ROLLED_BACK));
    CHECK(pb_journal_validate(NULL) == ERROR_INVALID_DATA);
    PB_INSTALL_JOURNAL record = {0};
    CHECK(pb_journal_validate(&record) == ERROR_INVALID_DATA);
    record.size = sizeof(record);
    record.version = PB_JOURNAL_VERSION;
    record.transaction.Data1 = 1;
    record.phase = PB_INSTALL_PREPARED;
    record.targetProtocol = 4;
    record.deviceInstance[0] = L'R';
    record.targetManifestHash[0] = 1;
    record.targetDriverVersion = 0x10001;
    record.targetDirectory[0] = L'C';
    CHECK(pb_journal_validate(&record) == ERROR_SUCCESS);
    record.phase = PB_INSTALL_REMOVING;
    CHECK(pb_journal_validate(&record) == ERROR_INVALID_DATA);
    wcscpy_s(record.removalInf, MAX_PATH, L"oem1.inf");
    CHECK(pb_journal_validate(&record) == ERROR_SUCCESS);
    CHECK(pb_journal_transition_allowed(PB_INSTALL_REMOVING, PB_INSTALL_REMOVE_PENDING));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_REMOVE_PENDING, PB_INSTALL_REMOVING));
    CHECK(pb_journal_transition_allowed(PB_INSTALL_REMOVE_PENDING, PB_INSTALL_REMOVED));
    CHECK(!pb_journal_transition_allowed(PB_INSTALL_REMOVING, PB_INSTALL_COMMITTED));
    record.version++;
    CHECK(pb_journal_validate(&record) == ERROR_INVALID_DATA);
    record.version = PB_JOURNAL_VERSION;
    record.previousInf[MAX_PATH - 1] = L'x';
    CHECK(pb_journal_validate(&record) == ERROR_INVALID_DATA);
    puts("Journal state and malformed-record checks passed. No registry writes performed.");
    return 0;
}
