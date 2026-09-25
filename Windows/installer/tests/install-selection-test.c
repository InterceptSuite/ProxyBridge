#include "../install-selection.h"
#include <stdio.h>
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { printf("Selection failure line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    PB_INSTALL_JOURNAL record = {0};
    record.size = sizeof(record); record.version = PB_JOURNAL_VERSION;
    record.transaction.Data1 = 1; record.deviceInstance[0] = L'R';
    record.targetProtocol = 4; record.targetDriverVersion = 65537; record.targetManifestHash[0] = 1;
    wcscpy_s(record.targetDirectory, MAX_PATH, L"C:\\new");
    PB_APP_SELECTION selected;
    wcscpy_s(record.removalInf, MAX_PATH, L"oem1.inf");
    for (DWORD phase = PB_INSTALL_PREPARED; phase <= PB_INSTALL_CLEANED; ++phase) {
        record.phase = phase;
        DWORD result = pb_select_application(&record, &selected);
        if (phase == PB_INSTALL_COMMITTED) {
            CHECK(result == 0 && !wcscmp(selected.directory, record.targetDirectory));
            CHECK(selected.protocol == 4 && selected.driverVersion == 65537 && selected.manifestHash[0] == 1);
        } else if (phase == PB_INSTALL_ROLLED_BACK || phase == PB_INSTALL_REMOVED || phase == PB_INSTALL_CLEANED) CHECK(result == ERROR_NOT_FOUND);
        else CHECK(result == ERROR_INSTALL_SUSPEND && !selected.directory[0]);
    }
    record.phase = PB_INSTALL_ROLLED_BACK;
    wcscpy_s(record.previousDirectory, MAX_PATH, L"C:\\previous");
    record.previousProtocol = 3; record.previousDriverVersion = 65536; record.previousManifestHash[0] = 2;
    CHECK(pb_select_application(&record, &selected) == 0);
    CHECK(!wcscmp(selected.directory, record.previousDirectory) && selected.protocol == 3 &&
           selected.driverVersion == 65536 && selected.manifestHash[0] == 2);
    record.version++;
    CHECK(pb_select_application(&record, &selected) == ERROR_INVALID_DATA && !selected.directory[0]);
    puts("Application selection pending/commit/rollback checks passed; no registry writes.");
    return 0;
}
