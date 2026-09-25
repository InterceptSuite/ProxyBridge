#include "../install-device-identity.h"
#include <stdio.h>
#include <wchar.h>

#define CHECK(x) do { if (!(x)) { printf("Identity test line %d failed\n", __LINE__); return 1; } } while (0)
int main(void)
{
    PB_INSTALL_JOURNAL record = {0};
    record.size = sizeof(record); record.version = PB_JOURNAL_VERSION;
    record.phase = PB_INSTALL_PREPARED; record.transaction.Data1 = 123;
    record.targetProtocol = 4; record.targetDriverVersion = 65537;
    record.targetDirectory[0] = L'C'; record.targetManifestHash[0] = 1;
    CHECK(pb_plan_device_instance(&record.transaction, record.deviceInstance) == 0);
    WCHAR again[200];
    CHECK(pb_plan_device_instance(&record.transaction, again) == 0);
    CHECK(wcscmp(again, record.deviceInstance) == 0);
    CHECK(wcsncmp(again, L"ROOT\\InterceptSuite_ProxyBridge\\", 31) == 0);
    CHECK(pb_check_device_instance(&record, FALSE, NULL) == 0);
    CHECK(pb_check_device_before_install(&record, FALSE, NULL, NULL) == 0);
    CHECK(pb_check_device_before_install(&record, TRUE, again, NULL) == ERROR_ALREADY_EXISTS);
    CHECK(pb_check_device_instance(&record, TRUE, again) == 0);
    CHECK(pb_check_device_instance(&record, TRUE, L"ROOT\\other\\0000") == ERROR_REVISION_MISMATCH);
    record.deviceExisted = 1;
    record.previousDirectory[0] = L'C'; record.previousManifestHash[0] = 1;
    record.previousProtocol = 4; record.previousDriverVersion = 65537;
    wcscpy_s(record.previousInf, MAX_PATH, L"oem42.inf");
    CHECK(pb_check_device_before_install(&record, TRUE, again, L"oem42.inf") == 0);
    CHECK(pb_check_device_before_install(&record, TRUE, again, L"oem43.inf") == ERROR_REVISION_MISMATCH);
    record.phase = PB_INSTALL_DRIVER_CHANGING;
    CHECK(pb_check_device_before_install(&record, TRUE, again, L"oem42.inf") == ERROR_INVALID_STATE);
    record.phase = PB_INSTALL_PREPARED;
    CHECK(pb_check_device_instance(&record, FALSE, NULL) == ERROR_NOT_FOUND);
    CHECK(pb_check_device_instance(&record, TRUE, again) == 0);
    record.deviceExisted = 2;
    CHECK(pb_check_device_instance(&record, TRUE, again) == ERROR_INVALID_DATA);
    puts("Device transaction identity checks passed; no device API mutations.");
    return 0;
}
