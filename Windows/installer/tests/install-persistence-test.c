#include "../install-journal.h"
#include <stdio.h>
#include <string.h>

static PB_INSTALL_JOURNAL disk;
static BOOL exists;
static DWORD storedType = REG_BINARY, size = sizeof(disk), writeError, flushError;
static unsigned writes, flushes;
static LSTATUS mockRead(HKEY key, LPCWSTR name, LPDWORD reserved, LPDWORD outType, LPBYTE data, LPDWORD bytes)
{
    (void)key; (void)name; (void)reserved;
    if (!exists) return ERROR_FILE_NOT_FOUND;
    *outType = storedType;
    if (*bytes < size) { *bytes = size; return ERROR_MORE_DATA; }
    memcpy(data, &disk, size); *bytes = size; return 0;
}
static LSTATUS mockWrite(HKEY key, LPCWSTR name, DWORD reserved, DWORD inType, const BYTE *data, DWORD bytes)
{
    (void)key; (void)name; (void)reserved; ++writes;
    if (writeError) return (LSTATUS)writeError;
    if (bytes != sizeof(disk)) return ERROR_INVALID_DATA;
    memcpy(&disk, data, bytes); size = bytes; storedType = inType; exists = TRUE; return 0;
}
static LSTATUS mockFlush(HKEY key) { (void)key; ++flushes; return (LSTATUS)flushError; }
// Execute production journal code against deterministic failing storage. These
// substitutions are confined to this test translation unit.
#define RegQueryValueExW mockRead
#define RegSetValueExW mockWrite
#define RegFlushKey mockFlush
#include "../install-journal.c"
#include "../install-coordinator.c"

static unsigned mutations;
static DWORD ok(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; return 0; }
static DWORD mutate(void *p, const PB_INSTALL_JOURNAL *r) { (void)p; (void)r; ++mutations; return 0; }
#define CHECK(x) do { if (!(x)) { printf("Failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    PB_INSTALL_JOURNAL record = {0}, readback;
    record.size = sizeof(record); record.version = PB_JOURNAL_VERSION;
    record.transaction.Data1 = 1; record.phase = PB_INSTALL_PREPARED;
    record.targetProtocol = 4; record.targetDriverVersion = 0x10001;
    record.deviceInstance[0] = L'R';
    record.targetManifestHash[0] = 1;
    wcscpy_s(record.targetDirectory, MAX_PATH, L"C:\\staged");
    CHECK(pb_journal_begin(NULL, &record) == 0 && writes == 1 && flushes == 1);
    CHECK(pb_journal_begin(NULL, &record) == ERROR_BUSY && writes == 1);
    PB_INSTALL_JOURNAL stale = record;
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_DRIVER_CHANGING, 0) == 0);
    CHECK(pb_journal_advance(NULL, &stale, PB_INSTALL_DRIVER_CHANGING, 0) == ERROR_REVISION_MISMATCH);
    writeError = ERROR_DISK_FULL;
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_DRIVER_PENDING, 3010) == ERROR_DISK_FULL);
    CHECK(record.phase == PB_INSTALL_DRIVER_CHANGING && disk.phase == record.phase);
    writeError = 0; flushError = ERROR_WRITE_FAULT;
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_DRIVER_PENDING, 3010) == ERROR_WRITE_FAULT);
    CHECK(record.phase == PB_INSTALL_DRIVER_CHANGING && disk.phase == PB_INSTALL_DRIVER_PENDING);
    CHECK(pb_journal_read(NULL, &readback) == 0 && readback.phase == PB_INSTALL_DRIVER_PENDING);
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_DRIVER_PENDING, 3010) == ERROR_REVISION_MISMATCH);
    storedType = REG_SZ;
    CHECK(pb_journal_read(NULL, &readback) == ERROR_INVALID_DATA);
    CHECK(pb_journal_begin(NULL, &stale) == ERROR_INVALID_DATA);
    storedType = REG_BINARY; size--;
    CHECK(pb_journal_read(NULL, &readback) == ERROR_INVALID_DATA);
    size = sizeof(disk); disk = stale;
    PB_INSTALL_OPERATIONS op = {NULL, ok, mutate, ok, mutate, ok, mutate, ok, ok};
    // Flush may have persisted DRIVER_CHANGING, but no callback can run until
    // persistence succeeds. A subsequent resume must recover, not reinstall.
    CHECK(pb_install_continue(NULL, &op) == ERROR_WRITE_FAULT && mutations == 0);
    CHECK(disk.phase == PB_INSTALL_DRIVER_CHANGING);
    flushError = 0;
    CHECK(pb_install_continue(NULL, &op) == ERROR_OPERATION_ABORTED && mutations == 1);
    CHECK(disk.phase == PB_INSTALL_ROLLED_BACK);
    CHECK(pb_journal_read(NULL, &record) == 0);
    CHECK(pb_journal_begin_remove(NULL, &record, L"..\\other.inf") == ERROR_INVALID_PARAMETER);
    writeError = ERROR_DISK_FULL;
    CHECK(pb_journal_begin_remove(NULL, &record, L"oem12.inf") == ERROR_DISK_FULL);
    CHECK(disk.phase == PB_INSTALL_ROLLED_BACK);
    writeError = 0; flushError = ERROR_WRITE_FAULT;
    CHECK(pb_journal_begin_remove(NULL, &record, L"oem12.inf") == ERROR_WRITE_FAULT);
    CHECK(record.phase == PB_INSTALL_ROLLED_BACK && disk.phase == PB_INSTALL_REMOVING);
    CHECK(pb_journal_blocks_launch(disk.phase));
    flushError = 0;
    CHECK(pb_journal_begin_remove(NULL, &record, L"oem12.inf") == ERROR_REVISION_MISMATCH);
    CHECK(pb_journal_read(NULL, &record) == 0);
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_REMOVE_PENDING, 3010) == 0);
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_REMOVED, 0) == 0);
    flushError = ERROR_WRITE_FAULT;
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_CLEANING, 0) == ERROR_WRITE_FAULT);
    CHECK(record.phase == PB_INSTALL_REMOVED && disk.phase == PB_INSTALL_CLEANING);
    CHECK(pb_journal_blocks_launch(disk.phase));
    flushError = 0;
    CHECK(pb_journal_read(NULL, &record) == 0);
    CHECK(pb_journal_advance(NULL, &record, PB_INSTALL_CLEANED, 0) == 0);
    stale.transaction.Data1++;
    CHECK(pb_journal_begin(NULL, &stale) == 0);
    puts("Production journal/coordinator storage-failure checks passed; no registry writes.");
    return 0;
}
