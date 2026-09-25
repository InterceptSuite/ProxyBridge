#include "../install-payload.h"
#include "../install-pair.h"
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>

int wmain(int argc, WCHAR **argv)
{
    if (argc != 4 || wcslen(argv[2]) != 64) return 1;
    BYTE hash[32];
    for (unsigned i = 0; i < 32; ++i) {
        WCHAR pair[3] = {argv[2][2*i], argv[2][2*i+1], 0}, *end;
        unsigned long value = wcstoul(pair, &end, 16);
        if (*end || value > 255) return 1;
        hash[i] = (BYTE)value;
    }
    PB_VERIFIED_PAYLOAD payload;
    DWORD result = pb_payload_open(argv[1], hash, 4, 0x10001, &payload);
    DWORD expected = wcstoul(argv[3], NULL, 10);
    if (result != expected) { printf("Expected %lu, got %lu\n", expected, result); return 1; }
    if (result == ERROR_SUCCESS) {
        WCHAR path[MAX_PATH];
        swprintf_s(path, MAX_PATH, L"%s\\ProxyBridgeCore.dll", argv[1]);
        HANDLE writer = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD error = GetLastError();
        if (writer != INVALID_HANDLE_VALUE) { CloseHandle(writer); pb_payload_close(&payload); return 1; }
        if (error != ERROR_SHARING_VIOLATION) { pb_payload_close(&payload); return 1; }
        HANDLE renameAccess = CreateFileW(argv[1], DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        error = GetLastError();
        if (renameAccess != INVALID_HANDLE_VALUE) { puts("Directory DELETE access unexpectedly granted"); CloseHandle(renameAccess); pb_payload_close(&payload); return 1; }
        if (error != ERROR_SHARING_VIOLATION) { printf("Directory DELETE access error: %lu\n", error); pb_payload_close(&payload); return 1; }
    } else {
        for (unsigned i = 0; i < ARRAYSIZE(payload.files); ++i) if (payload.files[i]) return 1;
        if (payload.directoryCount) return 1;
    }
    pb_payload_close(&payload);
    if (result == ERROR_SUCCESS) {
        PB_INSTALL_JOURNAL record = {0};
        record.size = sizeof(record); record.version = PB_JOURNAL_VERSION;
        record.transaction.Data1 = 1; record.phase = PB_INSTALL_PREPARED;
        record.targetProtocol = record.previousProtocol = 4;
        record.deviceInstance[0] = L'R';
        record.targetDriverVersion = record.previousDriverVersion = 0x10001;
        wcscpy_s(record.targetDirectory, MAX_PATH, argv[1]);
        wcscpy_s(record.previousDirectory, MAX_PATH, argv[1]);
        memcpy(record.targetManifestHash, hash, 32);
        memcpy(record.previousManifestHash, hash, 32);
        PB_TRANSACTION_PAYLOADS pair;
        if (pb_transaction_payloads_open(&record, &pair)) return 1;
        pb_transaction_payloads_close(&pair);
        record.previousManifestHash[0] ^= 1;
        if (pb_transaction_payloads_open(&record, &pair) != ERROR_CRC) return 1;
        if (pair.target.directoryCount || pair.previous.directoryCount) return 1;
        for (unsigned i = 0; i < ARRAYSIZE(pair.target.files); ++i)
            if (pair.target.files[i] || pair.previous.files[i]) return 1;
        record.previousManifestHash[0] ^= 1;
        wcscpy_s(record.targetDirectory, MAX_PATH, L"C:\\missing-target-for-rollback");
        if (pb_rollback_payload_open(&record, &pair)) return 1;
        if (pair.target.directoryCount || !pair.previous.directoryCount) return 1;
        pb_transaction_payloads_close(&pair);
    }
    printf("Payload verification expected result %lu passed.\n", expected);
    return 0;
}
