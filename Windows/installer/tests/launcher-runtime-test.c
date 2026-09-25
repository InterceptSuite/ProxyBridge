#include "../install-store.h"
#include "../install-selection.h"
#include "../install-payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static PB_INSTALL_JOURNAL fixtureRecord;
static DWORD mock_store_open(BOOL create, HKEY *key) { (void)create; *key = (HKEY)1; return 0; }
static DWORD mock_journal_read(HKEY key, PB_INSTALL_JOURNAL *record) { (void)key; *record = fixtureRecord; return 0; }
static LSTATUS mock_close(HKEY key) { (void)key; return 0; }
#define pb_install_store_open mock_store_open
#define pb_journal_read mock_journal_read
#define RegCloseKey mock_close
#define wmain unused_launcher_entry
// Run actual launcher/payload/child creation logic with only journal lookup
// substituted. No real journal keys are read or written by this test.
#include "../launcher.c"
#undef wmain

int wmain(int argc, WCHAR **argv)
{
    if (argc != 3 || wcslen(argv[2]) != 64) return 1;
    fixtureRecord.size = sizeof(fixtureRecord); fixtureRecord.version = PB_JOURNAL_VERSION;
    fixtureRecord.phase = PB_INSTALL_COMMITTED; fixtureRecord.transaction.Data1 = 1;
    fixtureRecord.deviceInstance[0] = L'R'; fixtureRecord.targetProtocol = 4;
    fixtureRecord.targetDriverVersion = 65537;
    if (wcscpy_s(fixtureRecord.targetDirectory, MAX_PATH, argv[1])) return 1;
    for (unsigned i = 0; i < 32; ++i) {
        WCHAR pair[3] = {argv[2][2*i], argv[2][2*i+1], 0}, *end;
        unsigned long byte = wcstoul(pair, &end, 16);
        if (*end || byte > 255) return 1;
        fixtureRecord.targetManifestHash[i] = (BYTE)byte;
    }
    HANDLE inRead, inWrite, outRead, outWrite;
    if (!CreatePipe(&inRead, &inWrite, NULL, 0) || !CreatePipe(&outRead, &outWrite, NULL, 0)) return 1;
    DWORD bytes;
    if (!WriteFile(inWrite, "abc", 3, &bytes, NULL)) return 1;
    CloseHandle(inWrite);
    HANDLE oldIn = GetStdHandle(STD_INPUT_HANDLE), oldOut = GetStdHandle(STD_OUTPUT_HANDLE), oldErr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_INPUT_HANDLE, inRead); SetStdHandle(STD_OUTPUT_HANDLE, outWrite); SetStdHandle(STD_ERROR_HANDLE, outWrite);
    WCHAR *childArgs[] = {L"launcher", L"--cli", L"--profile", L"C:\\space dir\\quoted\"value\\"};
    DWORD result = launch_selected(4, childArgs, TRUE);
    SetStdHandle(STD_INPUT_HANDLE, oldIn); SetStdHandle(STD_OUTPUT_HANDLE, oldOut); SetStdHandle(STD_ERROR_HANDLE, oldErr);
    CloseHandle(inRead); CloseHandle(outWrite);
    char output[16] = {0};
    BOOL read = ReadFile(outRead, output, sizeof(output), &bytes, NULL);
    CloseHandle(outRead);
    if (result != 37 || !read || bytes != 8 || memcmp(output, "child-ok", 8)) {
        printf("CLI child test: exit=%lu bytes=%lu read=%d\n", result, bytes, read); return 1;
    }
    if (!CreatePipe(&outRead, &outWrite, NULL, 0)) return 1;
    SetStdHandle(STD_INPUT_HANDLE, NULL); SetStdHandle(STD_OUTPUT_HANDLE, outWrite); SetStdHandle(STD_ERROR_HANDLE, outWrite);
    WCHAR *partialArgs[] = {L"launcher", L"--cli", L"--no-input"};
    result = launch_selected(3, partialArgs, TRUE);
    SetStdHandle(STD_INPUT_HANDLE, oldIn); SetStdHandle(STD_OUTPUT_HANDLE, oldOut); SetStdHandle(STD_ERROR_HANDLE, oldErr);
    CloseHandle(outWrite);
    ZeroMemory(output, sizeof(output));
    read = ReadFile(outRead, output, sizeof(output), &bytes, NULL);
    CloseHandle(outRead);
    if (result != 37 || !read || bytes != 8 || memcmp(output, "child-ok", 8)) {
        printf("Partial standard handles: exit=%lu bytes=%lu\n", result, bytes); return 1;
    }
    fixtureRecord.phase = PB_INSTALL_DRIVER_PENDING;
    if (launch_selected(4, childArgs, TRUE) != ERROR_INSTALL_SUSPEND) return 1;
    fixtureRecord.phase = PB_INSTALL_COMMITTED; fixtureRecord.targetManifestHash[0] ^= 1;
    if (launch_selected(4, childArgs, TRUE) != ERROR_CRC) return 1;
    puts("Actual child launch, argument/stdin/stdout/exit propagation and pending/hash gates passed.");
    return 0;
}
