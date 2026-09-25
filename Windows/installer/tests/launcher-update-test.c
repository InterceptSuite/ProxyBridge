#include "../install-store.h"
#include "../install-selection.h"
#include "../install-payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static PB_INSTALL_JOURNAL fixture;
static DWORD expectedVersion;
static unsigned launches;
static DWORD fake_open(BOOL create, HKEY *key) { (void)create; *key = (HKEY)1; return 0; }
static DWORD fake_read(HKEY key, PB_INSTALL_JOURNAL *out) { (void)key; *out = fixture; return 0; }
static LSTATUS fake_close(HKEY key) { (void)key; return 0; }
// Real benign child processes; only the test waits inside CreateProcess so it
// can check which GUI ran. Production launcher remains asynchronous for GUI.
static BOOL WINAPI checked_create(LPCWSTR app, LPWSTR command, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process)
{
    ++launches;
    if (!CreateProcessW(app, command, pa, ta, inherit, flags, env, cwd, startup, process)) return FALSE;
    DWORD code = 0;
    BOOL ok = WaitForSingleObject(process->hProcess, 5000) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process->hProcess, &code) && code == expectedVersion;
    if (!ok) {
        CloseHandle(process->hThread); CloseHandle(process->hProcess);
        SetLastError(ERROR_INVALID_DATA);
    }
    return ok;
}
#define pb_install_store_open fake_open
#define pb_journal_read fake_read
#define RegCloseKey fake_close
#define CreateProcessW checked_create
#define wmain unused_launcher_entry
#include "../launcher.c"
#undef wmain

static BOOL parse_hash(const WCHAR *text, BYTE out[32])
{
    if (wcslen(text) != 64) return FALSE;
    for (unsigned i = 0; i < 32; ++i) {
        WCHAR pair[] = {text[2*i], text[2*i+1], 0}, *end;
        unsigned long n = wcstoul(pair, &end, 16);
        if (*end || n > 255) return FALSE;
        out[i] = (BYTE)n;
    }
    return TRUE;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int wmain(int argc, WCHAR **argv)
{
    CHECK(argc == 5);
    fixture.size = sizeof(fixture); fixture.version = PB_JOURNAL_VERSION;
    fixture.transaction.Data1 = 1; fixture.phase = PB_INSTALL_COMMITTED;
    fixture.targetProtocol = fixture.previousProtocol = 4;
    fixture.targetDriverVersion = fixture.previousDriverVersion = 65537;
    wcscpy_s(fixture.deviceInstance, ARRAYSIZE(fixture.deviceInstance), L"ROOT\\TEST");
    wcscpy_s(fixture.removalInf, MAX_PATH, L"oem42.inf");
    CHECK(!wcscpy_s(fixture.targetDirectory, MAX_PATH, argv[1]));
    CHECK(parse_hash(argv[2], fixture.targetManifestHash));
    WCHAR *guiArgs[] = {L"retained-launcher", L"--minimized"};
    WCHAR *cliArgs[] = {L"retained-launcher", L"--cli", L"--identity"};
    expectedVersion = 41;
    CHECK(launch_selected(2, guiArgs, FALSE) == 0);
    CHECK(launch_selected(3, cliArgs, TRUE) == 41);
    // The launcher stays in place; only the protected journal selection changes.
    wcscpy_s(fixture.previousDirectory, MAX_PATH, fixture.targetDirectory);
    memcpy(fixture.previousManifestHash, fixture.targetManifestHash, 32);
    CHECK(!wcscpy_s(fixture.targetDirectory, MAX_PATH, argv[3]));
    CHECK(parse_hash(argv[4], fixture.targetManifestHash));
    expectedVersion = 42;
    CHECK(launch_selected(2, guiArgs, FALSE) == 0);
    CHECK(launch_selected(3, cliArgs, TRUE) == 42);
    fixture.phase = PB_INSTALL_ROLLED_BACK; expectedVersion = 41;
    CHECK(launch_selected(2, guiArgs, FALSE) == 0);
    CHECK(launch_selected(3, cliArgs, TRUE) == 41);
    CHECK(launches == 6);
    for (DWORD phase = PB_INSTALL_PREPARED; phase <= PB_INSTALL_CLEANED; ++phase) {
        if (phase == PB_INSTALL_COMMITTED || phase == PB_INSTALL_ROLLED_BACK) continue;
        fixture.phase = phase;
        DWORD error = phase == PB_INSTALL_REMOVED || phase == PB_INSTALL_CLEANED ? ERROR_NOT_FOUND : ERROR_INSTALL_SUSPEND;
        CHECK(launch_selected(2, guiArgs, FALSE) == error);
    }
    fixture.phase = PB_INSTALL_COMMITTED; ++fixture.version;
    CHECK(launch_selected(2, guiArgs, FALSE) == ERROR_INVALID_DATA);
    --fixture.version; fixture.targetManifestHash[0] ^= 1;
    CHECK(launch_selected(2, guiArgs, FALSE) == ERROR_CRC);
    CHECK(launches == 6);
    puts("PASS retained launcher: GUI/CLI A -> B -> rollback A; blocked phases/new journal format/hash rejection launch no child");
    return 0;
}
