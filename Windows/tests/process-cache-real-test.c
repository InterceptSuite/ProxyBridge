#include "pb_internal.h"
#include "process-name-reference.inc"
static volatile LONG open_calls, query_calls;
static HANDLE counted_open(DWORD access, BOOL inherit, DWORD pid) { InterlockedIncrement(&open_calls); return OpenProcess(access, inherit, pid); }
static BOOL counted_query(HANDLE process, DWORD flags, WCHAR *out, DWORD *size) { InterlockedIncrement(&query_calls); return QueryFullProcessImageNameW(process, flags, out, size); }
#define OpenProcess counted_open
#define QueryFullProcessImageNameW counted_query
#include "../src/net/pb_process_cache.inc"
#undef OpenProcess
#undef QueryFullProcessImageNameW
static DWORD own_pid;
static char expected[1024];
static DWORD WINAPI reader(LPVOID unused) {
    (void)unused;
    for (unsigned i = 0; i < 10000; ++i) {
        char name[1024];
        if (!get_process_name_from_pid(own_pid, name, sizeof(name)) || strcmp(name, expected)) return 1;
    }
    return 0;
}
static DWORD WINAPI clearer(LPVOID unused) {
    (void)unused;
    for (unsigned i = 0; i < 1000; ++i) { pb_process_cache_clear(); SwitchToThread(); }
    return 0;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--cache-child")) { Sleep(1000); return 0; }
    own_pid = GetCurrentProcessId();
    CHECK(reference_process_name(own_pid, expected, sizeof(expected)));
    char name[1024];
    CHECK(get_process_name_from_pid(own_pid, name, sizeof(name)) && !strcmp(name, expected));
    LARGE_INTEGER frequency, start, middle, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    for (unsigned i = 0; i < 20000; ++i) CHECK(reference_process_name(own_pid, name, sizeof(name)) && !strcmp(name, expected));
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) CHECK(get_process_name_from_pid(own_pid, name, sizeof(name)) && !strcmp(name, expected));
    QueryPerformanceCounter(&end);
    CHECK(open_calls == 1 && query_calls == 1);
    printf("20000-self-process-reference-ms=%.3f cached-ms=%.3f; cached OpenProcess=%ld QueryName=%ld\n", (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart, open_calls, query_calls);
    HANDLE threads[5];
    for (unsigned i = 0; i < 5; ++i) { threads[i] = CreateThread(NULL, 0, i == 4 ? clearer : reader, NULL, 0, NULL); CHECK(threads[i] != NULL); }
    CHECK(WaitForMultipleObjects(5, threads, TRUE, 10000) == WAIT_OBJECT_0);
    for (unsigned i = 0; i < 5; ++i) { DWORD code; CHECK(GetExitCodeThread(threads[i], &code) && code == 0); CloseHandle(threads[i]); }
    WCHAR exe[MAX_PATH], command[2 * MAX_PATH + 32];
    CHECK(GetModuleFileNameW(NULL, exe, MAX_PATH) > 0);
    swprintf_s(command, sizeof(command)/sizeof(command[0]), L"\"%s\" --cache-child", exe);
    STARTUPINFOW startup = {sizeof(startup)}; PROCESS_INFORMATION child = {0};
    CHECK(CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child));
    CHECK(get_process_name_from_pid(child.dwProcessId, name, sizeof(name)));
    CHECK(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0);
    // A terminated process may still be queried through a retained parent handle,
    // but its result must no longer be retained as a live cache entry.
    get_process_name_from_pid(child.dwProcessId, name, sizeof(name));
    CHECK(process_cache[process_cache_bucket(child.dwProcessId)].process == NULL);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    pb_process_cache_clear();
    for (unsigned i = 0; i < PB_PROCESS_CACHE_SIZE; ++i) CHECK(process_cache[i].process == NULL && process_cache[i].name == NULL);
    puts("PASS: real process hit, 40000 concurrent reads + 1000 clears, child termination and cleanup");
    return 0;
}
