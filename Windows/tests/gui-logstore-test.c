#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "../gui/profile/profile.h"
#define MAX_LOG_CHARS 60000
#define AUTO_CLEAR_LINES 500
#include "../gui/ui/logstore-types.h"
static BOOL g_autoClear;
static PBProfile g_profile;
static PBFilter g_flt[PB_MAX_FILTER];
static int g_fltCount;
static volatile LONG live, failCopy;
static void Check(BOOL ok, const char* expr, int line)
{
    if (!ok) { fprintf(stderr, "FAIL line %d: %s\n", line, expr); ExitProcess(1); }
}
#define CHECK(x) Check(!!(x), #x, __LINE__)
static wchar_t* CopyLine(const wchar_t* text)
{
    if (InterlockedExchange(&failCopy, 0)) return NULL;
    size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t);
    wchar_t* out = malloc(bytes);
    CHECK(out != NULL);
    memcpy(out, text, bytes);
    InterlockedIncrement(&live);
    return out;
}
static void FreeLine(void* ptr)
{
    if (ptr) { CHECK(InterlockedDecrement(&live) >= 0); free(ptr); }
}
#define _wcsdup CopyLine
#define free FreeLine
#include "../gui/ui/logview.h"
#undef free
#undef _wcsdup
static LogStore g_connStore, g_actStore;
static volatile LONG g_connectionLogEnabled;
static LONG callbackAllocations;
static void* CallbackAlloc(size_t bytes)
{
    callbackAllocations++;
    if (InterlockedExchange(&failCopy, 0)) return NULL;
    void* ptr = malloc(bytes);
    CHECK(ptr != NULL);
    InterlockedIncrement(&live);
    return ptr;
}
#define malloc CallbackAlloc
#include "../gui/ui/log-callbacks.h"
#undef malloc
static LogStore store;
static wchar_t large[MAX_LOG_CHARS + 2];
static wchar_t readback[4096];
static DWORD WINAPI Producer(void* context)
{
    unsigned id = (unsigned)(ULONG_PTR)context;
    for (int i = 0; i < 5000; i++)
    {
        wchar_t line[64];
        swprintf_s(line, 64, L"%u:%d\r\n", id, i);
        LogStoreQueue(&store, CopyLine(line));
    }
    return 0;
}
static DWORD WINAPI FilterReader(void* context)
{
    (void)context;
    for (int i = 0; i < 10000; i++)
        CHECK(PassesLogFilters(L"alpha", L"127.0.0.1", L"80", L"TCP", L"Direct"));
    return 0;
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    HWND edit = CreateWindowExW(0, L"EDIT", L"", WS_POPUP | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL, 0, 0, 800, 600,
                                NULL, NULL, GetModuleHandleW(NULL), NULL);
    CHECK(edit != NULL); // Hidden stock control, no Core DLL or driver.
    SendMessageW(edit, EM_SETLIMITTEXT, MAX_LOG_CHARS * 2, 0);
    LogStoreInit(&store, edit);
    wchar_t timestamp[16]; GetTimePrefix(timestamp, 16);
    CHECK(wcslen(timestamp) == 11);
    ApplyFilterSnapshot();
    CHECK(PassesLogFilters(L"app", L"1.2.3.4", L"80", L"TCP", L"Direct"));
    for (int i = 0; i < LOG_PEND_MAX + 1; i++)
    {
        wchar_t line[32]; swprintf_s(line, 32, L"%04d\r\n", i);
        LogStoreQueue(&store, CopyLine(line));
    }
    CHECK(store.pendCount == LOG_PEND_MAX && live == LOG_PEND_MAX);
    CHECK(store.dropped == 1);
    CHECK(LogStoreFlush(&store) == LOG_FLUSH_LINES);
    CHECK(store.count == LOG_FLUSH_LINES);
    for (int i = 0; i < LOG_FLUSH_LINES; i++)
    {
        wchar_t line[32]; swprintf_s(line, 32, L"%04d\r\n", LOG_PEND_MAX + i);
        LogStoreQueue(&store, CopyLine(line)); // wrap the pending tail
    }
    LARGE_INTEGER started, finished, frequency;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&started);
    while (LogStoreFlush(&store)) {}
    QueryPerformanceCounter(&finished);
    printf("Hidden-edit backlog drain CPU-side wall time: %.3f ms (timer spacing excluded)\n",
        1000.0 * (double)(finished.QuadPart - started.QuadPart) / (double)frequency.QuadPart);
    CHECK(store.count == LOG_MAX_LINES && live == LOG_MAX_LINES);
    for (int i = 0; i < LOG_MAX_LINES; i++)
    {
        wchar_t expected[32]; swprintf_s(expected, 32, L"%04d\r\n", 4000 + LOG_FLUSH_LINES + i);
        CHECK(wcscmp(store.lines[(store.head + i) % LOG_MAX_LINES], expected) == 0);
    }
    wcscpy_s(store.filter, 128, L"799");
    CHECK(LogLineMatches(&store, L"7990\r\n"));
    LogStoreRebuild(&store);
    GetWindowTextW(edit, readback, 4096);
    CHECK(wcsstr(readback, L"7990\r\n") && wcsstr(readback, L"7999\r\n"));
    CHECK(!wcsstr(readback, L"4000"));
    LogStoreClear(&store);
    CHECK(live == 0 && store.bytes == 0 && store.pendBytes == 0);
    CHECK(!store.dropped && !store.reported);
    store.filter[0] = 0;

    // Pending/history byte caps, oversized rejection, and one maximum line per slice.
    wmemset(large, L'x', MAX_LOG_CHARS + 1); large[MAX_LOG_CHARS + 1] = 0;
    LogStoreQueue(&store, CopyLine(large));
    CHECK(live == 0);
    large[MAX_LOG_CHARS] = 0;
    for (int i = 0; i < 100; i++) LogStoreQueue(&store, CopyLine(large));
    int capacity = (int)(LOG_STORE_BYTES / ((MAX_LOG_CHARS + 1) * sizeof(wchar_t)));
    CHECK(store.pendCount == capacity && store.pendBytes <= LOG_STORE_BYTES);
    CHECK(store.dropped == (ULONGLONG)(101 - capacity)); // oversized plus queue overflow
    CHECK(LogStoreFlush(&store) == 1);
    while (LogStoreFlush(&store)) {}
    for (int i = 0; i < 100; i++) LogStoreAdd(&store, large);
    CHECK(store.count == capacity && store.bytes <= LOG_STORE_BYTES && live == capacity);
    LogStoreClear(&store);

    InterlockedExchange(&failCopy, 1);
    LogStoreAdd(&store, L"allocation failure");
    CHECK(store.count == 0 && live == 0);
    g_autoClear = TRUE;
    for (int i = 0; i <= AUTO_CLEAR_LINES; i++) LogStoreAdd(&store, L"line\r\n");
    CHECK(store.count == 0 && live == 0 && GetWindowTextLengthW(edit) == 0);
    g_autoClear = FALSE;

    const wchar_t* summary = L"Skipped %llu log entries\r\n";
    LogStoreNoteDrop(&store);
    CHECK(LogStoreReportDrops(&store, 100, summary));
    CHECK(store.reported == 1 && store.count == 1);
    LogStoreNoteDrop(&store);
    CHECK(!LogStoreReportDrops(&store, 5099, summary));
    InterlockedExchange(&failCopy, 1);
    CHECK(!LogStoreReportDrops(&store, 5100, summary));
    CHECK(store.reported == 1 && store.dropped == 2);
    CHECK(LogStoreReportDrops(&store, 10100, summary));
    CHECK(store.reported == 2 && store.count == 2);
    GetWindowTextW(edit, readback, 4096);
    CHECK(wcsstr(readback, L"Skipped 2 log entries") != NULL);
    store.dropped = ~(ULONGLONG)0;
    LogStoreNoteDrop(&store); CHECK(store.dropped == ~(ULONGLONG)0);
    LogStoreClear(&store); CHECK(!store.dropped && !store.reported && !live);
    g_autoClear = TRUE;
    for (int i = 0; i < AUTO_CLEAR_LINES; i++) LogStoreAdd(&store, L"line\r\n");
    LogStoreNoteDrop(&store); CHECK(LogStoreReportDrops(&store, 1, summary));
    CHECK(store.count == 1 && store.reported == 1);
    LogStoreClear(&store); g_autoClear = FALSE;

    // Clear and close race with producers. A closed static lock remains usable.
    HANDLE threads[8];
    for (int i = 0; i < 8; i++)
    {
        threads[i] = CreateThread(NULL, 0, Producer, (void*)(ULONG_PTR)i, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    for (int i = 0; i < 100; i++)
    {
        CHECK(LogStoreFlush(&store) <= LOG_FLUSH_LINES);
        if (i % 7 == 0) LogStoreClear(&store);
    }
    LogStoreFree(&store);
    CHECK(WaitForMultipleObjects(8, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (int i = 0; i < 8; i++) CloseHandle(threads[i]);
    LogStoreQueue(&store, CopyLine(L"late callback"));
    ULONGLONG closedDrops = store.dropped;
    LogStoreNoteDrop(&store); CHECK(store.dropped == closedDrops);
    CHECK(live == 0 && store.count == 0 && store.pendCount == 0);
    CHECK(store.bytes == 0 && store.pendBytes == 0);
    // Production callbacks: UTF-8 preservation, exact bounds and heap accounting.
    LogStoreInit(&g_connStore, edit); LogStoreInit(&g_actStore, edit);
    g_connectionLogEnabled = TRUE;
    callbackAllocations = 0;
    PBConnCb("\xD1\x82\xD0\xB5\xD1\x81\xD1\x82.exe", 7, "::1", 443, "Direct (UDP)");
    CHECK(callbackAllocations == 1 && g_connStore.pendCount == 1 && live == 1);
    CHECK(wcsstr(g_connStore.pend[g_connStore.pendHead], L"тест.exe (PID:7) -> ::1:443  via Direct (UDP)\r\n") != NULL);
    PBLogCb("hello");
    CHECK(callbackAllocations == 2 && g_actStore.pendCount == 1 && live == 2);
    g_profile.filterCount = 1;
    wcscpy_s(g_profile.filter[0].mode, 16, L"Exclude");
    ApplyFilterSnapshot();
    PBConnCb("app", 7, "::1", 443, "Direct");
    CHECK(callbackAllocations == 2 && g_connStore.pendCount == 1);
    g_connectionLogEnabled = FALSE;
    PBConnCb("app", 7, "::1", 443, "Direct");
    CHECK(callbackAllocations == 2);
    CHECK(!g_connStore.dropped);
    char boundary[1025]; memset(boundary, 'x', sizeof(boundary)); boundary[1024] = 0;
    PBLogCb(boundary); CHECK(callbackAllocations == 2);
    boundary[1023] = 0;
    PBLogCb(boundary); CHECK(callbackAllocations == 3);
    InterlockedExchange(&failCopy, 1);
    PBLogCb("OOM"); CHECK(callbackAllocations == 4 && g_actStore.pendCount == 2);
    CHECK(g_actStore.dropped == 2);
    LogStoreFree(&g_connStore); LogStoreFree(&g_actStore); CHECK(live == 0);

    // Both complete snapshots allow alpha; a torn pair of beta/beta would reject.
    memset(&g_profile, 0, sizeof(g_profile)); g_profile.filterCount = 2;
    wcscpy_s(g_profile.filter[0].mode, 16, L"Include");
    wcscpy_s(g_profile.filter[1].mode, 16, L"Include");
    wcscpy_s(g_profile.filter[0].proc, 256, L"alpha");
    wcscpy_s(g_profile.filter[1].proc, 256, L"beta"); ApplyFilterSnapshot();
    for (int i = 0; i < 8; i++) {
        threads[i] = CreateThread(NULL, 0, FilterReader, NULL, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    for (int i = 0; i < 2000; i++) {
        wcscpy_s(g_profile.filter[0].proc, 256, (i & 1) ? L"alpha" : L"beta");
        wcscpy_s(g_profile.filter[1].proc, 256, (i & 1) ? L"beta" : L"alpha");
        ApplyFilterSnapshot();
    }
    CHECK(WaitForMultipleObjects(8, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (int i = 0; i < 8; i++) CloseHandle(threads[i]);
    DestroyWindow(edit);
    printf("PASS GUI logstore: FIFO8000/history4000, byte caps,256-line/60000-char slices, "
           "search, OOM, auto-clear,40000 concurrent enqueue attempts, close; zero live allocations\n");
    printf("Each store: pending/history payload <=%u bytes each; metadata=%zu bytes\n",
           LOG_STORE_BYTES, sizeof(LogStore));
    puts("PASS callbacks: one allocation per admitted line, zero when filtered/disabled/oversized; UTF-8, maximum length, OOM;80000 filter reads/2000 publications");
    puts("PASS loss accounting: entry/byte caps, conversion/OOM, five-second summaries, retry, saturation, manual clear and auto-clear visibility; disabled/filtered/closed excluded");
    return 0;
}
