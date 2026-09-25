#include "pb_internal.h"
LogCallback g_log_callback;
#include "../src/net/pb_logging.inc"
static volatile LONG calls, bad;
static void callback(const char* message)
{
    if (strcmp(message, "event:7") != 0) InterlockedIncrement(&bad);
    InterlockedIncrement(&calls);
}
static void alternate(const char* message) { callback(message); }
static void reentrant(const char* message)
{
    callback(message);
    ProxyBridge_SetLogCallback(NULL);
    log_message("event:%d", 7);
}
static void truncated(const char* message)
{
    if (strlen(message) != LOG_BUFFER_SIZE - 1) InterlockedIncrement(&bad);
    InterlockedIncrement(&calls);
}
static DWORD WINAPI writer(void* arg)
{
    (void)arg;
    for (int i = 0; i < 20000; i++)
        ProxyBridge_SetLogCallback(i % 3 == 0 ? NULL : (i % 3 == 1 ? callback : alternate));
    return 0;
}
static DWORD WINAPI reader(void* arg)
{
    (void)arg;
    for (int i = 0; i < 20000; i++) log_message("event:%d", 7);
    return 0;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    log_message("unused"); CHECK(!calls);
    ProxyBridge_SetLogCallback(reentrant); log_message("event:%d", 7);
    CHECK(calls == 1 && !bad && g_log_callback == NULL);
    char text[LOG_BUFFER_SIZE * 2]; memset(text, 'x', sizeof(text) - 1); text[sizeof(text) - 1] = 0;
    ProxyBridge_SetLogCallback(truncated); log_message("%s", text); CHECK(calls == 2 && !bad);
    HANDLE threads[5];
    ProxyBridge_SetLogCallback(callback);
    for (int i = 0; i < 5; i++) {
        threads[i] = CreateThread(NULL, 0, i == 0 ? writer : reader, NULL, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    CHECK(WaitForMultipleObjects(5, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (int i = 0; i < 5; i++) CloseHandle(threads[i]);
    ProxyBridge_SetLogCallback(NULL);
    LONG before = calls; log_message("unused");
    CHECK(calls == before && !bad);
    puts("PASS logging: disabled, formatted/truncated, self-unregister/reentry,80000 reports/20000 callback publications");
    return 0;
}
