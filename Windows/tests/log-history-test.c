#include "pb_internal.h"
BOOL g_traffic_logging_enabled = TRUE;
ConnectionCallback g_connection_callback;
#include "../src/relay/pb_log_history.inc"
#include "../src/relay/pb_connection_report.inc"
BOOL get_process_name_from_pid(DWORD pid, char *out, DWORD size) { (void)pid; (void)out; (void)size; return FALSE; }
const char *extract_filename(const char *name) { return name; }
static PB_LOG_KEY common;
static volatile LONG accepted;
static DWORD WINAPI writer(LPVOID unused) {
    (void)unused;
    for (unsigned i = 0; i < 10000; ++i) if (pb_log_connection_once(&common, TRUE)) InterlockedIncrement(&accepted);
    return 0;
}
static unsigned used(void) { unsigned n = 0; for (unsigned i = 0; i < PB_LOG_CAPACITY; ++i) n += !!log_entries[i].used; return n; }
static unsigned callbacks;
static BOOL reenter, clear_in_callback;
static void callback(const char *name, DWORD pid, const char *ip, UINT16 port, const char *info) {
    (void)name; (void)pid; (void)ip; (void)port; (void)info; ++callbacks;
    if (clear_in_callback) clear_logged_connections();
    if (reenter) { reenter = FALSE; pb_report_connection(12, "app.exe", FALSE, 1, NULL, 443, RULE_ACTION_DIRECT, 0, FALSE, NULL); }
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    PB_LOG_KEY key = {0}; key.pid = 12; key.ipv6 = TRUE; key.address[14] = 1;
    CHECK(pb_log_connection_once(&key, TRUE));
    key.address[14] = 0; key.address[15] = 31; // same old 32-bit fold, different IPv6 address
    CHECK(pb_log_connection_once(&key, TRUE));
    CHECK(!pb_log_connection_once(&key, TRUE));
    key.udp = TRUE; CHECK(pb_log_connection_once(&key, TRUE));
    key.ipv6 = FALSE; CHECK(pb_log_connection_once(&key, TRUE));
    key.proxy_id = 55; CHECK(pb_log_connection_once(&key, TRUE));
    ++key.proxy_revision; CHECK(pb_log_connection_once(&key, TRUE));
    CHECK(used() == 6);
    clear_logged_connections();
    for (unsigned i = 0; i < 101; ++i) { key.dest_port = (UINT16)i; CHECK(pb_log_connection_once(&key, TRUE)); }
    CHECK(used() == 100);
    key.dest_port = 0; CHECK(pb_log_connection_once(&key, FALSE));
    key.dest_port = 100; CHECK(!pb_log_connection_once(&key, FALSE));
    clear_logged_connections(); common = key;
    HANDLE threads[8];
    for (unsigned i = 0; i < 8; ++i) { threads[i] = CreateThread(NULL, 0, writer, NULL, 0, NULL); CHECK(threads[i] != NULL); }
    CHECK(WaitForMultipleObjects(8, threads, TRUE, 10000) == WAIT_OBJECT_0);
    for (unsigned i = 0; i < 8; ++i) CloseHandle(threads[i]);
    CHECK(accepted == 1 && used() == 1);
    pb_set_traffic_logging(FALSE);
    CHECK(pb_log_connection_once(&common, TRUE) && used() == 0); // stale producer cannot repopulate
    pb_set_traffic_logging(TRUE);
    g_connection_callback = callback; reenter = TRUE;
    pb_report_connection(12, "app.exe", FALSE, 1, NULL, 443, RULE_ACTION_DIRECT, 0, FALSE, NULL);
    CHECK(callbacks == 1 && used() == 1);
    clear_logged_connections(); clear_in_callback = TRUE;
    pb_report_connection(12, "app.exe", FALSE, 1, NULL, 443, RULE_ACTION_DIRECT, 0, FALSE, NULL);
    CHECK(callbacks == 2 && used() == 0);
    printf("PASS: full-key separation, 100-entry FIFO, 80000 concurrent duplicate reports, disable, callback reentry/clear; storage=%zu\n", sizeof(log_entries)+sizeof(log_buckets));
    return 0;
}
