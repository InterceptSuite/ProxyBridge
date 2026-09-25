#include "pb_internal.h"
#include "../src/relay/pb_connection_report.inc"
#include "../src/driver/ProxyBridgeDrv_ioctl.h"
#include "../src/driver/pb_driver_event_report.inc"

BOOL g_traffic_logging_enabled;
ConnectionCallback g_connection_callback;
static unsigned lookups, histories, callbacks, dedups, proxy_lookups;
static BOOL duplicate;
static BOOL lookup_fails;
static unsigned selections;
static BOOL selected_v6, selected_udp;
static char last_process[MAX_PROCESS_NAME];
static char last_info[160];
static PB_LOG_KEY last_key;
BOOL pb_log_connection_once(const PB_LOG_KEY *key, BOOL record)
{
    ++dedups; last_key = *key;
    if (duplicate) return FALSE;
    if (record) ++histories;
    return TRUE;
}
BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD size)
{
    (void)pid; ++lookups;
    if (lookup_fails) return FALSE;
    strcpy_s(name, size, "resolved.exe"); return TRUE;
}
RuleAction pb_select_proxy(const char *name, BOOL v6, UINT32 ip, const UINT8 ip6[16], UINT16 port,
                          BOOL udp, UINT32 *id, PROXY_CONFIG *config, BOOL *available)
{
    (void)name; (void)ip; (void)ip6; (void)port;
    ++selections; selected_v6 = v6; selected_udp = udp;
    memset(config, 0, sizeof(*config));
    config->config_id = *id = 55; config->revision = 77; config->port = 1080;
    strcpy_s(config->host, sizeof(config->host), "event-proxy");
    *available = TRUE; return RULE_ACTION_PROXY;
}
const char *extract_filename(const char *name) { return name; }
BOOL find_proxy_config_copy(UINT32 id, PROXY_CONFIG *config)
{
    (void)id; ++proxy_lookups; memset(config, 0, sizeof(*config));
    strcpy_s(config->host, sizeof(config->host), "test"); config->port = 1080; return TRUE;
}
static void callback(const char *process, DWORD pid, const char *ip, UINT16 port, const char *info)
{
    (void)pid; (void)ip; (void)port; (void)info;
    ++callbacks; strcpy_s(last_process, sizeof(last_process), process);
    strcpy_s(last_info, sizeof(last_info), info);
}
// Actual GUI toggle helper with DLL setter adapters; reporting below is production.
static BOOL g_trafficLog;
static volatile LONG g_connectionLogEnabled;
static unsigned setter_order;
static void set_callback(ConnectionCallback cb)
{
    setter_order = setter_order * 10 + 1;
    g_connection_callback = cb;
}
static void set_history(BOOL enabled)
{
    setter_order = setter_order * 10 + 2;
    g_traffic_logging_enabled = enabled;
}
static struct {
    void (*SetConnectionCallback)(ConnectionCallback);
    void (*SetTrafficLoggingEnabled)(BOOL);
} g_api = {set_callback, set_history};
#define PBConnCb callback
#include "../gui/ui/traffic-logging.h"
#undef PBConnCb
static void report(const char *name)
{
    pb_report_connection(123, name, FALSE, htonl(INADDR_LOOPBACK), NULL, 443, RULE_ACTION_PROXY, 1, TRUE, NULL);
}
#define CHECK(condition) do { if (!(condition)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    report(NULL);
    CHECK(!dedups && !histories && !lookups && !callbacks && !proxy_lookups);
    g_traffic_logging_enabled = TRUE;
    report(NULL);
    CHECK(histories == 1 && dedups == 1 && lookups == 0 && proxy_lookups == 0);
    g_connection_callback = callback; g_traffic_logging_enabled = FALSE;
    report("provided.exe");
    CHECK(callbacks == 1 && histories == 1 && lookups == 0 && proxy_lookups == 0 && !strcmp(last_process, "provided.exe"));
    report(NULL);
    CHECK(callbacks == 2 && lookups == 1 && !strcmp(last_process, "resolved.exe"));
    duplicate = TRUE; g_traffic_logging_enabled = TRUE;
    report(NULL);
    CHECK(callbacks == 2 && histories == 1 && lookups == 1 && proxy_lookups == 0);
    duplicate = FALSE;
    PROXY_CONFIG selected = {0};
    strcpy_s(selected.host, sizeof(selected.host), "selected-host"); selected.port = 1080;
    selected.config_id = 55; selected.revision = 77; selected.type = PROXY_TYPE_SOCKS5;
    pb_report_connection(123, "provided.exe", FALSE, htonl(INADDR_LOOPBACK), NULL, 443, RULE_ACTION_PROXY, 0, TRUE, &selected);
    CHECK(strstr(last_info, "selected-host:1080") != NULL && last_key.proxy_id == 55 && last_key.proxy_revision == 77 && proxy_lookups == 0);
    lookups = histories = callbacks = dedups = 0;
    for (int i = 0; i < 10000; i++) {
        g_trafficLog = FALSE; setter_order = 0;
        ApplyTrafficLogging();
        CHECK(setter_order == 12 && !g_connectionLogEnabled && !g_connection_callback && !g_traffic_logging_enabled);
        report(NULL);
        CHECK(lookups == (unsigned)i && histories == (unsigned)i && callbacks == (unsigned)i && dedups == (unsigned)i);
        g_trafficLog = TRUE; setter_order = 0;
        ApplyTrafficLogging();
        CHECK(setter_order == 21 && g_connectionLogEnabled && g_connection_callback == callback && g_traffic_logging_enabled);
        report(NULL);
    }
    CHECK(lookups == 10000 && histories == 10000 && callbacks == 10000 && dedups == 10000 && proxy_lookups == 0);
    lookups = histories = callbacks = dedups = selections = 0;
    PBDRV_EVENT event = {0}; event.pid = 123; event.family = AF_INET; event.protocol = IPPROTO_TCP;
    event.remotePort = 443; event.remoteV4 = htonl(INADDR_LOOPBACK);
    g_trafficLog = FALSE; ApplyTrafficLogging();
    for (int i = 0; i < 10000; i++) driver_report_event(&event);
    CHECK(!lookups && !selections && !histories && !callbacks && !dedups);
    g_traffic_logging_enabled = TRUE; // numeric-only consumer still needs the decision
    driver_report_event(&event);
    CHECK(lookups == 1 && selections == 1 && histories == 1 && !callbacks && !selected_v6 && !selected_udp);
    CHECK(last_key.proxy_id == 55 && last_key.proxy_revision == 77);
    g_connection_callback = callback; g_traffic_logging_enabled = FALSE;
    lookup_fails = TRUE;
    wcscpy_s(event.image, PBDRV_EVENT_NAME_LEN, L"captured.exe");
    event.family = AF_INET6; event.protocol = IPPROTO_UDP; event.remoteV6[15] = 1;
    driver_report_event(&event);
    CHECK(callbacks == 1 && selections == 2 && selected_v6 && selected_udp);
    CHECK(!strcmp(last_process, "captured.exe") && strstr(last_info, "event-proxy:1080") != NULL);
    event.image[0] = 0; driver_report_event(&event);
    CHECK(callbacks == 2 && selections == 2 && last_key.action == RULE_ACTION_DIRECT);
    CHECK(!strcmp(last_process, "unknown"));
    puts("PASS: no consumers, numeric history, provided name, callback without history, fallback lookup, dedup");
    puts("PASS: production GUI toggle,10000 off/on cycles; disabled reports skip dedup, lookup and callback; enabled restores delivery");
    puts("PASS:10000 disabled driver events skip preparation; numeric/callback-only modes, captured-name fallback, IPv4/TCP, IPv6/UDP, unknown-name behavior");
    return 0;
}
