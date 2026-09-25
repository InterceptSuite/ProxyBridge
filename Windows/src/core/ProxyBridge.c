#include "pb_internal.h"
#include "../../shared/update-guard.h"
#include "../../installer/install-store.h"
#include "../../installer/install-selection.h"
#include "../driver/ProxyBridgeDrv_ioctl.h"

// Core: shared globals, WFP-driver capture, lifecycle (Start/Stop), DllMain.

// ==== shared global definitions ====
PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
int g_proxy_config_count = 0;
UINT32 g_next_config_id = 1;
volatile LONG64 g_proxy_revision = 0;

CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
// Reverse index keyed by original destination, so inbound UDP relay replies map back to
// the client in O(1) instead of scanning the whole table per datagram (games/downloads
// generate a high inbound packet rate against a large connection table). Both tables are
// guarded by `lock`; every add/update/remove/cleanup keeps them consistent.
CONNECTION_INFO *connection_rev_table[CONNECTION_HASH_SIZE] = {NULL};
PROCESS_RULE *rules_list = NULL;
UINT32 g_next_rule_id = 1;
SRWLOCK lock;

// Guards rules_list and the rule nodes/strings it points to. Separate from `lock`
// (which guards the connection table + PID cache) so rule edits from the GUI thread
// never block the packet path's connection bookkeeping. A zero-initialised SRWLOCK is
// already in the valid unlocked state, so this is safe to use before ProxyBridge_Start.
SRWLOCK g_rules_lock;
// Guards g_proxy_configs[]/g_proxy_config_count. Zero-init = valid unlocked SRWLOCK.
SRWLOCK g_proxy_lock;
HANDLE proxy_thread = NULL;
HANDLE udp_relay_thread = NULL;
HANDLE cleanup_thread = NULL;
static HANDLE g_cleanup_stop = NULL;
static HMODULE g_runtime_module = NULL;
static HANDLE g_update_guard = NULL;

static DWORD check_installation_state(void)
{
    HKEY key;
    DWORD error = pb_install_store_open(FALSE, &key);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
    if (error != ERROR_SUCCESS) return error;
    PB_INSTALL_JOURNAL record;
    error = pb_journal_read(key, &record);
    RegCloseKey(key);
    if (error == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if (error != ERROR_SUCCESS) return error;
    PB_APP_SELECTION selection;
    error = pb_select_application(&record, &selection);
    if (error != ERROR_SUCCESS) return error;
    HMODULE current;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&g_update_guard, &current)) return GetLastError();
    WCHAR path[MAX_PATH];
    DWORD length = GetModuleFileNameW(current, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    WCHAR *separator = wcsrchr(path, L'\\');
    if (!separator) return ERROR_INVALID_NAME;
    *separator = 0;
    if (_wcsicmp(path, selection.directory) || selection.protocol != PBDRV_PROTOCOL_VERSION ||
        selection.driverVersion != PBDRV_DRIVER_VERSION) return ERROR_REVISION_MISMATCH;
    return ERROR_SUCCESS;
}
enum { PB_STOPPED, PB_STARTING, PB_RUNNING, PB_STOPPING };
static volatile LONG g_lifecycle_state = PB_STOPPED;
BOOL g_relay_ipv6_ready = FALSE;
volatile BOOL g_has_active_rules = FALSE;
// Set when at least one enabled rule carries a domain filter. Gates the DNS-cache
// lookup in match_rule so setups without domain rules pay zero extra cost.
volatile BOOL g_has_domain_rules = FALSE;
SOCKET udp_relay_socket = INVALID_SOCKET;
SOCKET udp_relay_socket6 = INVALID_SOCKET;
volatile BOOL running = FALSE;
DWORD g_current_process_id = 0;

BOOL g_traffic_logging_enabled = TRUE;

DNS_CACHE_ENTRY    *g_dns_cache[DNS_CACHE_BUCKETS];
DNS_CACHE_ENTRY_V6 *g_dns_cache_v6[DNS_CACHE_BUCKETS];
SRWLOCK             g_dns_cache_lock;

// per src port decision cache.
//
// check_process_rule() resolves (src_port) to DIRECT, PROXY, or BLOCK,
// every subsequent packet from that port gets the cached answer in 5 cycles
// (one atomic read). this is needed else every outbound data/ack segment from an
// established connection re runs the full check_process_rule() path:
//   GetExtendedTcpTable (malloc + kernel roundtrip)
//   + OpenProcess + QueryFullProcessImageName
//   + rule list walk
// On a sustained 300 Mbps download (17 000 packets/sec) that is thousands of
// kernel calls per second, saturating a single core.
//
// Layout: two 2048-LONG bitmaps, 8 KB each.
//   port_decided_bitmap : bit set = decision is cached for this port
//   port_direct_bitmap  : bit set = decision was DIRECT (bit clear = PROXY/BLOCK)
// Together they encode three states per port:
//   decided=0            -> no cached decision, call check_process_rule
//   decided=1, direct=1  -> DIRECT, pass packet unchanged
//   decided=1, direct=0  -> already added to connection (PROXY/BLOCK handled)
//
// Thread safety: InterlockedOr/And for writes; plain aligned 32-bit read for
// reads (x86/x64 aligned read is atomic; we only need visibility, not ordering).
volatile LONG port_decided_bitmap[2048] = {0};  // 8 KB
volatile LONG port_direct_bitmap[2048]  = {0};  // 8 KB

UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
BOOL g_localhost_via_proxy = FALSE;  // default disabled for security - most proxy server block localhost for ssrf and also many app might not work if localhost trafic goes to remote server if proxy server is on diffrent machine
LogCallback g_log_callback = NULL;
ConnectionCallback g_connection_callback = NULL;

PROXYBRIDGE_API void ProxyBridge_SetLocalhostViaProxy(BOOL enable)
{
    (void)ProxyBridge_SetLocalhostViaProxyChecked(enable);
}

PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    InterlockedExchangePointer((PVOID volatile *)&g_connection_callback, (PVOID)callback);
}

PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable)
{
    pb_set_traffic_logging(enable);
}

PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void)
{
    clear_logged_connections();
    log_message("Connection logs cleared");
}

// Dedicated cleanup thread - runs independently without blocking packet processing
DWORD WINAPI cleanup_worker(LPVOID arg)
{
    HANDLE stop = (HANDLE)arg;
    while (WaitForSingleObject(stop, 30000) == WAIT_TIMEOUT)
    {
        if (running)
        {
            cleanup_stale_connections();
            cleanup_stale_dns_cache();
        }
    }
    return 0;
}

static BOOL wait_relay_ready(HANDLE ready, HANDLE worker)
{
    // Failure before bind/listen signals the thread handle, not the ready event.
    HANDLE handles[] = { ready, worker };
    DWORD result = WaitForMultipleObjects(2, handles, FALSE, 10000);
    if (result == WAIT_OBJECT_0 && WaitForSingleObject(worker, 0) == WAIT_TIMEOUT)
        return TRUE;
    if (result != WAIT_FAILED)
        SetLastError(result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_NOT_READY);
    return FALSE;
}

static void join_worker(HANDLE *worker)
{
    if (*worker != NULL) {
        WaitForSingleObject(*worker, INFINITE);
        CloseHandle(*worker);
        *worker = NULL;
    }
}

PROXYBRIDGE_API BOOL ProxyBridge_Start(void)
{
    if (InterlockedCompareExchange(&g_lifecycle_state, PB_STARTING, PB_STOPPED) != PB_STOPPED) {
        SetLastError(ERROR_BUSY);
        return FALSE;
    }

    PB_RELAY_STARTUP tcpStartup = {0};
    PB_RELAY_STARTUP udpStartup = {0};
    BOOL winsockStarted = FALSE;
    WSADATA wsa;
    DWORD updateError = pb_update_guard_acquire(&g_update_guard);
    if (updateError == ERROR_SUCCESS) updateError = check_installation_state();
    if (updateError != ERROR_SUCCESS) {
        SetLastError(updateError);
        goto start_failed;
    }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)&g_lifecycle_state, &g_runtime_module)) goto start_failed;
    int wsaError = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaError != 0) {
        SetLastError((DWORD)wsaError);
        goto start_failed;
    }
    winsockStarted = TRUE;

    // Global SRW locks are initialized once, before any public API can use them.
    dns_cache_clear();

    // If domain rules were configured before start, flush the OS DNS cache so the very
    // first connections re-resolve on the wire and populate our IP->hostname snoop cache.
    if (g_has_domain_rules)
        flush_dns_resolver_cache();

    tcpStartup.readyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (tcpStartup.readyEvent == NULL) goto start_failed;
    udpStartup.readyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (udpStartup.readyEvent == NULL) goto start_failed;
    g_cleanup_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_cleanup_stop == NULL) goto start_failed;
    g_relay_ipv6_ready = FALSE;
    running = TRUE;
    if (!pb_tcp_start_workers()) goto start_failed;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, &tcpStartup, 0, NULL);
    if (proxy_thread == NULL)
    {
        goto start_failed;
    }

    // Start cleanup thread to avoid blocking packet processing
    cleanup_thread = CreateThread(NULL, 1, cleanup_worker, g_cleanup_stop, 0, NULL);
    if (cleanup_thread == NULL)
    {
        goto start_failed;
    }

    // Keep the listener available when a live profile later adds SOCKS5 rules.
    {
        udp_relay_thread = CreateThread(NULL, 1, udp_relay_server, &udpStartup, 0, NULL);
        if (udp_relay_thread == NULL)
        {
            goto start_failed;
        }
    }

    if (!wait_relay_ready(tcpStartup.readyEvent, proxy_thread) ||
        (udp_relay_thread != NULL && !wait_relay_ready(udpStartup.readyEvent, udp_relay_thread))) {
        log_message("Relay listeners did not become ready (%lu)", GetLastError());
        goto start_failed;
    }
    g_relay_ipv6_ready = tcpStartup.ipv6Ready && udpStartup.ipv6Ready;
    if (!g_relay_ipv6_ready) {
        log_message("IPv6 TCP/UDP listeners are unavailable; capture was not enabled");
        SetLastError(ERROR_NOT_READY);
        goto start_failed;
    }
    CloseHandle(tcpStartup.readyEvent);
    tcpStartup.readyEvent = NULL;
    CloseHandle(udpStartup.readyEvent);
    udpStartup.readyEvent = NULL;

    // Capture is the WFP driver (ProxyBridgeDrv.sys): it redirects watched apps' connections to the
    // relay and hands us PID + original destination. No packet interception in user mode.
    if (!pb_driver_start(g_local_relay_port))
    {
        log_message("Driver activation failed. Aborting.");
        goto start_failed;
    }
    log_message("Capture: WFP driver (ProxyBridgeDrv.sys)");

    // pb_driver_start already applied the complete initial watchlist. Do not
    // perform another unchecked update after activation.

    log_message("ProxyBridge started");
    log_message("Local relay: localhost:%d", g_local_relay_port);
    PROXY_CONFIG configSnapshot[MAX_PROXY_CONFIGS];
    LONG64 configRevision;
    int configCount = pb_proxy_snapshot(configSnapshot, &configRevision);
    for (int i = 0; i < configCount; i++)
    {
        const PROXY_CONFIG *cfg = &configSnapshot[i];
        if (cfg->config_id == 0) continue;
        log_message("Proxy config ID %u: %s %s:%u", cfg->config_id,
            cfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5", cfg->host, cfg->port);
    }
    if (configCount == 0) log_message("Warning: No proxy configs configured");

    int rule_count = 0;
    AcquireSRWLockShared(&g_rules_lock);
    for (const PROCESS_RULE *rule = rules_list; rule != NULL; rule = rule->next) ++rule_count;
    ReleaseSRWLockShared(&g_rules_lock);
    // Logging can call user code; never retain a pointer into a replaceable list.
    log_message("Configured rules: %d", rule_count);
    if (rule_count == 0)
        log_message("No rules configured - all traffic will be direct");

    InterlockedExchange(&g_lifecycle_state, PB_RUNNING);
    return TRUE;

start_failed: {
    DWORD error = GetLastError();
    running = FALSE;
    if (g_cleanup_stop != NULL) SetEvent(g_cleanup_stop);
    join_worker(&proxy_thread);
    pb_tcp_stop_workers();
    join_worker(&udp_relay_thread);
    join_worker(&cleanup_thread);
    pb_process_cache_clear();
    if (g_cleanup_stop != NULL) CloseHandle(g_cleanup_stop);
    g_cleanup_stop = NULL;
    // A worker that failed or timed out could still have been using its startup
    // context. Join it before releasing the context/events.
    if (tcpStartup.readyEvent != NULL) CloseHandle(tcpStartup.readyEvent);
    if (udpStartup.readyEvent != NULL) CloseHandle(udpStartup.readyEvent);
    g_relay_ipv6_ready = FALSE;
    if (winsockStarted) WSACleanup();
    HMODULE module = g_runtime_module;
    g_runtime_module = NULL;
    pb_update_guard_release(&g_update_guard);
    InterlockedExchange(&g_lifecycle_state, PB_STOPPED);
    // The caller retains its LoadLibrary reference until this API returns.
    if (module != NULL) FreeLibrary(module);
    SetLastError(error);
    return FALSE;
}
}

PROXYBRIDGE_API BOOL ProxyBridge_IsFilteringActive(void)
{
    return InterlockedCompareExchange(&g_lifecycle_state, 0, 0) == PB_RUNNING &&
           pb_driver_is_active();
}

PROXYBRIDGE_API BOOL ProxyBridge_Stop(void)
{
    if (InterlockedCompareExchange(&g_lifecycle_state, PB_STOPPING, PB_RUNNING) != PB_RUNNING) {
        SetLastError(ERROR_BUSY);
        return FALSE;
    }

    // Synchronous log callbacks can re-enter the public API on a worker.
    // Never join that same thread. The caller can schedule Stop on its UI thread.
    DWORD caller = GetCurrentThreadId();
    if ((proxy_thread != NULL && GetThreadId(proxy_thread) == caller) ||
        (udp_relay_thread != NULL && GetThreadId(udp_relay_thread) == caller) ||
        (cleanup_thread != NULL && GetThreadId(cleanup_thread) == caller) ||
        pb_driver_is_worker_thread() || pb_tcp_is_worker_thread()) {
        InterlockedExchange(&g_lifecycle_state, PB_RUNNING);
        SetLastError(ERROR_BUSY);
        return FALSE;
    }

    running = FALSE;
    SetEvent(g_cleanup_stop);

    pb_driver_stop();

    join_worker(&proxy_thread);
    pb_tcp_stop_workers();
    join_worker(&cleanup_thread);
    join_worker(&udp_relay_thread);
    CloseHandle(g_cleanup_stop);
    g_cleanup_stop = NULL;
    g_relay_ipv6_ready = FALSE;

    AcquireSRWLockExclusive(&lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != NULL)
        {
            CONNECTION_INFO *to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            free(to_free);
        }
    }
    // Entries were freed via the forward table above; just drop the reverse index's
    // dangling bucket pointers so a later Start doesn't walk freed memory.
    memset(connection_rev_table, 0, sizeof(connection_rev_table));
    ReleaseSRWLockExclusive(&lock);

    dns_cache_clear();

    pb_process_cache_clear();
    // Clear logged connections list
    clear_logged_connections();

    // Reset per-port decision cache so stale entries don't carry over
    // if ProxyBridge is stopped and restarted with different rules.
    memset((void*)port_decided_bitmap, 0, sizeof(port_decided_bitmap));
    memset((void*)port_direct_bitmap,  0, sizeof(port_direct_bitmap));

    log_message("ProxyBridge stopped");

    WSACleanup();
    HMODULE module = g_runtime_module;
    g_runtime_module = NULL;
    pb_update_guard_release(&g_update_guard);
    InterlockedExchange(&g_lifecycle_state, PB_STOPPED);
    // Drop only our active-session reference; the caller still owns its reference.
    FreeLibrary(module);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_current_process_id = GetCurrentProcessId();
    } else if (fdwReason == DLL_PROCESS_DETACH && lpReserved == NULL) {
        // Explicit unload is allowed only after Stop and all API calls return.
        // No threads, waits, locks, Winsock calls, or callbacks under loader lock.
        // At process termination let the OS reclaim memory; heap state may be torn down.
        pb_process_cache_dispose();
        while (rules_list != NULL) {
            PROCESS_RULE *rule = rules_list;
            rules_list = rule->next;
            free(rule->target_hosts);
            free(rule->target_ports);
            free(rule->target_domains);
            free(rule->prepared_process);
            free(rule->prepared_ports);
            free(rule->prepared_domains);
            free(rule->prepared_ipv6);
            free(rule->prepared_ipv4);
            free(rule);
        }

    }
    return TRUE;
}
