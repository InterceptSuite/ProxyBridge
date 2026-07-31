#include "pb_internal.h"

// Core: shared globals, WFP-driver capture, lifecycle (Start/Stop), DllMain.

// ==== shared global definitions ====
PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
int g_proxy_config_count = 0;
UINT32 g_next_config_id = 1;

CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
// Reverse index keyed by original destination, so inbound UDP relay replies map back to
// the client in O(1) instead of scanning the whole table per datagram (games/downloads
// generate a high inbound packet rate against a large connection table). Both tables are
// guarded by `lock`; every add/update/remove/cleanup keeps them consistent.
CONNECTION_INFO *connection_rev_table[CONNECTION_HASH_SIZE] = {NULL};
LOGGED_CONNECTION *logged_connections = NULL;
int g_logged_count = 0;  // running length of logged_connections (guarded by `lock`)
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
    g_localhost_via_proxy = enable;
    log_message("Localhost routing: %s (most proxies block localhost for SSRF prevention)", enable ? "via proxy" : "direct");
    pb_driver_sync_config();   // push the new loopback setting to the driver (no-op until started)
}

PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback)
{
    g_log_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable)
{
    g_traffic_logging_enabled = enable;
    if (!enable)
    {
        clear_logged_connections();
    }
}

PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void)
{
    clear_logged_connections();
    log_message("Connection logs cleared");
}

// Dedicated cleanup thread - runs independently without blocking packet processing
DWORD WINAPI cleanup_worker(LPVOID arg)
{
    while (running)
    {
        Sleep(30000);  // 30 seconds
        if (running)
        {
            cleanup_stale_connections();
            cleanup_stale_dns_cache();
        }
    }
    return 0;
}

PROXYBRIDGE_API BOOL ProxyBridge_Start(void)
{
    if (running)
        return FALSE;

    InitializeSRWLock(&lock);
    dns_cache_init();

    // If domain rules were configured before start, flush the OS DNS cache so the very
    // first connections re-resolve on the wire and populate our IP->hostname snoop cache.
    if (g_has_domain_rules)
        flush_dns_resolver_cache();

    running = TRUE;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, NULL, 0, NULL);
    if (proxy_thread == NULL)
    {
        running = FALSE;
        return FALSE;
    }

    // Start cleanup thread to avoid blocking packet processing
    cleanup_thread = CreateThread(NULL, 1, cleanup_worker, NULL, 0, NULL);
    if (cleanup_thread == NULL)
    {
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    if (any_socks5_config())
    {
        udp_relay_thread = CreateThread(NULL, 1, udp_relay_server, NULL, 0, NULL);
        if (udp_relay_thread == NULL)
        {
            running = FALSE;
            WaitForSingleObject(cleanup_thread, INFINITE);
            CloseHandle(cleanup_thread);
            cleanup_thread = NULL;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    Sleep(500);

    // Capture is the WFP driver (ProxyBridgeDrv.sys): it redirects watched apps' connections to the
    // relay and hands us PID + original destination. No packet interception in user mode.
    if (!pb_driver_start(g_local_relay_port))
    {
        log_message("Failed to start ProxyBridgeDrv.sys (signed? admin? testsigning?). Aborting.");
        running = FALSE;
        // Join+close EVERY worker started above, not just proxy_thread. Leaving cleanup_thread /
        // udp_relay_thread running with a leaked handle would let a later Start() overwrite the
        // globals and run two of each thread concurrently.
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        if (cleanup_thread != NULL)
        {
            WaitForSingleObject(cleanup_thread, INFINITE);
            CloseHandle(cleanup_thread);
            cleanup_thread = NULL;
        }
        if (udp_relay_thread != NULL)
        {
            WaitForSingleObject(udp_relay_thread, INFINITE);
            CloseHandle(udp_relay_thread);
            udp_relay_thread = NULL;
        }
        return FALSE;
    }
    log_message("Capture: WFP driver (ProxyBridgeDrv.sys)");

    update_has_active_rules();

    log_message("ProxyBridge started");
    log_message("Local relay: localhost:%d", g_local_relay_port);
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        log_message("Proxy config ID %u: %s %s:%u",
            cfg->config_id,
            cfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
            cfg->host, cfg->port);
    }
    if (g_proxy_config_count == 0)
        log_message("Warning: No proxy configs configured");

    int rule_count = 0;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        const char *action_str = (rule->action == RULE_ACTION_PROXY) ? "PROXY" :
                                 (rule->action == RULE_ACTION_BLOCK) ? "BLOCK" : "DIRECT";
        log_message("Rule: %s -> %s", rule->process_name, action_str);
        rule_count++;
        rule = rule->next;
    }
    if (rule_count == 0)
        log_message("No rules configured - all traffic will be direct");

    return TRUE;
}

PROXYBRIDGE_API BOOL ProxyBridge_Stop(void)
{
    if (!running)
        return FALSE;

    running = FALSE;

    pb_driver_stop();

    if (proxy_thread != NULL)
    {
        WaitForSingleObject(proxy_thread, 1000);  // 1 second timeout
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }

    if (cleanup_thread != NULL)
    {
        WaitForSingleObject(cleanup_thread, 1000);  // 1 second timeout
        CloseHandle(cleanup_thread);
        cleanup_thread = NULL;
    }

    if (udp_relay_thread != NULL)
    {
        WaitForSingleObject(udp_relay_thread, 1000);  // 1 second timeout
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }

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

    // Clear logged connections list
    clear_logged_connections();

    // Reset per-port decision cache so stale entries don't carry over
    // if ProxyBridge is stopped and restarted with different rules.
    memset((void*)port_decided_bitmap, 0, sizeof(port_decided_bitmap));
    memset((void*)port_direct_bitmap,  0, sizeof(port_direct_bitmap));

    log_message("ProxyBridge stopped");

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Store the PID of the process that loaded this DLL
            g_current_process_id = GetCurrentProcessId();
            // Initialize Winsock here so that resolve_hostname() / getaddrinfo()
            // work correctly when AddProxyConfig is called before any thread
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
            break;
        }
        case DLL_PROCESS_DETACH:
            // NOTE: joining worker threads from DllMain runs under the loader lock and is a
            // known anti-pattern - callers should ProxyBridge_Stop() explicitly before unload;
            // this is only a best-effort fallback. WSACleanup() MUST come last, after every
            // socket is closed and the relay/worker threads have stopped, or those closes run
            // against an already-torn-down Winsock.
            if (running)
                ProxyBridge_Stop();
            // Close all proxy config UDP sockets
            for (int i = 0; i < g_proxy_config_count; i++)
            {
                PROXY_CONFIG *cfg = &g_proxy_configs[i];
                if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  cfg->udp_tcp_ctrl  = INVALID_SOCKET; }
                if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
            }
            AcquireSRWLockExclusive(&g_rules_lock);
            while (rules_list != NULL)
            {
                PROCESS_RULE *to_free = rules_list;
                rules_list = rules_list->next;

                if (to_free->target_hosts != NULL)
                    free(to_free->target_hosts);
                if (to_free->target_ports != NULL)
                    free(to_free->target_ports);
                if (to_free->target_domains != NULL)
                    free(to_free->target_domains);

                free(to_free);
            }
            ReleaseSRWLockExclusive(&g_rules_lock);
            WSACleanup();
            break;
    }
    return TRUE;
}

