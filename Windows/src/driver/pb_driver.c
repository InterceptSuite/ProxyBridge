#include "pb_internal.h"
#include "ProxyBridgeDrv_user.h"

// ProxyBridge <-> ProxyBridgeDrv.sys glue. The WFP connect-redirect driver is the sole capture
// path: it redirects watched connections to the local relay and hands us the PID and the
// original destination, so there is no packet loop, no owner-PID table scan. Full coverage
// TCP + UDP, IPv4 + IPv6 (gated by PBDRV_CONFIG.redirectUdp / redirectIpv6, both on).

BOOL g_use_wfp_driver = TRUE;   // the only capture path (WinDivert fully removed)
static HANDLE g_drv = INVALID_HANDLE_VALUE;

// Connection-log drain: pulls the driver's monitor events (every outbound connect) and turns
// each into a connection-log entry (app / ip / port / proto / action) via the rule engine.
static volatile BOOL g_drain_run = FALSE;
static HANDLE        g_drain_thread = NULL;

static DWORD WINAPI driver_event_drain(LPVOID arg)
{
    (void)arg;
    const DWORD CAP = 256;
    PBDRV_EVENT *buf = (PBDRV_EVENT *)malloc(CAP * sizeof(PBDRV_EVENT));
    if (buf == NULL) return 0;

    while (g_drain_run)
    {
        DWORD got = 0;
        if (g_drv != INVALID_HANDLE_VALUE && pbdrv_pop_events(g_drv, buf, CAP, &got) && got > 0)
        {
            for (DWORD i = 0; i < got; i++)
            {
                PBDRV_EVENT *e = &buf[i];
                BOOL   is_udp = (e->protocol == IPPROTO_UDP);
                BOOL   is_v6  = (e->family == AF_INET6);
                UINT32 cfg    = 0;
                char   pname[MAX_PROCESS_NAME] = "";
                RuleAction act = RULE_ACTION_DIRECT;

                // Resolve the process name: prefer the live PID (gives the full C:\ path so
                // full-path rules work); fall back to the basename the driver captured at connect
                // time, so a process that already exited still logs correctly (never "unknown").
                if (!get_process_name_from_pid(e->pid, pname, sizeof(pname)) && e->image[0] != 0)
                    WideCharToMultiByte(CP_UTF8, 0, e->image, -1, pname, sizeof(pname), NULL, NULL);

                if (pname[0] != '\0')
                    act = is_v6 ? match_rule_v6(pname, e->remoteV6, e->remotePort, is_udp, &cfg)
                                : match_rule(pname, e->remoteV4, e->remotePort, is_udp, &cfg);

                pb_report_connection(e->pid, pname[0] ? pname : NULL, is_v6, e->remoteV4, e->remoteV6,
                                     e->remotePort, act, cfg, is_udp);
            }
            if (got == CAP) continue;   // ring likely still full - drain again without sleeping
        }
        Sleep(150);
    }
    free(buf);
    return 0;
}

// Install (if needed) and start the ProxyBridgeDrv kernel service from <exe dir>\ProxyBridgeDrv.sys.
static BOOL driver_service_start(void)
{
    WCHAR path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return FALSE;
    WCHAR *slash = wcsrchr(path, L'\\');
    if (slash == NULL) return FALSE;
    wcscpy_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - path), L"ProxyBridgeDrv.sys");

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) { log_message("driver: OpenSCManager failed (%lu)", GetLastError()); return FALSE; }

    SC_HANDLE svc = OpenServiceW(scm, L"ProxyBridgeDrv", SERVICE_ALL_ACCESS);
    if (svc == NULL) {
        svc = CreateServiceW(scm, L"ProxyBridgeDrv", L"ProxyBridge WFP", SERVICE_ALL_ACCESS,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             path, NULL, NULL, NULL, NULL, NULL);
        if (svc == NULL) {
            log_message("driver: CreateService failed (%lu) - is ProxyBridgeDrv.sys next to the exe?", GetLastError());
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    BOOL ok = StartServiceW(svc, 0, NULL);
    if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;
    if (!ok) log_message("driver: StartService failed (%lu) - signed? testsigning on?", GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// Push the watch list = image names of enabled PROXY rules (relay refines the decision).
static void driver_push_watchlist(void)
{
    PBDRV_WATCHLIST *wl = (PBDRV_WATCHLIST *)calloc(1, sizeof(*wl));
    if (wl == NULL) return;

    AcquireSRWLockShared(&g_rules_lock);
    for (PROCESS_RULE *r = rules_list; r != NULL && wl->count < PBDRV_MAX_WATCH; r = r->next) {
        // Watch = every app the relay must see: PROXY (redirect to upstream) and BLOCK
        // (redirect so the relay can refuse). DIRECT-only apps are left untouched in-kernel.
        if (!r->enabled || (r->action != RULE_ACTION_PROXY && r->action != RULE_ACTION_BLOCK)) continue;
        if (r->process_name == NULL) continue;
        // process_name is a ';'-delimited list of image patterns; push each token.
        char tmp[1024];
        strncpy_s(tmp, sizeof(tmp), r->process_name, _TRUNCATE);
        char *ctxp = NULL;
        for (char *tok = strtok_s(tmp, ";", &ctxp); tok && wl->count < PBDRV_MAX_WATCH; tok = strtok_s(NULL, ";", &ctxp)) {
            while (*tok == ' ') tok++;
            if (*tok == 0) continue;
            // Leave room for the terminator: a boundary-length name would otherwise fill all
            // PBDRV_NAME_LEN cells with no NUL (or fail and leave a partial entry). The buffer is
            // calloc-zeroed, so forcing image[PBDRV_NAME_LEN-1]=0 guarantees a terminated string.
            MultiByteToWideChar(CP_UTF8, 0, tok, -1, wl->entries[wl->count].image, PBDRV_NAME_LEN - 1);
            wl->entries[wl->count].image[PBDRV_NAME_LEN - 1] = 0;
            wl->count++;
        }
    }
    ReleaseSRWLockShared(&g_rules_lock);

    pbdrv_set_watchlist(g_drv, wl);
    log_message("driver: pushed %u watched image(s)", wl->count);
    free(wl);
}

// Re-push the watch list to the driver after any rule change. Safe to call anytime:
// a no-op until the driver handle is open (rules added before Start are picked up by
// the push in pb_driver_start). This is the hook that makes live Add/Edit/Delete/Enable
// of proxy & block rules take effect without a restart.
void pb_driver_sync_rules(void)
{
    if (!g_use_wfp_driver || g_drv == INVALID_HANDLE_VALUE) return;
    driver_push_watchlist();
}

// Build the driver config: relay endpoints, our own PID (never redirected), full TCP+UDP and
// IPv4+IPv6 coverage, and whether to also redirect loopback traffic (the "Localhost via Proxy"
// option - off by default; most proxies reject localhost and local dev services would break).
static void driver_build_config(PBDRV_CONFIG *cfg, UINT16 relay_port)
{
    memset(cfg, 0, sizeof(*cfg));
    static const UINT8 lb6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    cfg->tcpV4Addr = htonl(INADDR_LOOPBACK); cfg->tcpV4Port = relay_port;          // 127.0.0.1:relay
    memcpy(cfg->tcpV6Addr, lb6, 16);         cfg->tcpV6Port = relay_port;          // [::1]:relay
    cfg->udpV4Addr = htonl(INADDR_LOOPBACK); cfg->udpV4Port = LOCAL_UDP_RELAY_PORT;
    memcpy(cfg->udpV6Addr, lb6, 16);         cfg->udpV6Port = LOCAL_UDP_RELAY_PORT;
    cfg->selfPid            = GetCurrentProcessId();
    cfg->redirectUdp        = 1;
    cfg->redirectIpv6       = 1;
    cfg->redirectLoopbackApps = g_localhost_via_proxy ? 1 : 0;   // "Localhost via Proxy" menu option
}

// Re-push the driver config after a setting change (e.g. "Localhost via Proxy" toggled). No-op
// until the driver is started; the relay port is the one the drain/relay are already using.
void pb_driver_sync_config(void)
{
    if (!g_use_wfp_driver || g_drv == INVALID_HANDLE_VALUE) return;
    PBDRV_CONFIG cfg;
    driver_build_config(&cfg, g_local_relay_port);
    pbdrv_configure(g_drv, &cfg);
}

BOOL pb_driver_start(UINT16 relay_port)
{
    if (!driver_service_start()) return FALSE;

    g_drv = pbdrv_open();
    if (g_drv == INVALID_HANDLE_VALUE) {
        log_message("driver: open \\\\.\\ProxyBridgeDrv failed (%lu) - admin?", GetLastError());
        return FALSE;
    }

    PBDRV_CONFIG cfg;
    driver_build_config(&cfg, relay_port);
    if (!pbdrv_configure(g_drv, &cfg))
        log_message("driver: configure failed (%lu)", GetLastError());

    driver_push_watchlist();
    pbdrv_enable(g_drv, TRUE);

    // Start the connection-log drain (logs every connection: direct/proxy/block).
    g_drain_run = TRUE;
    g_drain_thread = CreateThread(NULL, 0, driver_event_drain, NULL, 0, NULL);

    log_message("driver: ProxyBridgeDrv active - relay 127.0.0.1:%u, TCP+UDP, IPv4+IPv6", relay_port);
    return TRUE;
}

void pb_driver_stop(void)
{
    // Stop the drain thread before closing the handle it uses. Wait INFINITE (not a timeout):
    // the thread reads g_drv, so closing it while the thread is mid pbdrv_pop_events() would be
    // a use-after-close. The loop checks g_drain_run every <=150 ms, so this returns promptly.
    g_drain_run = FALSE;
    if (g_drain_thread != NULL) {
        WaitForSingleObject(g_drain_thread, INFINITE);
        CloseHandle(g_drain_thread);
        g_drain_thread = NULL;
    }
    if (g_drv != INVALID_HANDLE_VALUE) {
        pbdrv_enable(g_drv, FALSE);
        CloseHandle(g_drv);
        g_drv = INVALID_HANDLE_VALUE;
    }
    // Service is left installed; a later start reuses it.
}

// Relay-side (TCP IPv4): original dest + PID for an accepted redirected socket.
BOOL pb_driver_orig_dest(SOCKET s, UINT32 *ip, UINT16 *port, DWORD *pid)
{
    PBDRV_REDIRECT_CTX ctx;
    if (!pbdrv_get_original_dest(s, &ctx)) return FALSE;
    if (ctx.family != AF_INET) return FALSE;
    *ip = ctx.origV4; *port = ctx.origPort;
    if (pid) *pid = ctx.pid;
    return TRUE;
}

// Relay-side (TCP IPv6): original dest + PID for an accepted redirected socket.
BOOL pb_driver_orig_dest6(SOCKET s, UINT8 ip6[16], UINT16 *port, DWORD *pid)
{
    PBDRV_REDIRECT_CTX ctx;
    if (!pbdrv_get_original_dest(s, &ctx)) return FALSE;
    if (ctx.family != AF_INET6) return FALSE;
    memcpy(ip6, ctx.origV6, 16); *port = ctx.origPort;
    if (pid) *pid = ctx.pid;
    return TRUE;
}

// Relay-side (UDP IPv4): recover a redirected datagram's original dest by its source.
BOOL pb_driver_udp_orig(UINT32 src_ip, UINT16 src_port, UINT32 *ip, UINT16 *port, DWORD *pid)
{
    if (g_drv == INVALID_HANDLE_VALUE) return FALSE;
    PBDRV_UDP_QUERY q; memset(&q, 0, sizeof(q));
    q.family = AF_INET; q.srcV4 = src_ip; q.srcPort = src_port;
    if (!pbdrv_udp_query(g_drv, &q) || !q.found) return FALSE;
    *ip = q.origV4; *port = q.origPort;
    if (pid) *pid = q.pid;
    return TRUE;
}
