#include "pb_internal.h"
#include "ProxyBridgeDrv_user.h"
#include <fwpmu.h>
#include <stdint.h>

// ProxyBridge <-> ProxyBridgeDrv.sys glue. The WFP connect-redirect driver is the sole capture
// path: it redirects watched connections to the local relay and hands us the PID and the
// original destination, so there is no packet loop, no owner-PID table scan. Full coverage
// TCP + UDP, IPv4 + IPv6 (gated by PBDRV_CONFIG.redirectUdp / redirectIpv6, both on).

BOOL g_use_wfp_driver = TRUE;   // the only capture path (WinDivert fully removed)
static HANDLE g_drv = INVALID_HANDLE_VALUE;
static volatile LONG g_filtering_active = FALSE;
static volatile LONG64 g_driver_session_epoch = 0;
static SRWLOCK g_driver_handle_lock = SRWLOCK_INIT;

// Connection-log drain: pulls the driver's monitor events (every outbound connect) and turns
// each into a connection-log entry (app / ip / port / proto / action) via the rule engine.
static volatile LONG g_drain_run = FALSE;
static HANDLE        g_drain_thread = NULL;
#define PB_DRAIN_CAP 256u

static HANDLE driver_open_configured(UINT16 relay_port);

LONG64 pb_driver_session_epoch(void)
{
    return InterlockedCompareExchange64(&g_driver_session_epoch, 0, 0);
}

BOOL pb_driver_is_active(void)
{
    return InterlockedCompareExchange(&g_filtering_active, 0, 0) != 0;
}

static BOOL relay_threads_alive(void)
{
    // Core joins this worker before closing either relay thread handle.
    return proxy_thread != NULL && udp_relay_thread != NULL &&
        WaitForSingleObject(proxy_thread, 0) == WAIT_TIMEOUT &&
        WaitForSingleObject(udp_relay_thread, 0) == WAIT_TIMEOUT;
}


#include "pb_driver_event_report.inc"

static DWORD WINAPI driver_event_drain(LPVOID arg)
{
    const DWORD CAP = PB_DRAIN_CAP;
    PBDRV_EVENT *buf = (PBDRV_EVENT *)arg;
    ULONGLONG reconnectAt = 0;
    DWORD reconnectDelay = 250;
    ULONGLONG statusAt = 0;
    BOOL admissionWarningShown = FALSE;

    while (InterlockedCompareExchange(&g_drain_run, 0, 0))
    {
        if (!relay_threads_alive()) {
            InterlockedExchange(&g_filtering_active, FALSE);
            AcquireSRWLockExclusive(&g_driver_handle_lock);
            HANDLE stale = g_drv;
            g_drv = INVALID_HANDLE_VALUE;
            InterlockedIncrement64(&g_driver_session_epoch);
            ReleaseSRWLockExclusive(&g_driver_handle_lock);
            if (stale != INVALID_HANDLE_VALUE) {
                pbdrv_enable(stale, FALSE);
                CloseHandle(stale);
            }
            log_message("driver: relay worker exited; filtering disabled, restart required");
            break; // Never reconnect capture to a dead listener.
        }
        BOOL warnAdmission = FALSE;
        DWORD got = 0;
        AcquireSRWLockShared(&g_driver_handle_lock);
        BOOL ok = g_drv != INVALID_HANDLE_VALUE && pbdrv_pop_events(g_drv, buf, CAP, &got);
        if (ok && GetTickCount64() >= statusAt) {
            PBDRV_STATUS state;
            ok = pbdrv_get_status(g_drv, &state) &&
                 (state.flags & PBDRV_STATUS_ACTIVE) != 0;
            if (ok) {
                BOOL rejected = (state.flags & PBDRV_STATUS_UDP_ADMISSION_FAILED) != 0;
                warnAdmission = rejected && !admissionWarningShown;
                admissionWarningShown = rejected;
            }
            InterlockedExchange(&g_filtering_active, ok);
            statusAt = GetTickCount64() + 500;
        }
        ReleaseSRWLockShared(&g_driver_handle_lock);
        if (warnAdmission)
            log_message("driver: UDP admission rejected (capacity, allocation, missing endpoint or conflicting mapping); affected attempts were blocked, not sent direct");
        if (ok && got > 0)
        {
            for (DWORD i = 0; i < got; i++)
            {
                PBDRV_EVENT *e = &buf[i];
                driver_report_event(e);
            }
            if (got == CAP) continue;   // ring likely still full - drain again without sleeping
        }
        if (!ok) {
            InterlockedExchange(&g_filtering_active, FALSE);
            AcquireSRWLockExclusive(&g_driver_handle_lock);
            HANDLE stale = g_drv;
            g_drv = INVALID_HANDLE_VALUE;
            InterlockedIncrement64(&g_driver_session_epoch);
            ReleaseSRWLockExclusive(&g_driver_handle_lock);
            if (stale != INVALID_HANDLE_VALUE) {
                CloseHandle(stale); // revoke the old session before opening another
                log_message("driver: device unavailable; filtering inactive, waiting to reconnect");
                reconnectAt = GetTickCount64() + reconnectDelay;
            }
            if (GetTickCount64() >= reconnectAt && InterlockedCompareExchange(&g_drain_run, 0, 0)) {
                BOOL ownsRules = pb_rules_begin_update();
                HANDLE replacement = ownsRules ? driver_open_configured(g_local_relay_port) : INVALID_HANDLE_VALUE;
                BOOL restored = FALSE;
                AcquireSRWLockExclusive(&g_driver_handle_lock);
                if (replacement != INVALID_HANDLE_VALUE &&
                    InterlockedCompareExchange(&g_drain_run, 0, 0) && relay_threads_alive()) {
                    g_drv = replacement;
                    InterlockedIncrement64(&g_driver_session_epoch);
                    restored = TRUE;
                    InterlockedExchange(&g_filtering_active, TRUE);
                }
                ReleaseSRWLockExclusive(&g_driver_handle_lock);
                if (!restored && replacement != INVALID_HANDLE_VALUE) {
                    pbdrv_enable(replacement, FALSE);
                    CloseHandle(replacement);
                }
                if (ownsRules) pb_rules_end_update();
                if (restored) {
                    reconnectDelay = 250;
                    log_message("driver: filtering restored after applying current configuration and rules");
                } else if (reconnectDelay < 5000) {
                    reconnectDelay = min(reconnectDelay * 2, 5000);
                }
                reconnectAt = GetTickCount64() + reconnectDelay;
            }
        }
        Sleep(150);
    }
    InterlockedExchange(&g_filtering_active, FALSE);
    free(buf);
    return 0;
}

// Add one rule token to the kernel watch list. WFP exposes ALE_APP_ID as a kernel device
// path, so exact DOS paths must be converted to that namespace before they can match.
static BOOL driver_add_watch_entry(PBDRV_WATCHLIST *wl, const char *token)
{
    if (wl->count >= PBDRV_MAX_WATCH) {
        log_message("driver: watchlist exceeds the %u-entry limit", (unsigned)PBDRV_MAX_WATCH);
        return FALSE;
    }

    WCHAR token_w[MAX_PROCESS_NAME];
    int token_chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, token, -1,
                                          token_w, ARRAYSIZE(token_w));
    if (token_chars == 0) {
        log_message("driver: invalid UTF-8 watch entry '%s' (%lu)", token, GetLastError());
        return FALSE;
    }

    const WCHAR *image = token_w;
    size_t image_chars = (size_t)token_chars - 1;
    FWP_BYTE_BLOB *app_id = NULL;
    BOOL added = FALSE;
    BOOL exact_path = (strchr(token, '\\') != NULL || strchr(token, '/') != NULL) &&
                      strchr(token, '*') == NULL;

    if (exact_path) {
        DWORD status = FwpmGetAppIdFromFileName0(token_w, &app_id);
        if (status != ERROR_SUCCESS) {
            log_message("driver: cannot resolve watch path '%s' (%lu)", token, status);
            goto done;
        }
        if (app_id == NULL || app_id->data == NULL ||
            app_id->size < sizeof(WCHAR) || app_id->size % sizeof(WCHAR) != 0) {
            log_message("driver: WFP returned an invalid app ID for '%s'", token);
            goto done;
        }

        image = (const WCHAR *)app_id->data;
        size_t available = app_id->size / sizeof(WCHAR);
        image_chars = 0;
        while (image_chars < available && image[image_chars] != 0) {
            image_chars++;
        }
    }

    if (image_chars == 0 || image_chars >= PBDRV_NAME_LEN) {
        log_message("driver: watch entry '%s' exceeds the %u-character limit",
                    token, (unsigned)PBDRV_NAME_LEN - 1);
        goto done;
    }

    memcpy(wl->entries[wl->count].image, image, image_chars * sizeof(WCHAR));
    wl->entries[wl->count].image[image_chars] = 0;
    wl->count++;
    added = TRUE;

done:
    if (app_id != NULL) {
        FwpmFreeMemory0((void **)&app_id);
    }
    return added;
}

// Caller owns an immutable candidate or holds the rules writer gate.
PBDRV_WATCHLIST *pb_driver_prepare_rules(const PROCESS_RULE *rules)
{
    PBDRV_WATCHLIST *wl = calloc(1, sizeof(*wl));
    if (wl == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    BOOL valid = TRUE;
    for (const PROCESS_RULE *r = rules; r != NULL && valid; r = r->next) {
        if (!r->enabled || (r->action != RULE_ACTION_PROXY && r->action != RULE_ACTION_BLOCK)) continue;
        // Watch = every app the relay must see: PROXY (redirect to upstream) and BLOCK
        // (redirect so the relay can refuse). DIRECT-only apps are left untouched in-kernel.
        // Keep token parsing aligned with match_process_list: comma/semicolon separators,
        // surrounding whitespace, and optional quotes around paths containing spaces.
        char tmp[1024];
        strcpy_s(tmp, sizeof(tmp), r->process_name);
        char *ctxp = NULL;
        for (char *tok = strtok_s(tmp, ",;", &ctxp); tok && valid;
             tok = strtok_s(NULL, ",;", &ctxp)) {
            while (*tok == ' ' || *tok == '\t') {
                tok++;
            }
            char *end = tok + strlen(tok);
            while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) {
                *(--end) = 0;
            }
            if (*tok == '"' && end > tok + 1) {
                tok++;
                char *quote = strchr(tok, '"');
                if (quote != NULL) {
                    *quote = 0;
                }
            }
            if (*tok == 0) {
                continue;
            }
            valid = driver_add_watch_entry(wl, tok);
        }
    }

    if (!valid) {
        log_message("driver: watchlist update rejected; previous list remains active");
        free(wl);
        SetLastError(ERROR_INVALID_DATA);
        return NULL;
    }

    return wl;
}

// Called under the rules writer gate and g_rules_lock exclusive. No callbacks.
BOOL pb_driver_apply_rules(const PBDRV_WATCHLIST *watch)
{
    AcquireSRWLockShared(&g_driver_handle_lock);
    BOOL ok = g_drv == INVALID_HANDLE_VALUE || pbdrv_set_watchlist(g_drv, watch);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    ReleaseSRWLockShared(&g_driver_handle_lock);
    SetLastError(error);
    return ok;
}

BOOL pb_driver_apply_profile_rules(const PBDRV_WATCHLIST *watch, BOOL loopback)
{
    AcquireSRWLockShared(&g_driver_handle_lock);
    BOOL ok = g_drv == INVALID_HANDLE_VALUE || pbdrv_set_rule_policy(g_drv, watch, loopback);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    ReleaseSRWLockShared(&g_driver_handle_lock);
    SetLastError(error);
    return ok;
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
    cfg->redirectUdp        = (udp_relay_thread != NULL);
    cfg->redirectIpv6       = g_relay_ipv6_ready;
    cfg->redirectLoopbackApps = g_localhost_via_proxy ? 1 : 0;   // "Localhost via Proxy" menu option
}

static HANDLE driver_open_configured(UINT16 relay_port)
{
    HANDLE driver = pbdrv_open();
    if (driver == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        log_message("driver: PnP interface open failed (%lu); check installation and controller ownership", error);
        SetLastError(error);
        goto fail;
    }

    PBDRV_STATUS state;
    if (!pbdrv_get_status(driver, &state)) {
        DWORD error = GetLastError();
        log_message("driver: incompatible or unreadable driver status (%lu)", error);
        SetLastError(error);
        goto fail;
    }
    if (!(state.flags & PBDRV_STATUS_READY)) {
        log_message("driver: device is not ready");
        SetLastError(ERROR_NOT_READY);
        goto fail;
    }

    PBDRV_CONFIG cfg;
    driver_build_config(&cfg, relay_port);
    if (!pbdrv_configure(driver, &cfg)) {
        DWORD error = GetLastError();
        log_message("driver: configure failed (%lu)", error);
        SetLastError(error);
        goto fail;
    }

    PBDRV_WATCHLIST *watch = pb_driver_prepare_rules(rules_list);
    if (watch == NULL) {
        SetLastError(ERROR_INVALID_DATA);
        goto fail;
    }
    BOOL watchApplied = pbdrv_set_watchlist(driver, watch);
    DWORD watchError = watchApplied ? ERROR_SUCCESS : GetLastError();
    free(watch);
    if (!watchApplied) {
        SetLastError(watchError);
        goto fail;
    }
    if (!relay_threads_alive()) {
        SetLastError(ERROR_NOT_READY);
        goto fail;
    }
    if (!pbdrv_enable(driver, TRUE)) {
        DWORD error = GetLastError();
        log_message("driver: enable failed (%lu)", error);
        SetLastError(error);
        goto fail;
    }
    if (!pbdrv_get_status(driver, &state)) {
        DWORD error = GetLastError();
        log_message("driver: activation status query failed (%lu)", error);
        SetLastError(error);
        goto fail;
    }
    if (!(state.flags & PBDRV_STATUS_ACTIVE) || !relay_threads_alive()) {
        log_message("driver: activation was not confirmed (status=0x%08lx)",
                    (unsigned long)state.lastActivationStatus);
        SetLastError(ERROR_NOT_READY);
        goto fail;
    }

    return driver;

fail: {
    DWORD error = GetLastError();
    if (driver != INVALID_HANDLE_VALUE) {
        pbdrv_enable(driver, FALSE);
        CloseHandle(driver);
        driver = INVALID_HANDLE_VALUE;
    }
    SetLastError(error);
    return INVALID_HANDLE_VALUE;
}
}

BOOL pb_driver_start(UINT16 relay_port)
{
    PBDRV_EVENT *events = malloc(PB_DRAIN_CAP * sizeof(*events));
    if (events == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    if (!pb_rules_begin_update()) {
        free(events);
        SetLastError(ERROR_BUSY);
        return FALSE;
    }
    HANDLE driver = driver_open_configured(relay_port);
    if (driver == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        pb_rules_end_update();
        free(events);
        SetLastError(error);
        return FALSE;
    }
    AcquireSRWLockExclusive(&g_driver_handle_lock);
    g_drv = driver;
    InterlockedIncrement64(&g_driver_session_epoch);
    InterlockedExchange(&g_filtering_active, TRUE);
    InterlockedExchange(&g_drain_run, TRUE);
    g_drain_thread = CreateThread(NULL, 0, driver_event_drain, events, 0, NULL);
    DWORD error = g_drain_thread == NULL ? GetLastError() : ERROR_SUCCESS;
    if (g_drain_thread == NULL) {
        InterlockedExchange(&g_drain_run, FALSE);
        InterlockedExchange(&g_filtering_active, FALSE);
        g_drv = INVALID_HANDLE_VALUE;
        InterlockedIncrement64(&g_driver_session_epoch);
    }
    ReleaseSRWLockExclusive(&g_driver_handle_lock);
    if (error != ERROR_SUCCESS) {
        free(events);
        pbdrv_enable(driver, FALSE);
        CloseHandle(driver);
        pb_rules_end_update();
        log_message("driver: event worker creation failed (%lu)", error);
        SetLastError(error);
        return FALSE;
    }
    pb_rules_end_update();
    log_message("driver: ProxyBridgeDrv active - relay port %u", relay_port);
    return TRUE;
}
BOOL pb_driver_is_worker_thread(void)
{
    // Called only by the serialized core lifecycle while handles are stable.
    return g_drain_thread != NULL && GetThreadId(g_drain_thread) == GetCurrentThreadId();
}

void pb_driver_stop(void)
{
    InterlockedExchange(&g_filtering_active, FALSE);
    // Stop the drain thread before closing the handle it uses. Wait INFINITE (not a timeout):
    // the thread reads g_drv, so closing it while the thread is mid pbdrv_pop_events() would be
    // a use-after-close. The idle sleep is <=150 ms; an in-flight synchronous
    // IOCTL or reconnect can take longer and must complete before the join.
    InterlockedExchange(&g_drain_run, FALSE);
    if (g_drain_thread != NULL) {
        WaitForSingleObject(g_drain_thread, INFINITE);
        CloseHandle(g_drain_thread);
        g_drain_thread = NULL;
    }
    AcquireSRWLockExclusive(&g_driver_handle_lock);
    if (g_drv != INVALID_HANDLE_VALUE) {
        pbdrv_enable(g_drv, FALSE);
        CloseHandle(g_drv);
        g_drv = INVALID_HANDLE_VALUE;
        InterlockedIncrement64(&g_driver_session_epoch);
    }
    ReleaseSRWLockExclusive(&g_driver_handle_lock);
    // The installer owns the devnode/package; closing the session leaves it ready.
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

// Relay-side UDP: ERROR_NOT_FOUND is reserved for a successful query with no
// mapping. An IOCTL failure must never be mistaken for proof of endpoint close.
// IPv4: recover a redirected datagram's original dest by its source.
BOOL pb_driver_udp_orig(UINT32 src_ip, UINT16 src_port, UINT32 *ip, UINT16 *port, DWORD *pid, UINT64 *generation)
{
    PBDRV_UDP_QUERY q; memset(&q, 0, sizeof(q));
    q.family = AF_INET; q.srcV4 = src_ip; q.srcPort = src_port;
    AcquireSRWLockShared(&g_driver_handle_lock);
    BOOL ok = g_drv != INVALID_HANDLE_VALUE && pbdrv_udp_query(g_drv, &q);
    DWORD error = ok ? ERROR_SUCCESS :
        (g_drv == INVALID_HANDLE_VALUE ? ERROR_INVALID_HANDLE : GetLastError());
    if (!ok && error == ERROR_NOT_FOUND) error = ERROR_GEN_FAILURE;
    ReleaseSRWLockShared(&g_driver_handle_lock);
    if (!ok || !q.found) {
        SetLastError(ok ? ERROR_NOT_FOUND : error);
        return FALSE;
    }
    *ip = q.origV4; *port = q.origPort;
    if (pid) *pid = q.pid;
    if (generation) *generation = q.mappingGeneration;
    return TRUE;
}

BOOL pb_driver_udp_orig6(const UINT8 src_ip6[16], UINT16 src_port,
                         UINT8 ip6[16], UINT16 *port, DWORD *pid, UINT64 *generation)
{
    PBDRV_UDP_QUERY q; memset(&q, 0, sizeof(q));
    q.family = AF_INET6;
    memcpy(q.srcV6, src_ip6, 16);
    q.srcPort = src_port;
    AcquireSRWLockShared(&g_driver_handle_lock);
    BOOL ok = g_drv != INVALID_HANDLE_VALUE && pbdrv_udp_query(g_drv, &q);
    DWORD error = ok ? ERROR_SUCCESS :
        (g_drv == INVALID_HANDLE_VALUE ? ERROR_INVALID_HANDLE : GetLastError());
    if (!ok && error == ERROR_NOT_FOUND) error = ERROR_GEN_FAILURE;
    ReleaseSRWLockShared(&g_driver_handle_lock);
    if (!ok || !q.found) {
        SetLastError(ok ? ERROR_NOT_FOUND : error);
        return FALSE;
    }
    memcpy(ip6, q.origV6, 16);
    *port = q.origPort;
    if (pid != NULL) *pid = q.pid;
    if (generation) *generation = q.mappingGeneration;
    return TRUE;
}
