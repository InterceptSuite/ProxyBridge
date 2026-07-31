#include "pb_internal.h"

// Proxy config: config store, lookup helpers, and management/test API.

// Internal: locate a config (caller must hold g_proxy_lock). config_id 0 = "first available".
// Tombstoned slots (config_id == 0) are skipped.
static PROXY_CONFIG* find_locked(UINT32 config_id)
{
    if (config_id != 0)
        for (int i = 0; i < g_proxy_config_count; i++)
            if (g_proxy_configs[i].config_id == config_id)
                return &g_proxy_configs[i];
    // "first available" or id not found -> first live (non-tombstone) config
    for (int i = 0; i < g_proxy_config_count; i++)
        if (g_proxy_configs[i].config_id != 0)
            return &g_proxy_configs[i];
    return NULL;
}

// Find proxy config by ID; falls back to first live config. Returns a LIVE pointer for the
// single-threaded UDP relay's persistent per-config state. TCP callers that hold the config
// across blocking I/O must use find_proxy_config_copy() instead (immune to Edit/Delete).
PROXY_CONFIG* find_proxy_config(UINT32 config_id)
{
    AcquireSRWLockShared(&g_proxy_lock);
    PROXY_CONFIG *found = find_locked(config_id);
    ReleaseSRWLockShared(&g_proxy_lock);
    return found;
}

// Snapshot a config into *out under the lock. TRUE if a config was found.
BOOL find_proxy_config_copy(UINT32 config_id, PROXY_CONFIG *out)
{
    AcquireSRWLockShared(&g_proxy_lock);
    PROXY_CONFIG *found = find_locked(config_id);
    if (found != NULL) *out = *found;
    ReleaseSRWLockShared(&g_proxy_lock);
    return found != NULL;
}

// Helper: check if any proxy config is SOCKS5 (needed to decide whether to start UDP relay)
BOOL any_socks5_config(void)
{
    BOOL yes = FALSE;
    AcquireSRWLockShared(&g_proxy_lock);
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].config_id != 0 &&
            g_proxy_configs[i].type == PROXY_TYPE_SOCKS5 &&
            g_proxy_configs[i].host[0] != '\0' &&
            g_proxy_configs[i].port != 0)
        { yes = TRUE; break; }
    }
    ReleaseSRWLockShared(&g_proxy_lock);
    return yes;
}

// TRUE if any enabled PROXY rule routes traffic through this proxy config. Used to skip
// proactively establishing UDP ASSOCIATE for configs that no rule uses - otherwise the
// relay wastes time (and can stall on a dead/unreachable host) connecting to proxies that
// will never carry traffic. A rule with proxy_config_id 0 means "first available", which
// could resolve to any config, so its presence marks all configs as potentially used.
BOOL is_proxy_config_referenced(UINT32 config_id)
{
    BOOL referenced = FALSE;
    AcquireSRWLockShared(&g_rules_lock);
    for (PROCESS_RULE *r = rules_list; r != NULL; r = r->next)
    {
        if (!r->enabled || r->action != RULE_ACTION_PROXY)
            continue;
        if (r->proxy_config_id == config_id || r->proxy_config_id == 0)
        {
            referenced = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_rules_lock);
    return referenced;
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL send_domain_to_proxy)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return 0;

    UINT32 resolved = resolve_hostname(proxy_ip);   // network I/O - do it before taking the lock
    if (resolved == 0)
        return 0;

    UINT32 new_id = 0;
    char   log_host[256]; UINT16 log_port = 0; int log_type = 0;
    AcquireSRWLockExclusive(&g_proxy_lock);
    // Reuse a tombstoned slot if one exists (keeps the array bounded); else append.
    int slot = -1;
    for (int i = 0; i < g_proxy_config_count; i++)
        if (g_proxy_configs[i].config_id == 0) { slot = i; break; }
    if (slot < 0)
    {
        if (g_proxy_config_count >= MAX_PROXY_CONFIGS) { ReleaseSRWLockExclusive(&g_proxy_lock); return 0; }
        slot = g_proxy_config_count++;
    }
    PROXY_CONFIG *cfg = &g_proxy_configs[slot];
    memset(cfg, 0, sizeof(PROXY_CONFIG));
    cfg->config_id = g_next_config_id++;
    cfg->type      = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    cfg->port      = proxy_port;
    cfg->send_domain_to_proxy = send_domain_to_proxy;
    strncpy_s(cfg->host, sizeof(cfg->host), proxy_ip, _TRUNCATE);
    cfg->resolved_ip = resolved;
    if (username != NULL) strncpy_s(cfg->username, sizeof(cfg->username), username, _TRUNCATE);
    if (password != NULL) strncpy_s(cfg->password, sizeof(cfg->password), password, _TRUNCATE);
    cfg->udp_tcp_ctrl  = INVALID_SOCKET;
    cfg->udp_send_sock = INVALID_SOCKET;
    cfg->udp_connected = FALSE;
    new_id = cfg->config_id;
    strncpy_s(log_host, sizeof(log_host), cfg->host, _TRUNCATE); log_port = cfg->port; log_type = cfg->type;
    ReleaseSRWLockExclusive(&g_proxy_lock);

    log_message("Added proxy config ID %u: %s:%u (type %d)", new_id, log_host, log_port, log_type);
    return new_id;
}

PROXYBRIDGE_API BOOL ProxyBridge_EditProxyConfig(UINT32 config_id, ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL send_domain_to_proxy)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return FALSE;

    UINT32 resolved = resolve_hostname(proxy_ip);   // network I/O - before the lock
    if (resolved == 0)
        return FALSE;

    BOOL found = FALSE;
    char log_host[256]; UINT16 log_port = 0; int log_type = 0;
    AcquireSRWLockExclusive(&g_proxy_lock);
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->config_id != 0 && cfg->config_id == config_id)
        {
            // Close any open UDP state before changing config
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  cfg->udp_tcp_ctrl  = INVALID_SOCKET; }
            if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
            cfg->udp_connected = FALSE;

            cfg->type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
            cfg->port = proxy_port;
            cfg->send_domain_to_proxy = send_domain_to_proxy;
            strncpy_s(cfg->host, sizeof(cfg->host), proxy_ip, _TRUNCATE);
            cfg->resolved_ip = resolved;
            cfg->username[0] = '\0';
            cfg->password[0] = '\0';
            if (username != NULL) strncpy_s(cfg->username, sizeof(cfg->username), username, _TRUNCATE);
            if (password != NULL) strncpy_s(cfg->password, sizeof(cfg->password), password, _TRUNCATE);

            strncpy_s(log_host, sizeof(log_host), cfg->host, _TRUNCATE); log_port = cfg->port; log_type = cfg->type;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_proxy_lock);
    if (found)
        log_message("Edited proxy config ID %u: %s:%u (type %d)", config_id, log_host, log_port, log_type);
    return found;
}

PROXYBRIDGE_API BOOL ProxyBridge_DeleteProxyConfig(UINT32 config_id)
{
    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_proxy_lock);
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->config_id != 0 && cfg->config_id == config_id)
        {
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  }
            if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); }

            // Tombstone the slot instead of memmove-ing the array down. Shifting entries would
            // invalidate PROXY_CONFIG* pointers and indices held by relay/drain threads (wrong
            // proxy used, or a torn read). A tombstone (config_id = 0) is skipped by all readers
            // and reused by a later Add, so the array stays structurally stable.
            memset(cfg, 0, sizeof(*cfg));
            cfg->config_id     = 0;              // tombstone marker (memset already did this)
            cfg->udp_tcp_ctrl  = INVALID_SOCKET;
            cfg->udp_send_sock = INVALID_SOCKET;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_proxy_lock);
    if (found)
        log_message("Deleted proxy config ID %u", config_id);
    return found;
}

PROXYBRIDGE_API int ProxyBridge_TestProxyConfig(UINT32 config_id, const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size)
{
    PROXY_CONFIG *cfg = find_proxy_config(config_id);
    if (cfg == NULL)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "No proxy config found", _TRUNCATE);
        return -1;
    }

    UINT32 dest_ip = resolve_hostname(target_host);
    if (dest_ip == 0)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to resolve target host", _TRUNCATE);
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to create socket", _TRUNCATE);
        return -1;
    }

    // Set timeout
    DWORD timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port   = htons(cfg->port);
    UINT32 proxy_ip = resolve_hostname(cfg->host);
    if (proxy_ip == 0)
    {
        closesocket(sock);
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to resolve proxy host", _TRUNCATE);
        return -1;
    }
    proxy_addr.sin_addr.s_addr = proxy_ip;

    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0)
    {
        closesocket(sock);
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to connect to proxy", _TRUNCATE);
        return -1;
    }

    int result;
    if (cfg->type == PROXY_TYPE_SOCKS5)
        result = socks5_connect(sock, dest_ip, target_port, cfg);
    else
        result = http_connect(sock, dest_ip, target_port, cfg);

    closesocket(sock);

    if (result == 0)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Connection successful", _TRUNCATE);
        return 0;
    }
    else
    {
        if (result_buffer && buffer_size > 0)
            snprintf(result_buffer, buffer_size, "Connection failed (code %d)", result);
        return result;
    }
}

PROXYBRIDGE_API int ProxyBridge_TestProxyConfigEx(UINT32 config_id, const char* target_host, UINT16 target_port,
                                                  ProxyTestLogCallback cb, void* user)
{
    #define TLOG(...) do { if (cb) { char _l[300]; _snprintf_s(_l, sizeof(_l), _TRUNCATE, __VA_ARGS__); cb(_l, user); } } while (0)

    PROXY_CONFIG *cfg = find_proxy_config(config_id);
    if (cfg == NULL) { TLOG("[FAIL] No proxy config found"); return -1; }
    if (target_host == NULL || target_host[0] == '\0') target_host = "www.google.com";
    if (target_port == 0) target_port = 80;

    BOOL is_socks = (cfg->type == PROXY_TYPE_SOCKS5);
    BOOL use_auth = (cfg->username[0] != '\0');

    TLOG("Proxy:    %s:%u", cfg->host, cfg->port);
    TLOG("Protocol: %s", is_socks ? "SOCKS5" : "HTTP");
    TLOG("Auth:     %s", use_auth ? "yes" : "no");
    TLOG("Target:   %s:%u", target_host, target_port);

    UINT32 proxy_ip = resolve_hostname(cfg->host);
    if (proxy_ip == 0) { TLOG(""); TLOG("[FAIL] Could not resolve proxy host '%s'", cfg->host); return -1; }
    struct in_addr pa; pa.s_addr = proxy_ip;
    TLOG("Proxy IP: %s", inet_ntoa(pa));

    int overall = 0;

    // ── Test 1: TCP connection to the proxy server ───────────────────────────
    TLOG("");
    TLOG("Test 1: Connection to the proxy server");
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { TLOG("  [FAIL] Failed to create socket"); return -1; }
    DWORD to = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
    struct sockaddr_in paddr; memset(&paddr, 0, sizeof(paddr));
    paddr.sin_family = AF_INET; paddr.sin_port = htons(cfg->port); paddr.sin_addr.s_addr = proxy_ip;
    ULONGLONG c0 = GetTickCount64();
    if (connect(s, (struct sockaddr*)&paddr, sizeof(paddr)) != 0)
    {
        TLOG("  [FAIL] Could not connect to the proxy server");
        closesocket(s);
        TLOG(""); TLOG("Testing finished: proxy is NOT reachable.");
        return -1;
    }
    ULONGLONG c1 = GetTickCount64();
    ULONGLONG connect_ms = c1 - c0;
    TLOG("  Connection established (%llu ms)", connect_ms);
    TLOG("  Test 1 passed");

    // ── Test 2: Connection through the proxy server ──────────────────────────
    TLOG("");
    TLOG("Test 2: Connection through the proxy server");
    UINT32 dest_ip = resolve_hostname(target_host);
    if (dest_ip == 0)
    {
        TLOG("  [FAIL] Could not resolve target host '%s'", target_host);
        closesocket(s);
        overall = -1;
    }
    else
    {
        ULONGLONG h0 = GetTickCount64();
        int rc = is_socks ? socks5_connect(s, dest_ip, target_port, cfg)
                          : http_connect(s, dest_ip, target_port, cfg);
        ULONGLONG h1 = GetTickCount64();
        if (rc != 0)
        {
            TLOG("  [FAIL] Could not establish a tunnel through the proxy (code %d)", rc);
            if (use_auth) TLOG("  Hint: verify the proxy credentials");
            overall = -1;
        }
        else
        {
            if (use_auth) TLOG("  Authentication was successful");
            TLOG("  Connection to %s:%u established through the proxy (%llu ms)", target_host, target_port, h1 - h0);

            // Try to load a default web page (best-effort; needs a web server on the target).
            char req[256];
            int rn = _snprintf_s(req, sizeof(req), _TRUNCATE,
                                 "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ProxyBridge-Check\r\nConnection: close\r\n\r\n",
                                 target_host);
            if (rn > 0 && send(s, req, rn, 0) == rn)
            {
                char resp[512]; int got = recv(s, resp, sizeof(resp) - 1, 0);
                if (got > 0)
                {
                    resp[got] = '\0';
                    if (strncmp(resp, "HTTP/", 5) == 0)
                    {
                        char status[64] = {0};
                        const char* nl = strchr(resp, '\r'); size_t sl = nl ? (size_t)(nl - resp) : 0;
                        if (sl > 0 && sl < sizeof(status)) { memcpy(status, resp, sl); status[sl] = 0; }
                        TLOG("  Default web page loaded: %s", status[0] ? status : "HTTP response received");
                    }
                    else TLOG("  Received %d bytes (non-HTTP target)", got);
                }
                else TLOG("  Note: no page data returned (target may not run a web server)");
            }
            TLOG("  Test 2 passed");
        }
    }
    closesocket(s);

    // ── Test 3: Proxy server latency ─────────────────────────────────────────
    TLOG("");
    TLOG("Test 3: Proxy server latency");
    TLOG("  Latency = %llu ms", connect_ms);
    TLOG("  Test 3 passed");

    // ── Test 4: SOCKS5 UDP ASSOCIATE support ─────────────────────────────────
    if (is_socks)
    {
        TLOG("");
        TLOG("Test 4: SOCKS5 UDP ASSOCIATE support");
        SOCKET us = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (us != INVALID_SOCKET)
        {
            setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
            setsockopt(us, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
            if (connect(us, (struct sockaddr*)&paddr, sizeof(paddr)) == 0)
            {
                struct sockaddr_in relay; memset(&relay, 0, sizeof(relay));
                int urc = socks5_udp_associate_with_config(us, &relay, cfg);
                if (urc == 0)
                {
                    TLOG("  UDP ASSOCIATE granted; relay = %s:%u", inet_ntoa(relay.sin_addr), ntohs(relay.sin_port));
                    TLOG("  UDP is supported by this proxy");
                }
                else TLOG("  UDP ASSOCIATE refused - this proxy does not support UDP");
            }
            else TLOG("  Could not open a control connection for the UDP test");
            closesocket(us);
        }
    }

    TLOG("");
    TLOG(overall == 0 ? "Testing finished: proxy is ready to work." : "Testing finished with errors.");
    return overall;

    #undef TLOG
}

