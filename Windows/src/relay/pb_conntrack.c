#include "pb_internal.h"

// Connection tracking: forward table, reverse index, logged connections.

// Reverse-index helpers. Keyed by the ORIGINAL destination (what the app connected to) -
// an inbound relay reply carries that as its source. All callers hold `lock` exclusively.
UINT32 rev_hash_v4(UINT32 dest_ip, UINT16 dest_port)
{
    UINT32 h = dest_ip * 2654435761u ^ ((UINT32)dest_port * 40503u);
    return h % CONNECTION_HASH_SIZE;
}

UINT32 rev_hash_v6(const UINT8 dest_ip6[16], UINT16 dest_port)
{
    UINT32 h = (UINT32)dest_port * 40503u;
    for (int i = 0; i < 16; i++) h = h * 31u + dest_ip6[i];
    return h % CONNECTION_HASH_SIZE;
}

void rev_insert(CONNECTION_INFO *c)
{
    UINT32 b = c->is_ipv6 ? rev_hash_v6(c->orig_dest_ip6, c->orig_dest_port)
                          : rev_hash_v4(c->orig_dest_ip, c->orig_dest_port);
    c->rev_bucket = b;
    c->rev_next = connection_rev_table[b];
    connection_rev_table[b] = c;
    c->in_rev = TRUE;
}

void rev_unlink(CONNECTION_INFO *c)
{
    if (!c->in_rev) return;
    CONNECTION_INFO **pp = &connection_rev_table[c->rev_bucket];
    while (*pp) { if (*pp == c) { *pp = c->rev_next; break; } pp = &(*pp)->rev_next; }
    c->in_rev = FALSE;
    c->rev_next = NULL;
}

void add_connection(UINT16 src_port, BOOL is_udp, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id)
{
    AcquireSRWLockExclusive(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = connection_hash_table[hash];

    // Match on (port, protocol, family): a TCP and a UDP flow - or an IPv4 and an
    // IPv6 flow - may legitimately share a numeric local port at the same time.
    while (existing != NULL) {
        if (existing->src_port == src_port && existing->is_udp == is_udp && !existing->is_ipv6) {
            rev_unlink(existing);   // dest may change (port reuse) - re-key the reverse index
            existing->is_ipv6 = FALSE;
            existing->src_ip = src_ip;
            existing->orig_dest_ip = dest_ip;
            existing->orig_dest_port = dest_port;
            existing->proxy_config_id = proxy_config_id;
            existing->is_tracked = TRUE;
            existing->last_activity = GetTickCount64();
            rev_insert(existing);
            ReleaseSRWLockExclusive(&lock);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)calloc(1, sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&lock);
        return;
    }

    conn->src_port = src_port;
    conn->is_udp = is_udp;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->is_ipv6 = FALSE;
    conn->last_activity = GetTickCount64();

    conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = conn;
    rev_insert(conn);
    ReleaseSRWLockExclusive(&lock);
}

BOOL get_connection_full_v6(UINT16 src_port, BOOL is_udp, UINT8 dest_ip6[16], UINT16 *dest_port, UINT32 *proxy_config_id)
{
    BOOL found = FALSE;
    AcquireSRWLockShared(&lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];
    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_udp == is_udp && conn->is_ipv6) {
            memcpy(dest_ip6, conn->orig_dest_ip6, 16);
            *dest_port = conn->orig_dest_port;
            if (proxy_config_id != NULL) *proxy_config_id = conn->proxy_config_id;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);
    return found;
}

// Reverse lookup for IPv6 UDP relay responses: find src addr+port by orig dest ip6+port
BOOL find_v6_udp_sender(const UINT8 orig_dest_ip6[16], UINT16 orig_dest_port, UINT8 src_ip6[16], UINT16 *src_port)
{
    BOOL found = FALSE;
    ULONGLONG best = 0;
    AcquireSRWLockShared(&lock);
    // O(1): only the reverse bucket for this (dest ip6, dest port).
    for (CONNECTION_INFO *conn = connection_rev_table[rev_hash_v6(orig_dest_ip6, orig_dest_port)];
         conn != NULL; conn = conn->rev_next) {
        if (conn->is_udp && conn->is_ipv6 && conn->orig_dest_port == orig_dest_port &&
            memcmp(conn->orig_dest_ip6, orig_dest_ip6, 16) == 0) {
            if (!found || conn->last_activity > best) {
                memcpy(src_ip6, conn->src_ip6, 16);
                *src_port = conn->src_port;
                best = conn->last_activity;
                found = TRUE;
            }
        }
    }
    ReleaseSRWLockShared(&lock);
    return found;
}

BOOL get_connection(UINT16 src_port, BOOL is_udp, UINT32 *dest_ip, UINT16 *dest_port)
{
    BOOL found = FALSE;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port && conn->is_udp == is_udp && !conn->is_ipv6)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return found;
}

BOOL get_connection_full(UINT16 src_port, BOOL is_udp, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id)
{
    BOOL found = FALSE;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port && conn->is_udp == is_udp && !conn->is_ipv6)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            if (proxy_config_id != NULL) *proxy_config_id = conn->proxy_config_id;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return found;
}

UINT32 get_connection_proxy_id(UINT16 src_port, BOOL is_udp)
{
    UINT32 proxy_config_id = 0;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port && conn->is_udp == is_udp && !conn->is_ipv6)
        {
            proxy_config_id = conn->proxy_config_id;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return proxy_config_id;
}

void remove_connection(UINT16 src_port, BOOL is_udp, BOOL is_ipv6)
{
    AcquireSRWLockExclusive(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO **conn_ptr = &connection_hash_table[hash];

    while (*conn_ptr != NULL)
    {
        if ((*conn_ptr)->src_port == src_port && (*conn_ptr)->is_udp == is_udp && (*conn_ptr)->is_ipv6 == is_ipv6)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            rev_unlink(to_free);
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    ReleaseSRWLockExclusive(&lock);
}

void cleanup_stale_connections(void)
{
    ULONGLONG now = GetTickCount64();

    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        AcquireSRWLockExclusive(&lock);
        CONNECTION_INFO **conn_ptr = &connection_hash_table[i];

        while (*conn_ptr != NULL)
        {
            if (now - (*conn_ptr)->last_activity > CONNECTION_STALE_TIMEOUT_MS)
            {
                CONNECTION_INFO *to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                rev_unlink(to_free);              // must run under the exclusive lock
                // Free WHILE holding the lock. Dropping it here (as before) let another thread's
                // remove_connection free the predecessor or the next node that `conn_ptr` still
                // points into, so re-acquiring and dereferencing `*conn_ptr` was a use-after-free.
                // free() is cheap; keeping the lock across it is correct and race-free.
                free(to_free);
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        ReleaseSRWLockExclusive(&lock);
    }

    AcquireSRWLockExclusive(&lock);
    int logged_count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL) { logged_count++; temp = temp->next; }

    if (logged_count > 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 99 && temp != NULL; i++)
            temp = temp->next;

        if (temp != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
        }
    }
    ReleaseSRWLockExclusive(&lock);
}

// Check if connection already logged (deduplication)
BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    BOOL found = FALSE;
    AcquireSRWLockShared(&lock);

    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid &&
            logged->dest_ip == dest_ip &&
            logged->dest_port == dest_port &&
            logged->action == action)
        {
            found = TRUE;
            break;
        }
        logged = logged->next;
    }

    ReleaseSRWLockShared(&lock);
    return found;
}

void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    AcquireSRWLockExclusive(&lock);

    // Use the running counter instead of re-walking the whole list on every add.
    if (g_logged_count >= 100)
    {
        LOGGED_CONNECTION *temp = logged_connections;
        for (int i = 0; i < 98 && temp != NULL; i++)
            temp = temp->next;

        if (temp != NULL && temp->next != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;

            int freed = 0;
            ReleaseSRWLockExclusive(&lock);
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
                freed++;
            }
            AcquireSRWLockExclusive(&lock);
            g_logged_count -= freed;
        }
    }

    LOGGED_CONNECTION *logged = (LOGGED_CONNECTION *)malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->dest_ip = dest_ip;
        logged->dest_port = dest_port;
        logged->action = action;
        logged->next = logged_connections;
        logged_connections = logged;
        g_logged_count++;
    }

    ReleaseSRWLockExclusive(&lock);
}

// Report one connection the relay decided on to the GUI (connection tab) and the history
// list. Replaces the per-SYN logging the old WinDivert packet loop did. Called once per new
// connection that reaches the relay (i.e. every watched/redirected app: proxy, block, direct).
void pb_report_connection(DWORD pid, const char *name_override, BOOL is_ipv6, UINT32 dest_ip,
                          const UINT8 dest_ip6[16], UINT16 dest_port, RuleAction action,
                          UINT32 cfg_id, BOOL is_udp)
{
    // Fold the v6 address to a 32-bit dedup/history key (LOGGED_CONNECTION stores UINT32).
    UINT32 key = dest_ip;
    if (is_ipv6) {
        key = 0;
        for (int i = 0; i < 16; i++) key = key * 31u + dest_ip6[i];
    }
    if (is_connection_already_logged(pid, key, dest_port, action)) return;

    // Prefer a caller-supplied name (the driver captured it in-kernel, so it survives a process
    // that has already exited); otherwise resolve the live PID.
    char pname[MAX_PROCESS_NAME] = "unknown";
    if (name_override != NULL && name_override[0] != '\0')
        strncpy_s(pname, sizeof(pname), name_override, _TRUNCATE);
    else
        get_process_name_from_pid(pid, pname, sizeof(pname));
    const char *disp = extract_filename(pname);

    char ipstr[64] = "?";
    if (is_ipv6) {
        inet_ntop(AF_INET6, (void *)dest_ip6, ipstr, sizeof(ipstr));
    } else {
        struct in_addr a; a.S_un.S_addr = dest_ip;
        inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
    }

    char info[160];
    const char *u = is_udp ? " (UDP)" : "";
    if (action == RULE_ACTION_PROXY) {
        PROXY_CONFIG *p = find_proxy_config(cfg_id);
        if (p != NULL && p->host[0] != '\0')
            snprintf(info, sizeof(info), "Proxy %s://%s:%u%s",
                     p->type == PROXY_TYPE_HTTP ? "http" : "socks5", p->host, p->port, u);
        else
            snprintf(info, sizeof(info), "Proxy%s", u);
    } else if (action == RULE_ACTION_BLOCK) {
        snprintf(info, sizeof(info), "Blocked%s", u);
    } else {
        snprintf(info, sizeof(info), "Direct%s", u);
    }

    if (g_connection_callback != NULL)
        g_connection_callback(disp, pid, ipstr, dest_port, info);
    if (g_traffic_logging_enabled)
        add_logged_connection(pid, key, dest_port, action);
}

void clear_logged_connections(void)
{
    AcquireSRWLockExclusive(&lock);

    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }
    g_logged_count = 0;

    ReleaseSRWLockExclusive(&lock);
}

