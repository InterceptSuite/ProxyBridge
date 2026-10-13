#include "pb_internal.h"

// Connection tracking: forward table, reverse index, logged connections.

static CONNECTION_INFO *g_domain_rev_table[CONNECTION_HASH_SIZE];

static UINT32 rev_hash_domain(const char *hostname, UINT16 port)
{
    UINT32 hash = 5381u ^ port;
    for (const unsigned char *p = (const unsigned char *)hostname; *p; p++)
    {
        unsigned char c = *p;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        hash = ((hash << 5) + hash) ^ c;
    }
    return hash % CONNECTION_HASH_SIZE;
}

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
    if (c->is_udp && c->hostname[0])
    {
        c->domain_rev_bucket = rev_hash_domain(c->hostname, c->orig_dest_port);
        c->domain_rev_next = g_domain_rev_table[c->domain_rev_bucket];
        g_domain_rev_table[c->domain_rev_bucket] = c;
        c->in_domain_rev = TRUE;
    }
}

void rev_unlink(CONNECTION_INFO *c)
{
    if (c->in_rev)
    {
        CONNECTION_INFO **pp = &connection_rev_table[c->rev_bucket];
        while (*pp) { if (*pp == c) { *pp = c->rev_next; break; } pp = &(*pp)->rev_next; }
        c->in_rev = FALSE;
        c->rev_next = NULL;
    }
    if (c->in_domain_rev)
    {
        CONNECTION_INFO **pp = &g_domain_rev_table[c->domain_rev_bucket];
        while (*pp) { if (*pp == c) { *pp = c->domain_rev_next; break; } pp = &(*pp)->domain_rev_next; }
        c->in_domain_rev = FALSE;
        c->domain_rev_next = NULL;
    }
}

static BOOL connection_capture_process(DWORD pid, FILETIME *created, HANDLE *process)
{
    return get_process_identity(pid, created, process);
}

BOOL find_unique_udp_sender_by_domain(const char *hostname, UINT16 dest_port,
                                      UINT32 proxy_config_id,
                                      BOOL *is_ipv6, UINT32 *client_ip, UINT8 client_ip6[16],
                                      UINT16 *client_port)
{
    if (!hostname || !hostname[0] || !is_ipv6 || !client_ip || !client_ip6 || !client_port)
        return FALSE;

    CONNECTION_INFO *match = NULL;
    AcquireSRWLockShared(&lock);
    for (CONNECTION_INFO *c = g_domain_rev_table[rev_hash_domain(hostname, dest_port)];
         c; c = c->domain_rev_next)
    {
        PROXY_CONFIG *cfg = find_proxy_config(c->proxy_config_id);
        if (c->is_udp && cfg && cfg->config_id == proxy_config_id &&
            c->orig_dest_port == dest_port &&
            _stricmp(c->hostname, hostname) == 0)
        {
            if (match) { match = NULL; break; } // Ambiguous: never route a reply to an arbitrary client.
            match = c;
        }
    }
    if (match)
    {
        *is_ipv6 = match->is_ipv6;
        *client_ip = match->src_ip;
        if (match->is_ipv6) memcpy(client_ip6, match->src_ip6, 16);
        *client_port = match->src_port;
        InterlockedExchange64((LONGLONG volatile*)&match->last_activity, (LONGLONG)GetTickCount64());
    }
    ReleaseSRWLockShared(&lock);
    return match != NULL;
}

void add_connection(UINT16 src_port, BOOL is_udp, UINT32 src_ip, UINT32 dest_ip,
                    UINT16 dest_port, UINT32 proxy_config_id, const char *hostname,
                    DWORD process_id, BOOL log_pending)
{
    FILETIME process_created = {0};
    HANDLE process = NULL;
    BOOL has_process_identity = connection_capture_process(process_id, &process_created, &process);
    const char *conn_hostname = hostname;
    AcquireSRWLockExclusive(&lock);
    if (has_process_identity && WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
    {
        ReleaseSRWLockExclusive(&lock);
        CloseHandle(process);
        return;
    }

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
            strncpy_s(existing->hostname, sizeof(existing->hostname),
                      conn_hostname ? conn_hostname : "", _TRUNCATE);
            existing->log_pending = log_pending;
            existing->process_id = process_id;
            existing->process_created = process_created;
            existing->has_process_identity = has_process_identity;
            existing->is_tracked = TRUE;
            existing->fin_flags = 0;
            existing->last_activity = GetTickCount64();
            rev_insert(existing);
            ReleaseSRWLockExclusive(&lock);
            if (process) CloseHandle(process);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)calloc(1, sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&lock);
        if (process) CloseHandle(process);
        return;
    }

    conn->src_port = src_port;
    conn->is_udp = is_udp;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    strncpy_s(conn->hostname, sizeof(conn->hostname), conn_hostname ? conn_hostname : "", _TRUNCATE);
    conn->log_pending = log_pending;
    conn->process_id = process_id;
    conn->process_created = process_created;
    conn->has_process_identity = has_process_identity;
    conn->is_tracked = TRUE;
    conn->is_ipv6 = FALSE;
    conn->last_activity = GetTickCount64();

    conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = conn;
    rev_insert(conn);
    ReleaseSRWLockExclusive(&lock);
    if (process) CloseHandle(process);
}

void add_connection_v6(UINT16 src_port, BOOL is_udp, const UINT8 src_ip6[16],
                       const UINT8 dest_ip6[16], UINT16 dest_port,
                       UINT32 proxy_config_id, const char *hostname, DWORD process_id,
                       BOOL log_pending)
{
    FILETIME process_created = {0};
    HANDLE process = NULL;
    BOOL has_process_identity = connection_capture_process(process_id, &process_created, &process);
    const char *conn_hostname = hostname;
    AcquireSRWLockExclusive(&lock);
    if (has_process_identity && WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
    {
        ReleaseSRWLockExclusive(&lock);
        CloseHandle(process);
        return;
    }

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = connection_hash_table[hash];

    while (existing != NULL) {
        if (existing->src_port == src_port && existing->is_udp == is_udp && existing->is_ipv6) {
            rev_unlink(existing);   // dest may change (port reuse) - re-key the reverse index
            existing->is_ipv6 = TRUE;
            memcpy(existing->src_ip6, src_ip6, 16);
            memcpy(existing->orig_dest_ip6, dest_ip6, 16);
            existing->orig_dest_port = dest_port;
            existing->proxy_config_id = proxy_config_id;
            strncpy_s(existing->hostname, sizeof(existing->hostname),
                      conn_hostname ? conn_hostname : "", _TRUNCATE);
            existing->log_pending = log_pending;
            existing->process_id = process_id;
            existing->process_created = process_created;
            existing->has_process_identity = has_process_identity;
            existing->is_tracked = TRUE;
            existing->fin_flags = 0;
            existing->last_activity = GetTickCount64();
            rev_insert(existing);
            ReleaseSRWLockExclusive(&lock);
            if (process) CloseHandle(process);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)calloc(1, sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&lock);
        if (process) CloseHandle(process);
        return;
    }

    conn->src_port = src_port;
    conn->is_udp = is_udp;
    conn->src_ip = 0;
    conn->orig_dest_ip = 0;
    conn->is_ipv6 = TRUE;
    memcpy(conn->src_ip6, src_ip6, 16);
    memcpy(conn->orig_dest_ip6, dest_ip6, 16);
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    strncpy_s(conn->hostname, sizeof(conn->hostname), conn_hostname ? conn_hostname : "", _TRUNCATE);
    conn->log_pending = log_pending;
    conn->process_id = process_id;
    conn->process_created = process_created;
    conn->has_process_identity = has_process_identity;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();
    conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = conn;
    rev_insert(conn);
    ReleaseSRWLockExclusive(&lock);
    if (process) CloseHandle(process);
}

BOOL get_connection_full_v6(UINT16 src_port, BOOL is_udp, UINT8 dest_ip6[16],
                            UINT16 *dest_port, UINT32 *proxy_config_id,
                            char *hostname, size_t hostname_size,
                            DWORD *process_id, BOOL *log_pending)
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
            if (hostname && hostname_size)
                strncpy_s(hostname, hostname_size, conn->hostname, _TRUNCATE);
            if (process_id != NULL) *process_id = conn->process_id;
            if (log_pending != NULL) *log_pending = conn->log_pending;
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

// ---- UDP flow validation + direct-decision cache (see pb_internal.h) ----
BOOL udp_flow_validate(UINT16 src_port, BOOL is_ipv6, UINT32 dest_ip, const UINT8 dest_ip6[16], UINT16 dest_port)
{
    ULONGLONG now = GetTickCount64();
    int hash = src_port % CONNECTION_HASH_SIZE;
    BOOL need_write = FALSE, valid = FALSE;

    AcquireSRWLockShared(&lock);
    CONNECTION_INFO *c = connection_hash_table[hash];
    while (c != NULL && !(c->src_port == src_port && c->is_udp && c->is_ipv6 == is_ipv6)) c = c->next;
    if (c == NULL) { ReleaseSRWLockShared(&lock); return FALSE; }
    BOOL same = (c->orig_dest_port == dest_port) &&
                (is_ipv6 ? memcmp(c->orig_dest_ip6, dest_ip6, 16) == 0 : c->orig_dest_ip == dest_ip);
    if (c->last_activity < now && now - c->last_activity > UDP_REEVAL_IDLE_MS) need_write = TRUE;   // evict (guard: another thread may have stamped a later tick)
    else if (same) { InterlockedExchange64((LONGLONG volatile*)&c->last_activity, (LONGLONG)now); valid = TRUE; }
    else need_write = TRUE;                                                   // retarget
    ReleaseSRWLockShared(&lock);
    if (!need_write) return valid;

    AcquireSRWLockExclusive(&lock);
    CONNECTION_INFO **pp = &connection_hash_table[hash];
    while (*pp != NULL && !((*pp)->src_port == src_port && (*pp)->is_udp && (*pp)->is_ipv6 == is_ipv6)) pp = &(*pp)->next;
    c = *pp;
    if (c == NULL) { ReleaseSRWLockExclusive(&lock); return FALSE; }
    BOOL still_same = (c->orig_dest_port == dest_port) &&
                      (is_ipv6 ? memcmp(c->orig_dest_ip6, dest_ip6, 16) == 0
                               : c->orig_dest_ip == dest_ip);
    if ((c->last_activity < now && now - c->last_activity > UDP_REEVAL_IDLE_MS) ||
        !still_same)
    {
        *pp = c->next;
        rev_unlink(c);
        free(c);
        valid = FALSE;
    }
    else
    {
        c->last_activity = now;
        valid = TRUE;
    }
    ReleaseSRWLockExclusive(&lock);
    return valid;
}

#define UDP_DIRECT_SLOTS 4096
typedef struct { UINT8 dst[16]; UINT16 sp, dp; BOOL v6; DWORD until; } UDP_DIRECT_ENTRY;
static UDP_DIRECT_ENTRY g_udp_direct[UDP_DIRECT_SLOTS];

static UDP_DIRECT_ENTRY *udp_direct_slot(BOOL v6, const void *dst, UINT16 sp, UINT16 dp, UINT8 key[16])
{
    memset(key, 0, 16);
    memcpy(key, dst, v6 ? 16 : 4);
    UINT32 h = ((UINT32)sp << 16) ^ dp ^ (v6 ? 0x9E3779B9u : 0);
    for (int i = 0; i < 16; i++) h = h * 31u + key[i];
    return &g_udp_direct[h % UDP_DIRECT_SLOTS];
}

BOOL udp_direct_cached(BOOL is_ipv6, const void *dst, UINT16 src_port, UINT16 dst_port)
{
    UINT8 key[16];
    UDP_DIRECT_ENTRY *e = udp_direct_slot(is_ipv6, dst, src_port, dst_port, key);
    return e->until != 0 && e->sp == src_port && e->dp == dst_port && e->v6 == is_ipv6 &&
           memcmp(e->dst, key, 16) == 0 && (int)(e->until - GetTickCount()) > 0;
}

void udp_direct_remember(BOOL is_ipv6, const void *dst, UINT16 src_port, UINT16 dst_port)
{
    UINT8 key[16];
    UDP_DIRECT_ENTRY *e = udp_direct_slot(is_ipv6, dst, src_port, dst_port, key);
    memcpy(e->dst, key, 16); e->sp = src_port; e->dp = dst_port; e->v6 = is_ipv6;
    DWORD u = GetTickCount() + UDP_DIRECT_TTL_MS;
    e->until = u ? u : 1;
}

void udp_direct_reset(void)
{
    memset(g_udp_direct, 0, sizeof(g_udp_direct));
}

BOOL is_connection_tracked(UINT16 src_port, BOOL is_udp, BOOL is_ipv6)
{
    BOOL tracked = FALSE;
    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_udp == is_udp && conn->is_ipv6 == is_ipv6 && conn->is_tracked) {
            tracked = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);
    return tracked;
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

BOOL get_connection_full(UINT16 src_port, BOOL is_udp, UINT32 *dest_ip,
                         UINT16 *dest_port, UINT32 *proxy_config_id,
                         char *hostname, size_t hostname_size,
                         DWORD *process_id, BOOL *log_pending)
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
            if (hostname && hostname_size)
                strncpy_s(hostname, hostname_size, conn->hostname, _TRUNCATE);
            if (process_id != NULL) *process_id = conn->process_id;
            if (log_pending != NULL) *log_pending = conn->log_pending;
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

void remove_connections_for_process(DWORD process_id, const FILETIME *process_created)
{
    if (!process_id || !process_created) return;
    AcquireSRWLockExclusive(&lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        CONNECTION_INFO **link = &connection_hash_table[i];
        while (*link)
        {
            CONNECTION_INFO *c = *link;
            if (c->has_process_identity && c->process_id == process_id &&
                CompareFileTime(&c->process_created, process_created) == 0)
            {
                *link = c->next;
                rev_unlink(c);
                free(c);
            }
            else link = &c->next;
        }
    }
    ReleaseSRWLockExclusive(&lock);
}

void connection_fin(UINT16 src_port, BOOL is_ipv6, UINT8 bit)
{
    AcquireSRWLockExclusive(&lock);
    CONNECTION_INFO **pp = &connection_hash_table[src_port % CONNECTION_HASH_SIZE];
    while (*pp != NULL && !((*pp)->src_port == src_port && !(*pp)->is_udp && (*pp)->is_ipv6 == is_ipv6))
        pp = &(*pp)->next;
    CONNECTION_INFO *c = *pp;
    if (c != NULL)
    {
        c->fin_flags |= bit;
        if (c->fin_flags == 3)
        {
            *pp = c->next;
            rev_unlink(c);
            free(c);
        }
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
                ReleaseSRWLockExclusive(&lock);
                free(to_free);
                AcquireSRWLockExclusive(&lock);
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        ReleaseSRWLockExclusive(&lock);
    }

    ULONGLONG now_cache = GetTickCount64();
    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        AcquireSRWLockExclusive(&lock);
        PID_CACHE_ENTRY **entry_ptr = &pid_cache[i];
        while (*entry_ptr != NULL)
        {
            if (now_cache - (*entry_ptr)->timestamp > 10000)
            {
                PID_CACHE_ENTRY *to_free = *entry_ptr;
                *entry_ptr = (*entry_ptr)->next;
                ReleaseSRWLockExclusive(&lock);
                free(to_free);
                AcquireSRWLockExclusive(&lock);
            }
            else
            {
                entry_ptr = &(*entry_ptr)->next;
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

