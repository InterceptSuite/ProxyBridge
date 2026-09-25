#define PB_LOG_CAPACITY 100
#define PB_LOG_BUCKETS 128
typedef struct { PB_LOG_KEY key; unsigned next; BOOL used; } PB_LOG_ENTRY;
static PB_LOG_ENTRY log_entries[PB_LOG_CAPACITY];
static unsigned log_buckets[PB_LOG_BUCKETS], log_next;
static SRWLOCK log_history_lock = SRWLOCK_INIT;
static unsigned log_key_hash(const PB_LOG_KEY *key)
{
    UINT32 hash = 2166136261u;
    for (unsigned i = 0; i < 16; ++i) hash = (hash ^ key->address[i]) * 16777619u;
    hash = (hash ^ key->pid) * 16777619u;
    hash = (hash ^ key->dest_port) * 16777619u;
    hash = (hash ^ key->ipv6 ^ (key->udp << 1)) * 16777619u;
    hash = (hash ^ key->action ^ key->proxy_id) * 16777619u;
    hash = (hash ^ (UINT32)key->proxy_revision ^ (UINT32)((UINT64)key->proxy_revision >> 32)) * 16777619u;
    return (hash ^ (hash >> 16)) & (PB_LOG_BUCKETS - 1);
}
static BOOL log_key_equal(const PB_LOG_KEY *a, const PB_LOG_KEY *b)
{
    return a->pid == b->pid && a->dest_port == b->dest_port && a->ipv6 == b->ipv6 && a->udp == b->udp &&
        a->action == b->action && a->proxy_id == b->proxy_id && a->proxy_revision == b->proxy_revision &&
        !memcmp(a->address, b->address, 16);
}
BOOL pb_log_connection_once(const PB_LOG_KEY *key, BOOL record)
{
    unsigned bucket = log_key_hash(key);
    AcquireSRWLockExclusive(&log_history_lock);
    for (unsigned n = log_buckets[bucket]; n != 0; n = log_entries[n-1].next) {
        if (log_key_equal(&log_entries[n-1].key, key)) {
            ReleaseSRWLockExclusive(&log_history_lock); return FALSE;
        }
    }
    if (record && InterlockedCompareExchange((volatile LONG *)&g_traffic_logging_enabled, 0, 0)) {
        PB_LOG_ENTRY *entry = &log_entries[log_next];
        if (entry->used) {
            unsigned *link = &log_buckets[log_key_hash(&entry->key)];
            while (*link != 0 && *link != log_next + 1) link = &log_entries[*link-1].next;
            if (*link != 0) *link = entry->next;
        }
        entry->key = *key; entry->used = TRUE;
        entry->next = log_buckets[bucket]; log_buckets[bucket] = log_next + 1;
        log_next = (log_next + 1) % PB_LOG_CAPACITY;
    }
    ReleaseSRWLockExclusive(&log_history_lock);
    return TRUE;
}
void clear_logged_connections(void)
{
    AcquireSRWLockExclusive(&log_history_lock);
    memset(log_entries, 0, sizeof(log_entries));
    memset(log_buckets, 0, sizeof(log_buckets));
    log_next = 0;
    ReleaseSRWLockExclusive(&log_history_lock);
}
void pb_set_traffic_logging(BOOL enabled)
{
    AcquireSRWLockExclusive(&log_history_lock);
    InterlockedExchange((volatile LONG *)&g_traffic_logging_enabled, !!enabled);
    if (!enabled) {
        memset(log_entries, 0, sizeof(log_entries));
        memset(log_buckets, 0, sizeof(log_buckets));
        log_next = 0;
    }
    ReleaseSRWLockExclusive(&log_history_lock);
}
