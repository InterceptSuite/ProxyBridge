#define PB_RULE_CACHE_SIZE 64
UINT64 g_rules_generation;
typedef struct {
    BOOL valid, v6, udp;
    UINT64 generation;
    UINT8 ip[16];
    UINT16 port;
    RuleAction action;
    UINT32 proxy;
    char process[MAX_PROCESS_NAME];
} PB_RULE_CACHE_ENTRY;
static PB_RULE_CACHE_ENTRY rule_cache[PB_RULE_CACHE_SIZE];
static SRWLOCK rule_cache_lock = SRWLOCK_INIT;

// Caller holds g_rules_lock throughout lookup, matching and publication.
// Domain-dependent decisions intentionally bypass this cache.
static unsigned rule_cache_bucket(const char *process, const UINT8 *ip, size_t bytes, UINT16 port, BOOL udp, BOOL v6)
{
    UINT32 hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)process; *p; ++p) hash = (hash ^ *p) * 16777619u;
    for (size_t i = 0; i < bytes; ++i) hash = (hash ^ ip[i]) * 16777619u;
    hash = (hash ^ port) * 16777619u;
    hash = (hash ^ (udp ? 1u : 0u) ^ (v6 ? 2u : 0u)) * 16777619u;
    hash ^= hash >> 16;
    return hash & (PB_RULE_CACHE_SIZE - 1);
}

static BOOL rule_cache_lookup(unsigned bucket, const char *process, const UINT8 *ip, size_t bytes,
                              UINT16 port, BOOL udp, BOOL v6, RuleAction *action, UINT32 *proxy)
{
    AcquireSRWLockShared(&rule_cache_lock);
    const PB_RULE_CACHE_ENTRY *entry = &rule_cache[bucket];
    BOOL hit = entry->valid && entry->generation == g_rules_generation && entry->port == port &&
        entry->udp == !!udp && entry->v6 == !!v6 && memcmp(entry->ip, ip, bytes) == 0 && !strcmp(entry->process, process);
    if (hit) { *action = entry->action; *proxy = entry->proxy; }
    ReleaseSRWLockShared(&rule_cache_lock);
    return hit;
}

static void rule_cache_store(unsigned bucket, const char *process, const UINT8 *ip, size_t bytes,
                             UINT16 port, BOOL udp, BOOL v6, RuleAction action, UINT32 proxy)
{
    AcquireSRWLockExclusive(&rule_cache_lock);
    PB_RULE_CACHE_ENTRY *entry = &rule_cache[bucket];
    entry->generation = g_rules_generation; entry->v6 = !!v6; entry->udp = !!udp;
    entry->port = port; entry->action = action; entry->proxy = proxy;
    memcpy(entry->ip, ip, bytes);
    strcpy_s(entry->process, sizeof(entry->process), process);
    entry->valid = TRUE;
    ReleaseSRWLockExclusive(&rule_cache_lock);
}
