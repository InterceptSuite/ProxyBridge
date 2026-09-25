// One relay thread owns all clients, transports and readiness snapshots.
// Bounds are provisional until load tests: no live client is evicted for capacity.
#define PB_UDP_CLIENT_CAP 4096
#define PB_UDP_CLIENT_BLOCK 64
#define PB_UDP_HASH_BUCKETS 1024
#define PB_UDP_SETUP_CAP 8
#define PB_UDP_IDLE_MS CONNECTION_STALE_TIMEOUT_MS
#define PB_UDP_REAP_INTERVAL_MS 250
#define PB_UDP_REAP_BUDGET 32

typedef struct PB_UDP_CONTEXT PB_UDP_CONTEXT;
typedef struct PB_UDP_CLIENT {
    PB_UDP_CONTEXT *owner;
    struct PB_UDP_CLIENT *hash_next;
    int index;
    int free_next;
    int active_position;
    BOOL used;
    struct sockaddr_storage source;
    int source_length;
    DWORD pid;
    UINT64 mapping_generation;
    UINT8 destination[16];
    UINT16 destination_port;
    ULONGLONG activity;
    PB_UDP_ASSOCIATION association;
} PB_UDP_CLIENT;

struct PB_UDP_CONTEXT {
    PB_UDP_CLIENT *blocks[PB_UDP_CLIENT_CAP / PB_UDP_CLIENT_BLOCK];
    PB_UDP_CLIENT *buckets[PB_UDP_HASH_BUCKETS];
    int capacity;
    int client_count;
    int free_head;
    PB_UDP_QUEUE_BUDGET queue_budget;
    PB_UDP_QUEUE_BUDGET queue_reported;
    ULONGLONG queue_report_at;
    int active_indices[PB_UDP_CLIENT_CAP];
    PROXY_CONFIG definitions[MAX_PROXY_CONFIGS];
    int definition_count;
    LONG64 definition_revision;
    LONG64 driver_epoch;
    WSAPOLLFD *polls;
    PB_UDP_CLIENT **owners;
    BOOL *controls;
    unsigned char input[MAXBUF];
    unsigned char output[MAXBUF];
    ULONGLONG capacity_log_at;
    int setup_cursor;
    int receive_cursor;
    int reap_cursor;
    ULONGLONG reap_at;
};

static PB_UDP_CLIENT *udp_slot(PB_UDP_CONTEXT *ctx, int index)
{
    return &ctx->blocks[index / PB_UDP_CLIENT_BLOCK][index % PB_UDP_CLIENT_BLOCK];
}

static unsigned udp_source_hash(const struct sockaddr_storage *source)
{
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)source;
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)source;
    const unsigned char *address = source->ss_family == AF_INET ?
        (const unsigned char *)&v4->sin_addr : (const unsigned char *)&v6->sin6_addr;
    unsigned hash = 2166136261u;
    int length = source->ss_family == AF_INET ? 4 : 16;
    for (int i = 0; i < length; ++i) hash = (hash ^ address[i]) * 16777619u;
    hash = (hash ^ (unsigned)source->ss_family) * 16777619u;
    hash = (hash ^ (source->ss_family == AF_INET ? v4->sin_port : v6->sin6_port)) * 16777619u;
    if (source->ss_family == AF_INET6) hash = (hash ^ v6->sin6_scope_id) * 16777619u;
    // Fold high bits before the power-of-two bucket reduction. Consecutive ports
    // in network byte order otherwise cluster into just a few buckets.
    hash ^= hash >> 16;
    hash *= 0x7feb352du;
    hash ^= hash >> 15;
    hash *= 0x846ca68bu;
    hash ^= hash >> 16;
    return hash % PB_UDP_HASH_BUCKETS;
}

// Called only outside consumption of a poll snapshot. Client addresses never
// move: only the next poll's metadata is replaced when a new block is admitted.
static BOOL udp_grow_clients(PB_UDP_CONTEXT *ctx)
{
    if (ctx->capacity >= PB_UDP_CLIENT_CAP) return FALSE;
    int capacity = ctx->capacity + PB_UDP_CLIENT_BLOCK;
    size_t polls_count = 2u + 2u * (size_t)capacity;
    PB_UDP_CLIENT *block = calloc(PB_UDP_CLIENT_BLOCK, sizeof(*block));
    WSAPOLLFD *polls = calloc(polls_count, sizeof(*polls));
    PB_UDP_CLIENT **owners = calloc(polls_count, sizeof(*owners));
    BOOL *controls = calloc(polls_count, sizeof(*controls));
    if (!block || !polls || !owners || !controls) {
        free(block); free(polls); free(owners); free(controls);
        return FALSE;
    }
    int free_head = ctx->capacity == 0 ? -1 : ctx->free_head;
    for (int i = PB_UDP_CLIENT_BLOCK - 1; i >= 0; --i) {
        block[i].owner = ctx;
        block[i].index = ctx->capacity + i;
        block[i].free_next = free_head;
        free_head = block[i].index;
    }
    ctx->blocks[ctx->capacity / PB_UDP_CLIENT_BLOCK] = block;
    ctx->capacity = capacity;
    ctx->free_head = free_head;
    free(ctx->polls); free(ctx->owners); free(ctx->controls);
    ctx->polls = polls; ctx->owners = owners; ctx->controls = controls;
    return TRUE;
}

static void udp_retire_client(PB_UDP_CLIENT *client)
{
    if (!client->used) return;
    PB_UDP_CONTEXT *ctx = client->owner;
    int index = client->index;
    PB_UDP_CLIENT **link = &ctx->buckets[udp_source_hash(&client->source)];
    while (*link && *link != client) link = &(*link)->hash_next;
    if (*link) *link = client->hash_next;
    int position = client->active_position;
    int last = ctx->active_indices[--ctx->client_count];
    ctx->active_indices[position] = last;
    udp_slot(ctx, last)->active_position = position;
    pb_udp_association_close(&client->association);
    memset(client, 0, sizeof(*client));
    client->owner = ctx;
    client->index = index;
    client->free_next = ctx->free_head;
    ctx->free_head = index;
}

static void udp_destroy_clients(PB_UDP_CONTEXT *ctx)
{
    for (int i = 0; i < ctx->capacity; ++i) udp_retire_client(udp_slot(ctx, i));
    for (int i = 0; i < ctx->capacity / PB_UDP_CLIENT_BLOCK; ++i) free(ctx->blocks[i]);
    free(ctx->polls); free(ctx->owners); free(ctx->controls);
}

static const PROXY_CONFIG *udp_definition(PB_UDP_CONTEXT *ctx, UINT32 id)
{
    for (int i = 0; i < ctx->definition_count; ++i)
        if (ctx->definitions[i].config_id != 0 &&
            (id == 0 || ctx->definitions[i].config_id == id)) return &ctx->definitions[i];
    return NULL;
}

static const PROXY_CONFIG *udp_selected_definition(PB_UDP_CONTEXT *ctx, const PROXY_CONFIG *selected)
{
    const PROXY_CONFIG *def = udp_definition(ctx, selected->config_id);
    return def != NULL && def->revision == selected->revision && def->type == PROXY_TYPE_SOCKS5
        ? def : NULL;
}

// Check a bounded slice per tick, not a full scan per incoming datagram.
// Only a confirmed missing/replaced mapping retires an otherwise idle client.
static void udp_reap_closed(PB_UDP_CONTEXT *ctx)
{
    ULONGLONG now = GetTickCount64();
    if (ctx->client_count == 0 || now < ctx->reap_at) return;
    ctx->reap_at = now + PB_UDP_REAP_INTERVAL_MS;
    int budget = min(PB_UDP_REAP_BUDGET, ctx->client_count);
    for (int i = 0; i < budget && ctx->client_count != 0; ++i) {
        ctx->reap_cursor %= ctx->client_count;
        PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[ctx->reap_cursor]);
        UINT8 destination[16] = {0};
        UINT16 port = 0;
        DWORD pid = 0;
        UINT64 generation = 0;
        BOOL found;
        if (c->source.ss_family == AF_INET6) {
            const struct sockaddr_in6 *source = (const struct sockaddr_in6 *)&c->source;
            found = pb_driver_udp_orig6((const UINT8 *)&source->sin6_addr,
                ntohs(source->sin6_port), destination, &port, &pid, &generation);
        } else {
            const struct sockaddr_in *source = (const struct sockaddr_in *)&c->source;
            UINT32 ip = 0;
            found = pb_driver_udp_orig(source->sin_addr.s_addr,
                ntohs(source->sin_port), &ip, &port, &pid, &generation);
            memcpy(destination, &ip, sizeof(ip));
        }
        DWORD error = found ? ERROR_SUCCESS : GetLastError();
        // The next refresh performs the existing full session invalidation.
        if (ctx->driver_epoch != pb_driver_session_epoch()) return;
        if ((!found && error == ERROR_NOT_FOUND) ||
            (found && (generation != c->mapping_generation || pid != c->pid ||
                port != c->destination_port || memcmp(destination, c->destination, 16))))
            udp_retire_client(c);
        else
            ++ctx->reap_cursor;
    }
}

static BOOL udp_refresh_definitions(PB_UDP_CONTEXT *ctx)
{
    LONG64 epoch = pb_driver_session_epoch();
    BOOL retired = epoch != ctx->driver_epoch;
    if (retired) {
        while (ctx->client_count != 0)
            udp_retire_client(udp_slot(ctx, ctx->active_indices[ctx->client_count - 1]));
        ctx->driver_epoch = epoch;
    }
    udp_reap_closed(ctx);
    if (InterlockedCompareExchange64(&g_proxy_revision, 0, 0) == ctx->definition_revision) return retired;
    ctx->definition_count = pb_proxy_snapshot(ctx->definitions, &ctx->definition_revision);
    for (int i = 0; i < ctx->client_count;) {
        PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[i]);
        const PROXY_CONFIG *def = udp_definition(ctx, c->association.config.config_id);
        if (def == NULL || def->revision != c->association.config.revision) udp_retire_client(c);
        else ++i;
    }
    return TRUE;
}

static BOOL udp_same_source(const struct sockaddr_storage *left, const struct sockaddr_storage *right)
{
    if (left->ss_family != right->ss_family) return FALSE;
    if (left->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)left;
        const struct sockaddr_in *b = (const struct sockaddr_in *)right;
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left;
    const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right;
    return a->sin6_port == b->sin6_port && a->sin6_scope_id == b->sin6_scope_id &&
           memcmp(&a->sin6_addr, &b->sin6_addr, 16) == 0;
}

static PB_UDP_CLIENT *udp_client(PB_UDP_CONTEXT *ctx, const struct sockaddr_storage *source,
    int source_length, DWORD pid, UINT64 generation, const UINT8 destination[16], UINT16 port, const PROXY_CONFIG *def)
{
    unsigned bucket = udp_source_hash(source);
    for (PB_UDP_CLIENT *c = ctx->buckets[bucket]; c != NULL; c = c->hash_next) {
        if (!udp_same_source(&c->source, source)) continue;
        if (def != NULL && c->pid == pid && c->mapping_generation == generation && c->destination_port == port &&
            memcmp(c->destination, destination, 16) == 0 &&
            c->association.config.config_id == def->config_id &&
            c->association.config.revision == def->revision) return c;
        udp_retire_client(c);
        break;
    }
    if (def == NULL) return NULL;
    if ((ctx->capacity == 0 || ctx->free_head < 0) && !udp_grow_clients(ctx)) {
        ULONGLONG now = GetTickCount64();
        if (now >= ctx->capacity_log_at) {
            ctx->capacity_log_at = now + 5000;
            log_message("UDP client capacity/allocation limit reached; new client datagram dropped");
        }
        return NULL;
    }
    PB_UDP_CLIENT *slot = udp_slot(ctx, ctx->free_head);
    ctx->free_head = slot->free_next;
    slot->used = TRUE;
    slot->source = *source;
    slot->source_length = source_length;
    slot->pid = pid;
    slot->mapping_generation = generation;
    memcpy(slot->destination, destination, 16);
    slot->destination_port = port;
    slot->activity = GetTickCount64();
    slot->association.config = *def;
    slot->association.pending.budget = &ctx->queue_budget;
    slot->association.udp_tcp_ctrl = slot->association.udp_send_sock = INVALID_SOCKET;
    slot->hash_next = ctx->buckets[bucket];
    ctx->buckets[bucket] = slot;
    slot->active_position = ctx->client_count;
    ctx->active_indices[ctx->client_count++] = slot->index;
    return slot;
}

