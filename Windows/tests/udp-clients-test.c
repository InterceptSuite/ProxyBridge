#include "pb_internal.h"
static int allocation_fail_at = -1, allocation_attempt, live_allocations;
static void *test_calloc(size_t count, size_t size)
{
    if (allocation_attempt++ == allocation_fail_at) return NULL;
    void *result = calloc(count, size);
    if (result) ++live_allocations;
    return result;
}
static void test_free(void *allocation)
{
    if (allocation) --live_allocations;
    free(allocation);
}
#define calloc test_calloc
#define free test_free
#include "../src/relay/pb_udp_clients.inc"
#undef calloc
#undef free

// Driver/config/transport adapters: exercise real client ownership code without
// opening a driver, creating SOCKS sockets or waiting thirty minutes.
volatile LONG64 g_proxy_revision = 1;
static LONG64 epoch = 1;
static DWORD query_error = ERROR_NOT_FOUND;
static unsigned closed_count, query_count;
static int mutation;
LONG64 pb_driver_session_epoch(void) { return epoch; }
int pb_proxy_snapshot(PROXY_CONFIG *out, LONG64 *revision)
{
    (void)out; *revision = 1; return 0;
}
void log_message(const char *message, ...) { (void)message; }
void pb_udp_association_close(PB_UDP_ASSOCIATION *a)
{
    ++closed_count;
    pb_udp_queue_clear(&a->pending);
}
BOOL pb_driver_udp_orig(UINT32 source, UINT16 source_port, UINT32 *ip,
    UINT16 *port, DWORD *pid, UINT64 *generation)
{
    (void)source;
    ++query_count;
    if (query_error == ERROR_SUCCESS) {
        const UINT8 destination[4] = {1, 2, 3, 4};
        memcpy(ip, destination, sizeof(*ip));
        *port = mutation == 2 ? 80 : 443;
        *pid = mutation == 3 ? 124 : 123;
        *generation = (UINT64)source_port - 10000 + 1 + (mutation == 1 ? 1 : 0);
        return TRUE;
    }
    SetLastError(query_error);
    return FALSE;
}
BOOL pb_driver_udp_orig6(const UINT8 source[16], UINT16 source_port, UINT8 ip[16],
    UINT16 *port, DWORD *pid, UINT64 *generation)
{
    (void)source;
    UINT32 value = 0;
    BOOL found = pb_driver_udp_orig(0, source_port, &value, port, pid, generation);
    memset(ip, 0, 16);
    memcpy(ip, &value, sizeof(value));
    return found;
}

static BOOL capacity_case(DWORD driver_error, BOOL change_epoch, BOOL ipv6)
{
    PB_UDP_CONTEXT *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return FALSE;
    ctx->driver_epoch = epoch;
    ctx->definition_revision = 1;
    PROXY_CONFIG def = {0};
    def.config_id = 1; def.revision = 1;
    UINT8 destination[16] = {1, 2, 3, 4};
    struct sockaddr_storage source = {0};
    struct sockaddr_in *v4 = (struct sockaddr_in *)&source;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&source;
    if (ipv6) { v6->sin6_family = AF_INET6; v6->sin6_addr.u.Byte[15] = 1; }
    else { v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK); }
    UINT16 *source_port = ipv6 ? &v6->sin6_port : &v4->sin_port;
    int source_length = ipv6 ? sizeof(*v6) : sizeof(*v4);
    BOOL ok = TRUE;
    for (int i = 0; i < PB_UDP_CLIENT_CAP; ++i) {
        *source_port = htons((u_short)(10000 + i));
        if (!udp_client(ctx, &source, source_length, 123, (UINT64)i + 1, destination, 443, &def)) ok = FALSE;
    }
    closed_count = query_count = 0;
    query_error = driver_error;
    if (change_epoch) ++epoch;
    udp_refresh_definitions(ctx);
    *source_port = htons(20000);
    PB_UDP_CLIENT *next = udp_client(ctx, &source, source_length, 123, 999, destination, 443, &def);
    BOOL should_free = driver_error == ERROR_NOT_FOUND || change_epoch;
    if (driver_error == ERROR_SUCCESS && mutation != 0) should_free = TRUE;
    ok = ok && (should_free ? next != NULL && closed_count > 0 : next == NULL && closed_count == 0);
    if (query_count > PB_UDP_REAP_BUDGET) ok = FALSE;
    // A repeated refresh before the next deadline must not issue another slice.
    unsigned previous_queries = query_count;
    ctx->reap_at = GetTickCount64() + 10000;
    udp_refresh_definitions(ctx);
    if (query_count != previous_queries) ok = FALSE;
    udp_destroy_clients(ctx);
    free(ctx);
    return ok;
}

static BOOL growth_case(void)
{
    PB_UDP_CONTEXT *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return FALSE;
    PROXY_CONFIG def = {0}; def.config_id = 1; def.revision = 1;
    UINT8 destination[16] = {1, 2, 3, 4};
    struct sockaddr_storage source = {0};
    struct sockaddr_in *address = (struct sockaddr_in *)&source;
    address->sin_family = AF_INET;
    PB_UDP_CLIENT *saved[512] = {0};
    BOOL ok = TRUE;
    for (int i = 0; i < 512; ++i) {
        address->sin_port = htons((UINT16)(10000 + i));
        saved[i] = udp_client(ctx, &source, sizeof(*address), 123, (UINT64)i + 1, destination, 443, &def);
        if (!saved[i]) ok = FALSE;
    }
    if (ctx->capacity != 512 || ctx->client_count != 512) ok = FALSE;
    int longest_chain = 0;
    for (int i = 0; i < PB_UDP_HASH_BUCKETS; ++i) {
        int length = 0;
        for (PB_UDP_CLIENT *c = ctx->buckets[i]; c; c = c->hash_next) ++length;
        if (length > longest_chain) longest_chain = length;
    }
    if (longest_chain > 16) ok = FALSE; // catch port-byte-order clustering
    printf("512-sequential-ports-longest-hash-chain=%d\n", longest_chain);
    for (int i = 0; i < 512; ++i) {
        address->sin_port = htons((UINT16)(10000 + i));
        if (saved[i] != udp_client(ctx, &source, sizeof(*address), 123, (UINT64)i + 1, destination, 443, &def)) ok = FALSE;
    }
    // Each of the four allocations required for growth can fail independently.
    for (int fail = 0; fail < 4; ++fail) {
        allocation_attempt = 0; allocation_fail_at = fail;
        int allocations_before = live_allocations;
        address->sin_port = htons(22000);
        if (udp_client(ctx, &source, sizeof(*address), 123, 999, destination, 443, &def) != NULL ||
            ctx->capacity != 512 || ctx->client_count != 512 || live_allocations != allocations_before) ok = FALSE;
        allocation_fail_at = -1;
    }
    unsigned char queued = 7;
    if (!saved[0] || !pb_udp_queue_push(&saved[0]->association.pending, &queued, 1, GetTickCount64())) ok = FALSE;
    for (int i = 0; i < 512; i += 2) if (saved[i]) udp_retire_client(saved[i]);
    if (ctx->queue_budget.bytes != 0) ok = FALSE;
    for (int i = 0; i < 256; ++i) {
        address->sin_port = htons((UINT16)(22000 + i));
        if (!udp_client(ctx, &source, sizeof(*address), 123, (UINT64)i + 1000, destination, 443, &def)) ok = FALSE;
    }
    if (ctx->capacity != 512 || ctx->client_count != 512) ok = FALSE;
    for (int i = 0; i < ctx->client_count; ++i) {
        PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[i]);
        if (!c->used || c->active_position != i || c->owner != ctx) ok = FALSE;
    }
    for (int i = 1; i < 512; i += 2) {
        address->sin_port = htons((UINT16)(10000 + i));
        if (saved[i] != udp_client(ctx, &source, sizeof(*address), 123, (UINT64)i + 1, destination, 443, &def)) ok = FALSE;
    }
    udp_destroy_clients(ctx);
    free(ctx);
    return ok && live_allocations == 0;
}

int main(void)
{
    int failures = 0;
    PB_UDP_CONTEXT *selection_ctx = calloc(1, sizeof(*selection_ctx));
    if (selection_ctx == NULL) return 1;
    PROXY_CONFIG selected = {0};
    selected.config_id = 7; selected.revision = 2; selected.type = PROXY_TYPE_SOCKS5;
    selection_ctx->definitions[0] = selected;
    selection_ctx->definition_count = 1;
    BOOL selection_ok = udp_selected_definition(selection_ctx, &selected) != NULL;
    selection_ctx->definitions[0].revision++;
    selection_ok = selection_ok && udp_selected_definition(selection_ctx, &selected) == NULL;
    selection_ctx->definitions[0] = selected;
    selection_ctx->definitions[0].config_id = 8;
    selection_ok = selection_ok && udp_selected_definition(selection_ctx, &selected) == NULL;
    selection_ctx->definitions[0] = selected;
    selection_ctx->definitions[0].type = PROXY_TYPE_HTTP;
    selection_ok = selection_ok && udp_selected_definition(selection_ctx, &selected) == NULL;
    selection_ctx->definition_count = 0;
    selection_ok = selection_ok && udp_selected_definition(selection_ctx, &selected) == NULL;
    free(selection_ctx);
    printf("selected-definition-update-delete-replacement-type: %s\n", selection_ok ? "PASS" : "FAIL");
    if (!selection_ok) ++failures;
    DWORD errors[] = {ERROR_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_DATA};
    const char *names[] = {"closed-endpoints-reclaimed", "driver-error-preserves-clients", "malformed-query-preserves-clients", "epoch-retires-clients"};
    const char *identity_names[] = {"live-mapping-preserved", "generation-reuse-reclaimed", "destination-change-reclaimed", "pid-change-reclaimed"};
    for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
        mutation = 0;
        for (int i = 0; i < 4; ++i) {
            BOOL ok = capacity_case(i < 3 ? errors[i] : ERROR_INVALID_HANDLE, i == 3, ipv6);
            printf("IPv%d %s: %s\n", ipv6 ? 6 : 4, names[i], ok ? "PASS" : "FAIL");
            if (!ok) ++failures;
        }
        for (mutation = 0; mutation < 4; ++mutation) {
            BOOL ok = capacity_case(ERROR_SUCCESS, FALSE, ipv6);
            printf("IPv%d %s: %s\n", ipv6 ? 6 : 4, identity_names[mutation], ok ? "PASS" : "FAIL");
            if (!ok) ++failures;
        }
    }
    BOOL growth_ok = growth_case();
    printf("stable-growth-hash-reuse-allocation-failures: %s\n", growth_ok ? "PASS" : "FAIL");
    if (!growth_ok || live_allocations != 0) ++failures;
    printf("sizeof-context=%zu sizeof-client=%zu maximum-clients=%d\n", sizeof(PB_UDP_CONTEXT), sizeof(PB_UDP_CLIENT), PB_UDP_CLIENT_CAP);
    return failures ? 1 : 0;
}
