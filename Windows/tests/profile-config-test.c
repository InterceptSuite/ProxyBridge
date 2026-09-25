#define main engine_regression_main
#include "rule-engine-test.c"
#undef main
PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
int g_proxy_config_count;
UINT32 g_next_config_id;
volatile LONG64 g_proxy_revision;
SRWLOCK g_proxy_lock = SRWLOCK_INIT;
volatile BOOL running, g_has_active_rules;
BOOL g_localhost_via_proxy;
struct _PBDRV_WATCHLIST { int placeholder; };
static BOOL accept_driver = TRUE;
struct _PBDRV_WATCHLIST *pb_driver_prepare_rules(const PROCESS_RULE *rules) {
    (void)rules; return calloc(1, sizeof(struct _PBDRV_WATCHLIST));
}
BOOL pb_driver_apply_rules(const struct _PBDRV_WATCHLIST *watch) {
    (void)watch; if (!accept_driver) SetLastError(ERROR_GEN_FAILURE); return accept_driver;
}
BOOL pb_driver_apply_profile_rules(const struct _PBDRV_WATCHLIST *watch, BOOL loopback) {
    (void)loopback; return pb_driver_apply_rules(watch);
}
#include "../src/rules/pb_policy_commit.inc"
static PROCESS_RULE *candidate(UINT32 index)
{
    PROCESS_RULE source = {0};
    strcpy_s(source.process_name, sizeof(source.process_name), "app.exe");
    source.target_hosts = source.target_ports = source.target_domains = "*";
    source.enabled = TRUE; source.protocol = RULE_PROTOCOL_BOTH;
    source.action = RULE_ACTION_PROXY; source.proxy_config_id = index;
    return copy_rule(&source);
}
int main(void)
{
    PROXY_CONFIG a = {0}, b = {0}, incoming[2];
    a.config_id = 10; a.revision = 2; a.type = PROXY_TYPE_SOCKS5;
    a.port = 1080; a.resolved_ip = htonl(0x7f000001); strcpy_s(a.host, sizeof(a.host), "localhost");
    b = a; b.config_id = 20; b.revision = 3; b.port = 1081;
    g_proxy_configs[0] = a; g_proxy_config_count = 1; g_next_config_id = 21;
    for (int field = 0; field < 7; ++field) {
        incoming[0] = a;
        switch (field) {
            case 0: incoming[0].type = PROXY_TYPE_HTTP; break;
            case 1: ++incoming[0].port; break;
            case 2: ++incoming[0].resolved_ip; break;
            case 3: incoming[0].send_domain_to_proxy = TRUE; break;
            case 4: strcpy_s(incoming[0].host, sizeof(a.host), "other"); break;
            case 5: strcpy_s(incoming[0].username, sizeof(a.username), "user"); break;
            case 6: strcpy_s(incoming[0].password, sizeof(a.password), "test-password"); break;
        }
        UINT32 next; BOOL changed;
        CHECK(stage_profile_configs(incoming, 1, &next, &changed));
        CHECK(changed && incoming[0].config_id == 21 && incoming[0].revision == 0 && next == 22 && g_next_config_id == 21);
    }
    g_proxy_configs[1] = b; g_proxy_config_count = 2; g_proxy_revision = 3;
    incoming[0] = a; incoming[1] = b;
    UINT32 ids[2] = {999, 999}; BOOL flush = FALSE, loopback = FALSE;
    PROCESS_RULE *rule = candidate(2); CHECK(rule != NULL);
    CHECK(commit_policy(rule, &flush, incoming, 2, ids, &loopback));
    CHECK(ids[0] == 10 && ids[1] == 20 && g_next_config_id == 21 && g_proxy_revision == 3 && rules_list->proxy_config_id == 20);
    incoming[0] = b; incoming[1] = a;
    rule = candidate(1); CHECK(rule != NULL);
    CHECK(commit_policy(rule, &flush, incoming, 2, ids, &loopback));
    CHECK(ids[0] == 20 && ids[1] == 10 && g_proxy_revision == 4 && incoming[0].revision == 3 && incoming[1].revision == 2);
    strcpy_s(incoming[0].password, sizeof(incoming[0].password), "changed");
    rule = candidate(1); CHECK(rule != NULL);
    CHECK(commit_policy(rule, &flush, incoming, 2, ids, &loopback));
    CHECK(ids[0] == 21 && ids[1] == 10 && g_next_config_id == 22 && g_proxy_revision == 5 && incoming[1].revision == 2);
    PROXY_CONFIG saved[MAX_PROXY_CONFIGS]; memcpy(saved, g_proxy_configs, sizeof(saved));
    UINT64 generation = g_rules_generation;
    PROCESS_RULE *published = rules_list;
    incoming[0].port++;
    ids[0] = ids[1] = 999; accept_driver = FALSE; loopback = TRUE;
    rule = candidate(1); CHECK(rule != NULL);
    CHECK(!commit_policy(rule, &flush, incoming, 2, ids, &loopback) && GetLastError() == ERROR_GEN_FAILURE);
    CHECK(!memcmp(saved, g_proxy_configs, sizeof(saved)) && g_proxy_revision == 5 && g_next_config_id == 22 && rules_list == published && g_rules_generation == generation && !g_localhost_via_proxy && ids[0] == 999 && ids[1] == 999);
    free_rules(rule); accept_driver = TRUE;
    incoming[0] = incoming[1] = a;
    CHECK(commit_policy(NULL, &flush, incoming, 2, ids, &loopback));
    CHECK(ids[0] == 10 && ids[1] == 22 && g_next_config_id == 23 && incoming[0].revision == 2);
    LONG64 revision = g_proxy_revision;
    g_next_config_id = 0;
    CHECK(commit_policy(NULL, &flush, incoming, 2, ids, &loopback) && g_proxy_revision == revision);
    incoming[1].port++;
    CHECK(!commit_policy(NULL, &flush, incoming, 2, ids, &loopback) && GetLastError() == ERROR_ARITHMETIC_OVERFLOW);
    CHECK(g_proxy_revision == revision && g_next_config_id == 0);
    CHECK(commit_policy(NULL, &flush, incoming, 0, ids, &loopback) && g_proxy_config_count == 0);
    g_next_config_id = ~(UINT32)0; incoming[0] = a; incoming[1] = b;
    CHECK(!commit_policy(NULL, &flush, incoming, 2, ids, &loopback) && g_next_config_id == ~(UINT32)0 && g_proxy_config_count == 0);
    CHECK(commit_policy(NULL, &flush, incoming, 1, ids, &loopback) && ids[0] == ~(UINT32)0 && g_next_config_id == 0);
    CHECK(commit_policy(NULL, &flush, incoming, 1, ids, &loopback));
    puts("PASS: exact/no-op/reorder, every definition field, duplicates, index mapping, failed publication, ID exhaustion and final ID");
    return 0;
}
