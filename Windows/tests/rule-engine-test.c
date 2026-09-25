#include "pb_internal.h"
#include <ctype.h>
#include "../src/rules/pb_match.c"
#include "../src/rules/pb_ipmatch.c"
#include "../src/rules/pb_rule_storage.inc"
#include "token-list-reference.inc"
#include "rule-engine-reference.inc"
PROCESS_RULE *rules_list;
SRWLOCK g_rules_lock = SRWLOCK_INIT;
volatile BOOL g_has_domain_rules = TRUE;
static BOOL known_domain;
BOOL dns_cache_lookup(UINT32 ip, char *out, size_t size) {
    (void)ip; if (known_domain) strcpy_s(out, size, "www.example.com"); return known_domain;
}
BOOL dns_cache_lookup_v6(const UINT8 ip[16], char *out, size_t size) {
    (void)ip; return dns_cache_lookup(0, out, size);
}
BOOL find_proxy_config_copy(UINT32 id, PROXY_CONFIG *out) { (void)id; (void)out; return FALSE; }
static UINT32 state = 76543;
static UINT32 next_random(void) { state = state * 1664525u + 1013904223u; return state >> 8; }
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    const char *patterns[] = {"*", "ANY", "app.exe", "*.exe", "other.exe; app.exe", "\"C:\\app.exe\""};
    const char *hosts[] = {"*", "192.168.*.*", "10.0.0.1-10.0.0.9", "2001:db8::/32", "::1", "192.168.1.1;::1"};
    const char *ports[] = {"*", "443", "80;443", "8000-9000", " * "};
    const char *domains[] = {"*", "*.example.com", "other.example", " * "};
    RuleProtocol protocols[] = {RULE_PROTOCOL_BOTH, RULE_PROTOCOL_TCP, RULE_PROTOCOL_UDP};
    RuleAction actions[] = {RULE_ACTION_DIRECT, RULE_ACTION_PROXY, RULE_ACTION_BLOCK};
    const char *names[] = {"C:\\app.exe", "other.exe", "binary.bin", "APP.EXE"};
    UINT16 destinations[] = {80, 443, 8500};
    UINT32 ips[] = {htonl(0xc0a80101), htonl(0x0a000005), htonl(0x08080808)};
    UINT8 ips6[3][16];
    CHECK(inet_pton(AF_INET6, "::1", ips6[0]) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::5", ips6[1]) == 1);
    CHECK(inet_pton(AF_INET6, "2001:abcd::1", ips6[2]) == 1);
    unsigned comparisons = 0;
    for (unsigned profile = 0; profile < 200; ++profile) {
        ++g_rules_generation;
        PROCESS_RULE **tail = &rules_list;
        for (unsigned i = 0; i < 10; ++i) {
            PROCESS_RULE source = {0};
            strcpy_s(source.process_name, sizeof(source.process_name), patterns[next_random()%6]);
            source.target_hosts = (char *)hosts[next_random()%6];
            source.target_ports = (char *)ports[next_random()%5];
            source.target_domains = (char *)domains[next_random()%4];
            source.protocol = protocols[next_random()%3]; source.action = actions[next_random()%3];
            source.enabled = next_random()%5 != 0; source.proxy_config_id = i+1;
            *tail = copy_rule(&source); CHECK(*tail != NULL); tail = &(*tail)->next;
        }
        // Exercise detached prepared copies, including compacted/empty filters.
        for (PROCESS_RULE **link = &rules_list; *link != NULL; link = &(*link)->next) {
            PROCESS_RULE *old = *link;
            PROCESS_RULE *copy = copy_rule(old); CHECK(copy != NULL);
            copy->next = old->next; old->next = NULL;
            free_rules(old); *link = copy;
        }
        for (int known = 0; known < 2; ++known) for (int udp = 0; udp < 2; ++udp)
            for (unsigned name = 0; name < 4; ++name) for (unsigned port = 0; port < 3; ++port)
                for (unsigned ip = 0; ip < 3; ++ip) {
                    known_domain = known;
                    g_has_domain_rules = known; // exercise both cache bypass and cacheable decisions
                    UINT32 old_id = 999, new_id = 999;
                    CHECK(reference_rule(names[name], ips[ip], destinations[port], udp, &old_id) == match_rule(names[name], ips[ip], destinations[port], udp, &new_id));
                    CHECK(old_id == new_id);
                    CHECK(reference_rule_v6(names[name], ips6[ip], destinations[port], udp, &old_id) == match_rule_v6(names[name], ips6[ip], destinations[port], udp, &new_id));
                    CHECK(old_id == new_id); comparisons += 2;
                }
        free_rules(rules_list); rules_list = NULL;
    }
    // Explicitly ensure an unrestricted wildcard is deferred behind a specific rule.
    PROCESS_RULE source = {0};
    strcpy_s(source.process_name, sizeof(source.process_name), "*");
    source.target_hosts = source.target_ports = source.target_domains = "*";
    source.protocol = RULE_PROTOCOL_BOTH; source.enabled = TRUE;
    source.action = RULE_ACTION_BLOCK; source.proxy_config_id = 1;
    rules_list = copy_rule(&source); CHECK(rules_list != NULL);
    strcpy_s(source.process_name, sizeof(source.process_name), "app.exe");
    source.action = RULE_ACTION_PROXY; source.proxy_config_id = 2;
    rules_list->next = copy_rule(&source); CHECK(rules_list->next != NULL);
    UINT32 id;
    CHECK(match_rule("app.exe", ips[0], 443, FALSE, &id) == RULE_ACTION_PROXY && id == 2);
    CHECK(match_rule_v6("app.exe", ips6[0], 443, TRUE, &id) == RULE_ACTION_PROXY && id == 2);
    free_rules(rules_list); rules_list = NULL;
    printf("PASS: %u complete engine comparisons; protocol, action/config, disabled/order, unknown domain and deferred wildcard\n", comparisons);
    return 0;
}
