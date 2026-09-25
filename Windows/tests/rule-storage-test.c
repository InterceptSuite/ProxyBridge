#include "pb_internal.h"
#include <ctype.h>
#include "../src/rules/pb_wildcard.inc"
static int live, attempt, fail_at = -1;
static void *tracked_malloc(size_t size)
{
    if (attempt++ == fail_at) return NULL;
    void *p = malloc(size);
    if (p != NULL) ++live;
    return p;
}
static void tracked_free(void *p)
{
    if (p != NULL) --live;
    free(p);
}
static char *tracked_strdup(const char *s)
{
    size_t length = strlen(s) + 1;
    char *p = tracked_malloc(length);
    if (p != NULL) memcpy(p, s, length);
    return p;
}
#define malloc tracked_malloc
#define free tracked_free
#define _strdup tracked_strdup
#include "../src/rules/pb_process_patterns.inc"
#include "../src/rules/pb_port_filter.inc"
#include "../src/rules/pb_domain_filter.inc"
#include "../src/rules/pb_ipv6_filter.inc"
#include "../src/rules/pb_ipv4_filter.inc"
#include "../src/rules/pb_rule_storage.inc"
#undef malloc
#undef free
#undef _strdup
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d live=%d\n", __LINE__, live); return 1; } } while (0)
int main(void)
{
    PROCESS_RULE source = {0};
    strcpy_s(source.process_name, sizeof(source.process_name), "chrome.exe; *.bin");
    source.target_hosts = "*"; source.target_ports = "443"; source.target_domains = "*.example.com";
    PROCESS_RULE *original = copy_rule(&source);
    CHECK(original != NULL && live == 9);
    CHECK(pb_match_process_prepared(original->prepared_process, "chrome.exe"));
    for (int mode = 0; mode < 2; ++mode) for (int failure = 0; failure < (mode ? 9 : 11); ++failure) {
        attempt = 0; fail_at = failure;
        PROCESS_RULE *candidate = copy_rule(mode ? original : &source);
        CHECK(candidate == NULL && live == 9);
        CHECK(pb_match_process_prepared(original->prepared_process, "thing.bin"));
        CHECK(!strcmp(original->target_ports, "443"));
        CHECK(pb_match_port_prepared(original->prepared_ports, 443));
        CHECK(pb_match_domain_prepared(original->prepared_domains, "example.com"));
    }
    fail_at = -1;
    attempt = 0;
    PROCESS_RULE *copy = copy_rule(original);
    CHECK(attempt == 9);
    CHECK(copy != NULL && live == 18 && copy->prepared_process != original->prepared_process);
    CHECK(copy->prepared_ports != original->prepared_ports);
    CHECK(copy->prepared_domains != original->prepared_domains);
    CHECK(copy->prepared_ipv4 != original->prepared_ipv4 && copy->prepared_ipv6 != original->prepared_ipv6);
    free_rules(original);
    CHECK(live == 9 && pb_match_process_prepared(copy->prepared_process, "chrome.exe"));
    CHECK(pb_match_port_prepared(copy->prepared_ports, 443) && !pb_match_port_prepared(copy->prepared_ports, 80));
    CHECK(!pb_match_domain_prepared(copy->prepared_domains, NULL));
    CHECK(pb_match_domain_prepared(copy->prepared_domains, "www.example.com"));
    UINT8 ip6[16] = {0};
    CHECK(pb_match_ipv6_prepared(copy->prepared_ipv6, ip6));
    CHECK(pb_match_ipv4_prepared(copy->prepared_ipv4, htonl(0xc0a80101)));
    free_rules(copy);
    CHECK(live == 0);
    puts("PASS: 11 preparation and 9 clone allocation failures; independent filters, zero leaks; clone uses 9 allocations");
    return 0;
}
