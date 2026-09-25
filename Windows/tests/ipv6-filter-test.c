#include "pb_internal.h"
#include "port-filter-reference.inc"
#include "ipv6-filter-reference.inc"
static int attempt, fail_at = -1, live;
static void *tracked_malloc(size_t bytes)
{
    if (attempt++ == fail_at) return NULL;
    void *p = malloc(bytes); if (p != NULL) ++live; return p;
}
static void tracked_free(void *p) { if (p != NULL) --live; free(p); }
static char *tracked_strdup(const char *s)
{
    size_t size = strlen(s) + 1;
    char *p = tracked_malloc(size); if (p != NULL) memcpy(p, s, size); return p;
}
#define malloc tracked_malloc
#define free tracked_free
#define _strdup tracked_strdup
#include "../src/rules/pb_ipv6_filter.inc"
#undef malloc
#undef free
#undef _strdup
static unsigned comparisons;
static UINT32 random_state = 12345;
static UINT32 next_random(void) { random_state = random_state * 1664525u + 1013904223u; return random_state; }
static BOOL compare(const char *list)
{
    PB_IPV6_FILTER *filter = pb_prepare_ipv6_list(list);
    if (filter == NULL) return FALSE;
    int before = attempt;
    for (unsigned sample = 0; sample < 256; ++sample) {
        UINT8 ip[16];
        for (int byte = 0; byte < 16; ++byte) ip[byte] = (UINT8)(next_random() >> 24);
        if (sample < 128) { memset(ip, 0, 16); ip[15] = (UINT8)sample; }
        BOOL old = match_ip_list_v6(list, ip), now = pb_match_ipv6_prepared(filter, ip);
        ++comparisons;
        if (old != now) { puts("FAIL random parity"); tracked_free(filter); return FALSE; }
    }
    for (size_t i = 0; i < filter->count; ++i) {
        if (!match_ip_list_v6(list, filter->ranges[i].first) || !match_ip_list_v6(list, filter->ranges[i].last)) return FALSE;
        UINT8 neighbor[16];
        for (int side = 0; side < 2; ++side) {
            memcpy(neighbor, side ? filter->ranges[i].last : filter->ranges[i].first, 16);
            for (int b = 15; b >= 0; --b) {
                if (side) { if (++neighbor[b] != 0) break; }
                else { if (neighbor[b]-- != 0) break; }
            }
            ++comparisons;
            if (match_ip_list_v6(list, neighbor) != pb_match_ipv6_prepared(filter, neighbor)) return FALSE;
        }
    }
    tracked_free(filter);
    return attempt == before && live == 0;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d live=%d\n", __LINE__, live); return 1; } } while (0)
int main(void)
{
    const char *lists[] = {NULL, "", "*", " *", "* ", " ;\t;", "::", "::1", "::ffff:192.0.2.1", "192.168.*.*", "::1,::2", "::1;::2", "::1-::10", "::10-::1", "bad::address", "::/0", "::/128", "::/-1", "::/129", "::/junk", "2001:db8::/32", "2001:db8::1-2001:db8::ff", "::1-::9;::4-::20;::5", "::1;*"};
    for (unsigned i = 0; i < sizeof(lists)/sizeof(lists[0]); ++i) CHECK(compare(lists[i]));
    for (unsigned prefix = 0; prefix <= 128; ++prefix) {
        char pattern[80]; sprintf_s(pattern, sizeof(pattern), "2001:db8:abcd:1234:5678:90ab:cdef:1234/%u", prefix);
        CHECK(compare(pattern));
    }
    for (int failure = 0; failure < 2; ++failure) {
        attempt = 0; fail_at = failure; CHECK(pb_prepare_ipv6_list("::/0") == NULL && live == 0);
    }
    fail_at = -1;
    char *maximum = malloc(MAX_LIST_SIZE);
    CHECK(maximum != NULL);
    memset(maximum, ';', MAX_LIST_SIZE); maximum[MAX_LIST_SIZE-1] = 0;
    CHECK(compare(maximum)); maximum[MAX_LIST_SIZE-1] = ';';
    CHECK(pb_prepare_ipv6_list(maximum) == NULL); free(maximum);
    printf("PASS comparisons=%u: IPv6 prefixes/ranges/edges, grammar, allocation-free lookup, OOM and bounds\n", comparisons);
    char benchmark[2048] = {0};
    for (unsigned i = 1; i <= 100; ++i) {
        char token[20]; sprintf_s(token, sizeof(token), "2001:db8::%x;", i);
        strcat_s(benchmark, sizeof(benchmark), token);
    }
    UINT8 ip[16]; CHECK(inet_pton(AF_INET6, "2001:db8::64", ip) == 1);
    PB_IPV6_FILTER *filter = pb_prepare_ipv6_list(benchmark); CHECK(filter != NULL);
    LARGE_INTEGER frequency, start, middle, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    volatile unsigned matches = 0;
    for (unsigned i = 0; i < 20000; ++i) matches += match_ip_list_v6(benchmark, ip);
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) matches += pb_match_ipv6_prepared(filter, ip);
    QueryPerformanceCounter(&end); CHECK(matches == 40000);
    printf("20000-100-ipv6-reference-ms=%.3f prepared-ms=%.3f\n", (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart);
    tracked_free(filter); CHECK(live == 0);
    return 0;
}
