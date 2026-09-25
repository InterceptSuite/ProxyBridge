#include "pb_internal.h"
#include "port-filter-reference.inc"
#include "ipv4-filter-reference.inc"
static int attempt, fail_at = -1, live;
static void *tracked_malloc(size_t bytes) {
    if (attempt++ == fail_at) return NULL;
    void *p = malloc(bytes); if (p) ++live; return p;
}
static void tracked_free(void *p) { if (p) --live; free(p); }
static char *tracked_strdup(const char *s) {
    size_t n = strlen(s) + 1; char *p = tracked_malloc(n); if (p) memcpy(p, s, n); return p;
}
#define malloc tracked_malloc
#define free tracked_free
#define _strdup tracked_strdup
#include "../src/rules/pb_ipv4_filter.inc"
#undef malloc
#undef free
#undef _strdup
static unsigned comparisons;
static BOOL compare(const char *list)
{
    PB_IPV4_FILTER *filter = pb_prepare_ipv4_list(list);
    if (!filter) return FALSE;
    int before = attempt;
    UINT32 random = 12345;
    for (unsigned i = 0; i < 4096; ++i) {
        random = random * 1664525u + 1013904223u;
        UINT32 ip = i < 1024 ? htonl(0xc0a80000u + i) : random;
        if (match_ip_list(list, ip) != pb_match_ipv4_prepared(filter, ip)) {
            printf("FAIL list=%s ip=%08x\n", list ? list : "NULL", ip); return FALSE;
        }
        ++comparisons;
    }
    for (size_t i = 0; i < filter->count; ++i) {
        const PB_IPV4_TERM *term = &filter->terms[i];
        UINT32 addresses[] = {term->range ? htonl(term->first) : term->first,
            term->range ? htonl(term->last) : term->first | ~term->last};
        for (int a = 0; a < 2; ++a) for (int delta = -1; delta <= 1; ++delta) {
            UINT32 ip = htonl(ntohl(addresses[a]) + (UINT32)delta);
            if (match_ip_list(list, ip) != pb_match_ipv4_prepared(filter, ip)) return FALSE;
            ++comparisons;
        }
    }
    tracked_free(filter);
    return live == 0 && attempt == before;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d live=%d\n", __LINE__, live); return 1; } } while (0)
int main(void)
{
    const char *lists[] = {NULL, "", "*", " *", "* ", ";; ", "0.0.0.0", "255.255.255.255", "192.168.*.*", "*.168.*.1", "192.168.1.1", "192.168.1.1/24", "192.168.1.1.extra", "192.168.1.1,10.0.0.1", "192.168.1.1;10.0.0.1", "192.168.0.1-192.168.3.255", "255.0.0.1-255.255.255.255", "192.168.3.255-192.168.0.1", "999.1.1.1", "-1.1.1.1", "a.b.c.d", "...", "1..2.3", "1.2.3", "1.2.3.4 ", "1.* .3.4", "0.0.0.0-999.0.0.0", "::1", "0.0.0.0-255.255.255.255"};
    for (unsigned i = 0; i < sizeof(lists)/sizeof(lists[0]); ++i) CHECK(compare(lists[i]));
    for (unsigned mask = 0; mask < 16; ++mask) {
        char pattern[80]; sprintf_s(pattern, sizeof(pattern), "%s.%s.%s.%s", mask&1 ? "*" : "192", mask&2 ? "*" : "168", mask&4 ? "*" : "1", mask&8 ? "*" : "2");
        CHECK(compare(pattern));
    }
    char *maximum = malloc(MAX_LIST_SIZE); CHECK(maximum != NULL);
    memset(maximum, '1', MAX_LIST_SIZE); maximum[MAX_LIST_SIZE-1] = 0;
    CHECK(compare(maximum));
    maximum[MAX_LIST_SIZE-1] = '1'; CHECK(pb_prepare_ipv4_list(maximum) == NULL); free(maximum);
    for (int f = 0; f < 2; ++f) { attempt = 0; fail_at = f; CHECK(pb_prepare_ipv4_list("*") == NULL && live == 0); }
    fail_at = -1;
    printf("PASS comparisons=%u: grammar, wildcard masks, ranges, boundaries, OOM and allocation-free lookup\n", comparisons);
    char list[2048] = {0};
    for (unsigned i = 0; i < 100; ++i) { char token[24]; sprintf_s(token, sizeof(token), "192.168.1.%u;", i); strcat_s(list, sizeof(list), token); }
    PB_IPV4_FILTER *filter = pb_prepare_ipv4_list(list); CHECK(filter != NULL);
    LARGE_INTEGER frequency, start, middle, end; QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    volatile unsigned matches = 0;
    for (unsigned i = 0; i < 20000; ++i) matches += match_ip_list(list, htonl(0xc0a80163));
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) matches += pb_match_ipv4_prepared(filter, htonl(0xc0a80163));
    QueryPerformanceCounter(&end); CHECK(matches == 40000);
    printf("20000-100-ipv4-reference-ms=%.3f prepared-ms=%.3f\n", (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart);
    tracked_free(filter); CHECK(live == 0);
    return 0;
}
