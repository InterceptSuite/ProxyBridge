#include "pb_internal.h"
#include <ctype.h>
#include "../src/rules/pb_wildcard.inc"
#include "domain-filter-reference.inc"
static unsigned allocations, comparisons;
static BOOL fail_allocation;
static void *prepare_malloc(size_t size)
{
    ++allocations;
    return fail_allocation ? NULL : malloc(size);
}
#define malloc prepare_malloc
#include "../src/rules/pb_domain_filter.inc"
#undef malloc
static BOOL compare(const char *list)
{
    const char *domains[] = {NULL, "", "a", "A", "a.a", "b.a", "example.com", "www.example.com", "notexample.com", "\"a\"", "a?"};
    PB_DOMAIN_FILTER *filter = pb_prepare_domain_list(list);
    if (filter == NULL) return FALSE;
    unsigned before = allocations;
    for (unsigned i = 0; i < sizeof(domains)/sizeof(domains[0]); ++i) {
        BOOL old = match_domain_list(list, domains[i]);
        BOOL now = pb_match_domain_prepared(filter, domains[i]);
        ++comparisons;
        if (old != now) { printf("FAIL list=[%s] domain=[%s]\n", list ? list : "NULL", domains[i] ? domains[i] : "NULL"); free(filter); return FALSE; }
    }
    free(filter);
    return before == allocations;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    const char *targeted[] = {NULL, "", "*", " * ", "*;a", "*.example.com", "*.a", "example.com;*.example.com", "\"a\"", "a?", " \t ,; ", "\na", "a; A", "*example*"};
    for (unsigned i = 0; i < sizeof(targeted)/sizeof(targeted[0]); ++i) CHECK(compare(targeted[i]));
    const char alphabet[] = "a.*;, A";
    for (unsigned length = 0, count = 1; length <= 5; ++length, count *= 7) {
        for (unsigned n = 0; n < count; ++n) {
            char list[6]; unsigned value = n;
            for (unsigned p = 0; p < length; ++p) { list[p] = alphabet[value % 7]; value /= 7; }
            list[length] = '\0'; CHECK(compare(list));
        }
    }
    char *maximum = malloc(MAX_LIST_SIZE);
    CHECK(maximum != NULL);
    memset(maximum, 'a', MAX_LIST_SIZE); maximum[MAX_LIST_SIZE-1] = 0;
    CHECK(compare(maximum));
    for (unsigned i = 0; i < MAX_LIST_SIZE-1; ++i) maximum[i] = i & 1 ? ';' : 'a';
    CHECK(compare(maximum));
    maximum[MAX_LIST_SIZE-1] = 'a';
    CHECK(pb_prepare_domain_list(maximum) == NULL);
    free(maximum);
    fail_allocation = TRUE;
    CHECK(pb_prepare_domain_list("a") == NULL);
    fail_allocation = FALSE;
    printf("PASS comparisons=%u: parity, unknown domains, apex, whitespace, bounds, OOM and allocation-free matching\n", comparisons);
    char benchmark[2048] = {0};
    for (unsigned i = 0; i < 100; ++i) {
        char token[24]; sprintf_s(token, sizeof(token), "other%u.example; ", i);
        strcat_s(benchmark, sizeof(benchmark), token);
    }
    strcat_s(benchmark, sizeof(benchmark), "example.com");
    PB_DOMAIN_FILTER *filter = pb_prepare_domain_list(benchmark);
    CHECK(filter != NULL);
    LARGE_INTEGER frequency, start, middle, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    volatile unsigned matches = 0;
    for (unsigned i = 0; i < 20000; ++i) matches += match_domain_list(benchmark, "example.com");
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) matches += pb_match_domain_prepared(filter, "example.com");
    QueryPerformanceCounter(&end);
    CHECK(matches == 40000);
    printf("20000-long-domain-list-reference-ms=%.3f prepared-ms=%.3f\n", (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart);
    free(filter);
    return 0;
}
