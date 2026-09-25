#include "pb_internal.h"
#include "port-filter-reference.inc"
static unsigned allocations;
static BOOL fail_allocation;
static void *prepare_malloc(size_t size)
{
    ++allocations;
    return fail_allocation ? NULL : malloc(size);
}
#define malloc prepare_malloc
#include "../src/rules/pb_port_filter.inc"
#undef malloc
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    const char *lists[] = {NULL, "", "*", "80,443;8000-9000", "443;80;80;81-443", "65535", "0", "65536", "-1", "-1-3", "8-2", "abc", "80junk", "* ", " *", "\t , ;", ",;;", "65534-99999", "-4--2", " 80 - 90 ", "1-2-3", "\n80", "+80", "1;*;65535", "999999999999999999999999", "0-65535", "70-90;80-100;101;120-130"};
    unsigned comparisons = 0;
    for (unsigned i = 0; i < sizeof(lists) / sizeof(lists[0]); ++i) {
        PB_PORT_FILTER *prepared = pb_prepare_port_list(lists[i]);
        CHECK(prepared != NULL);
        unsigned before = allocations;
        for (unsigned port = 0; port <= 65535; ++port) {
            BOOL old = match_port_list(lists[i], (UINT16)port);
            BOOL now = pb_match_port_prepared(prepared, (UINT16)port);
            if (old != now) { printf("mismatch list=%s port=%u\n", lists[i], port); return 1; }
            ++comparisons;
        }
        CHECK(allocations == before);
        for (size_t j = 1; j < prepared->count; ++j)
            CHECK((unsigned)prepared->ranges[j-1].last + 1 < prepared->ranges[j].first);
        free(prepared);
    }
    fail_allocation = TRUE;
    CHECK(pb_prepare_port_list("443") == NULL);
    fail_allocation = FALSE;
    char *maximum = malloc(MAX_LIST_SIZE);
    CHECK(maximum != NULL);
    memset(maximum, ';', MAX_LIST_SIZE); maximum[MAX_LIST_SIZE-1] = 0;
    PB_PORT_FILTER *empty = pb_prepare_port_list(maximum);
    CHECK(empty != NULL && empty->count == 0);
    free(empty);
    maximum[MAX_LIST_SIZE-1] = ';';
    CHECK(pb_prepare_port_list(maximum) == NULL);
    free(maximum);
    printf("PASS: comparisons=%u; normalized intervals, allocation-free lookup, OOM and length bounds\n", comparisons);
    char benchmark[1024] = {0};
    for (unsigned i = 0; i < 100; ++i) {
        char token[12]; sprintf_s(token, sizeof(token), "%u;", 1000 + 2*i);
        strcat_s(benchmark, sizeof(benchmark), token);
    }
    PB_PORT_FILTER *prepared = pb_prepare_port_list(benchmark);
    CHECK(prepared != NULL);
    LARGE_INTEGER frequency, start, middle, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    volatile unsigned matches = 0;
    for (unsigned i = 0; i < 20000; ++i) matches += match_port_list(benchmark, 1198);
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) matches += pb_match_port_prepared(prepared, 1198);
    QueryPerformanceCounter(&end);
    CHECK(matches == 40000);
    printf("20000-100-port-reference-ms=%.3f prepared-ms=%.3f\n", (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart);
    free(prepared);
    return 0;
}
