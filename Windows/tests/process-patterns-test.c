#include "pb_internal.h"
#include <ctype.h>
#include "../src/rules/pb_wildcard.inc"
static unsigned allocations;
static BOOL fail_allocation;
static void *prepare_alloc(size_t bytes)
{
    ++allocations;
    return fail_allocation ? NULL : malloc(bytes);
}
#define malloc prepare_alloc
#include "../src/rules/pb_process_patterns.inc"
#undef malloc
#include "process-match-reference.inc"

static const char *processes[] = {"", "a", "A", "b", "a.exe", "C:\\a", "c:/a", "C:\\some app.exe", "chrome.exe"};
static unsigned comparisons;
static BOOL compare(const char *list)
{
    PB_PROCESS_PATTERNS *prepared = pb_prepare_process_list(list);
    if (prepared == NULL) return FALSE;
    unsigned before = allocations;
    for (unsigned i = 0; i < sizeof(processes) / sizeof(processes[0]); ++i) {
        BOOL expected = reference_process_list(list, processes[i]);
        BOOL actual = pb_match_process_prepared(prepared, processes[i]);
        ++comparisons;
        if (expected != actual) {
            printf("FAIL list=[%s] process=[%s] expected=%d actual=%d\n", list ? list : "NULL", processes[i], expected, actual);
            free(prepared); return FALSE;
        }
    }
    free(prepared);
    return allocations == before;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    const char *targeted[] = {NULL, "", "*", "ANY", "\t ; ,", "a; b", "a,,b;;", "\"C:\\some app.exe\";*.exe", "\"a\"ignored", "\"", "\"\"", "c:/a", "a?", "*a*;b"};
    for (unsigned i = 0; i < sizeof(targeted) / sizeof(targeted[0]); ++i) CHECK(compare(targeted[i]));
    const char alphabet[] = "aA*; ,\"";
    for (unsigned length = 0, count = 1; length <= 5; ++length, count *= 7) {
        for (unsigned n = 0; n < count; ++n) {
            char list[6]; unsigned value = n;
            for (unsigned p = 0; p < length; ++p) { list[p] = alphabet[value % 7]; value /= 7; }
            list[length] = 0;
            CHECK(compare(list));
        }
    }
    char maximum[MAX_PROCESS_NAME];
    memset(maximum, 'a', sizeof(maximum)); maximum[sizeof(maximum) - 1] = 0;
    CHECK(compare(maximum));
    for (unsigned i = 0; i < sizeof(maximum) - 1; ++i) maximum[i] = i & 1 ? ';' : 'a';
    CHECK(compare(maximum));
    maximum[sizeof(maximum) - 1] = 'a';
    CHECK(pb_prepare_process_list(maximum) == NULL);
    fail_allocation = TRUE;
    CHECK(pb_prepare_process_list("a.exe") == NULL);
    fail_allocation = FALSE;
    puts("PASS: parity, maximum length/dense lists, invalid length, allocation failure and allocation-free matching");
    printf("comparisons=%u\n", comparisons);

    char benchmark[MAX_PROCESS_NAME] = {0};
    for (unsigned i = 0; i < 35; ++i) {
        char token[24]; sprintf_s(token, sizeof(token), "other%u.exe; ", i);
        strcat_s(benchmark, sizeof(benchmark), token);
    }
    strcat_s(benchmark, sizeof(benchmark), "chrome.exe");
    PB_PROCESS_PATTERNS *prepared = pb_prepare_process_list(benchmark);
    CHECK(prepared != NULL);
    LARGE_INTEGER frequency, begin, middle, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&begin);
    volatile unsigned matches = 0;
    for (unsigned i = 0; i < 20000; ++i) matches += reference_process_list(benchmark, "chrome.exe");
    QueryPerformanceCounter(&middle);
    for (unsigned i = 0; i < 20000; ++i) matches += pb_match_process_prepared(prepared, "chrome.exe");
    QueryPerformanceCounter(&end);
    CHECK(matches == 40000);
    printf("20000-long-list-reference-ms=%.3f prepared-ms=%.3f prepared-requested-bytes=%zu\n",
        (middle.QuadPart - begin.QuadPart) * 1000.0 / frequency.QuadPart,
        (end.QuadPart - middle.QuadPart) * 1000.0 / frequency.QuadPart,
        sizeof(*prepared) + prepared->bytes);
    free(prepared);
    return 0;
}
