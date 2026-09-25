#include <windows.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "../src/rules/pb_wildcard.inc"

// Frozen reference to the previous recursive implementation, test-only.
static BOOL reference_match(const char *pattern, const char *text)
{
    while (*text) {
        if (*pattern == '*') {
            while (*pattern == '*') ++pattern;
            if (!*pattern) return TRUE;
            while (*text) {
                if (reference_match(pattern, text)) return TRUE;
                ++text;
            }
            return FALSE;
        }
        if (tolower((unsigned char)*pattern) != tolower((unsigned char)*text)) return FALSE;
        ++pattern; ++text;
    }
    while (*pattern == '*') ++pattern;
    return *pattern == 0;
}

static unsigned power(unsigned base, unsigned exponent)
{
    unsigned result = 1;
    while (exponent--) result *= base;
    return result;
}
static void word(char *out, unsigned value, unsigned length, const char *alphabet, unsigned radix)
{
    for (unsigned i = 0; i < length; ++i) { out[i] = alphabet[value % radix]; value /= radix; }
    out[length] = 0;
}
int main(void)
{
    unsigned comparisons = 0;
    char pattern[32], value[32];
    for (unsigned pl = 0; pl <= 6; ++pl)
        for (unsigned p = 0; p < power(4, pl); ++p) {
            word(pattern, p, pl, "abA*", 4);
            for (unsigned tl = 0; tl <= 5; ++tl)
                for (unsigned t = 0; t < power(3, tl); ++t) {
                    word(value, t, tl, "abA", 3);
                    if (wildcard_match(pattern, value) != reference_match(pattern, value)) {
                        printf("FAIL pattern='%s' text='%s'\n", pattern, value); return 1;
                    }
                    ++comparisons;
                }
        }
    const char *patterns[] = {"C:\\*\\*.EXE", "*.example.com", "*a*b*c*", "?", "**", "\xC3\xA9*"};
    const char *texts[] = {"c:\\apps\\Tool.exe", "a.example.com", "aaabbbccc", "x", "", "\xC3\xA9.exe"};
    for (unsigned i = 0; i < ARRAYSIZE(patterns); ++i)
        if (wildcard_match(patterns[i], texts[i]) != reference_match(patterns[i], texts[i])) return 1;
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    volatile unsigned matched = 0;
    const char *adversarial = "*a*a*a*a*a*a*a*a*b";
    const char *text = "aaaaaaaaaaaaaaaaaaaa";
    QueryPerformanceCounter(&start);
    for (unsigned i = 0; i < 100; ++i) matched += reference_match(adversarial, text);
    QueryPerformanceCounter(&end);
    double reference_ms = 1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart;
    QueryPerformanceCounter(&start);
    for (unsigned i = 0; i < 100; ++i) matched += wildcard_match(adversarial, text);
    QueryPerformanceCounter(&end);
    double current_ms = 1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart;
    printf("PASS equivalence=%u targeted=6 adversarial-result=%u\n", comparisons, matched);
    printf("adversarial-100-reference-ms=%.6f current-ms=%.6f\n", reference_ms, current_ms);
    return matched ? 1 : 0;
}
