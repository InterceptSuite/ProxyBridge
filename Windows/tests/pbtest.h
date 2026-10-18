// pbtest.h - minimal check macros shared by the Windows test programs (no framework needed).
//
// Every test program is a stand-alone console exe: it prints one line per failed check, a summary line, and
// returns 0 when every check passed (1 otherwise). tests\run_tests.ps1 builds and runs all of them.
#ifndef PB_TEST_H
#define PB_TEST_H

#include <windows.h>
#include <stdio.h>

static int g_checks = 0, g_fails = 0;

// Output is unbuffered (set before main runs), so a crash can never swallow the lines printed so far.
static void pb_unbuffer(void) { setvbuf(stdout, NULL, _IONBF, 0); }
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) static void (*pb_unbuffer_init)(void) = pb_unbuffer;

#define CHECK(c) do { g_checks++; if (!(c)) { g_fails++; printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

// Prints the summary line and returns the process exit code.
static int pbtest_done(const char* name)
{
    if (g_fails) printf("%s: FAILED (%d of %d checks failed)\n", name, g_fails, g_checks);
    else         printf("%s: OK (%d checks)\n", name, g_checks);
    return g_fails ? 1 : 0;
}

// Guard-page buffer for parser tests: the copy of `data` ends exactly where unreadable memory begins, so reading
// even one byte past the end crashes the test (a crash is reported as a failure by run_tests.ps1).
// Free with pb_guard_release(base).
static BYTE* pb_guarded(const void* data, size_t len, void** base)
{
    SYSTEM_INFO si; GetSystemInfo(&si); size_t pg = si.dwPageSize;
    size_t body = ((len ? len : 1) + pg - 1) / pg * pg;
    BYTE* mem = (BYTE*)VirtualAlloc(NULL, body + pg, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD old; VirtualProtect(mem + body, pg, PAGE_NOACCESS, &old);
    BYTE* p = mem + body - len;
    if (len) memcpy(p, data, len);
    *base = mem; return p;
}
static void pb_guard_release(void* base) { VirtualFree(base, 0, MEM_RELEASE); }

#endif
