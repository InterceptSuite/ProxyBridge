// test_hosts.c - the Target Hosts list helpers of the GUI (gui\profile\profile.c):
//   PB_ListNormalize / PB_ListFormat   line breaks are display-only, cleaned before saving
//   PB_HostsSplit / PB_HostsMerge      IPs and domain names are one list in the GUI, two keys in the profile file
// Includes random-input checks with canary words to catch buffer overruns.
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>
#include "../gui/profile/profile.h"
#include "pbtest.h"

static void norm(const wchar_t* in, const wchar_t* want)
{
    wchar_t buf[1024]; wcscpy_s(buf, ARRAYSIZE(buf), in);
    PB_ListNormalize(buf);
    if (wcscmp(buf, want)) { g_fails++; wprintf(L"  FAIL normalize [%ls] -> [%ls], wanted [%ls]\n", in, buf, want); }
    g_checks++;
}

static void split(const wchar_t* in, const wchar_t* wantIps, const wchar_t* wantDoms)
{
    size_t n = wcslen(in) + 2;
    wchar_t* a = (wchar_t*)malloc(n * sizeof(wchar_t)); wchar_t* d = (wchar_t*)malloc(n * sizeof(wchar_t));
    PB_HostsSplit(in, a, n, d, n);
    if (wcscmp(a, wantIps) || wcscmp(d, wantDoms))
    { g_fails++; wprintf(L"  FAIL split [%ls] -> ips[%ls] doms[%ls], wanted [%ls] [%ls]\n", in, a, d, wantIps, wantDoms); }
    g_checks++;
    free(a); free(d);
}

static void merge(const wchar_t* ips, const wchar_t* doms, const wchar_t* want)
{
    wchar_t out[512]; PB_HostsMerge(ips, doms, out, ARRAYSIZE(out));
    if (wcscmp(out, want)) { g_fails++; wprintf(L"  FAIL merge [%ls]+[%ls] -> [%ls], wanted [%ls]\n", ips ? ips : L"(null)", doms ? doms : L"(null)", out, want); }
    g_checks++;
}

int main(void)
{
    /* ---- normalize: line breaks and blanks are formatting only ---- */
    norm(L"google.com;\r\n*.google.com;\r\n*.gstatic.com;\r\ngithub.com;\r\n*.github.com;\r\n",
         L"google.com;*.google.com;*.gstatic.com;github.com;*.github.com");
    norm(L"  a ; b ,c  ", L"a;b;c");
    norm(L"a\r\nb", L"ab");                 /* a line break alone is NOT a separator */
    norm(L";;;", L"");  norm(L"", L"");  norm(L"   \r\n\t ", L"");
    norm(L"a;;b;;;c;", L"a;b;c");
    norm(L"*", L"*");
    norm(L"a b ; c", L"a b;c");             /* blanks inside an entry are kept */
    norm(L"\x01x\x02;y", L"x;y");           /* control characters are dropped */
    { wchar_t o[64]; PB_ListFormat(L"a;b;c", o, ARRAYSIZE(o)); CHECK(wcscmp(o, L"a;\r\nb;\r\nc") == 0); }
    { wchar_t o[64]; PB_ListFormat(L"", o, ARRAYSIZE(o)); CHECK(o[0] == 0); }
    { /* normalize(format(x)) == x */
        wchar_t f[128], x[64] = L"a.com;b.com;*.c.org"; PB_ListFormat(x, f, ARRAYSIZE(f)); PB_ListNormalize(f); CHECK(wcscmp(f, x) == 0); }

    /* ---- split: entry type decides the key ---- */
    split(L"10.0.0.0/8;github.com;*.google.com;2001:db8::/32;192.168.*.*", L"10.0.0.0/8;2001:db8::/32;192.168.*.*", L"github.com;*.google.com");
    split(L"github.com", L"*", L"github.com");
    split(L"10.0.0.0/8", L"10.0.0.0/8", L"*");
    split(L"*", L"*", L"*");  split(L"", L"*", L"*");
    split(L"a.com;*;10.0.0.1", L"*", L"*");                       /* a "*" anywhere = any host */
    split(L"1.2.3.4-1.2.3.9;10.1-5.*.7;fe80::1-fe80::ff;::1;example-site.org;my-1.2.com;abc.def;123.com",
          L"1.2.3.4-1.2.3.9;10.1-5.*.7;fe80::1-fe80::ff;::1", L"example-site.org;my-1.2.com;abc.def;123.com");
    split(L"  10.0.0.1 ; github.com  ,x.org ", L"10.0.0.1", L"github.com;x.org");

    /* ---- merge: a side that is empty or "*" adds nothing ---- */
    merge(L"10.0.0.0/8", L"github.com", L"10.0.0.0/8;github.com");
    merge(L"*", L"github.com", L"github.com");  merge(L"10.0.0.1", L"*", L"10.0.0.1");
    merge(L"*", L"*", L"*");  merge(L"", L"", L"*");  merge(NULL, NULL, L"*");
    { wchar_t m[256], a[256], d[256];                           /* split(merge(i, d)) gives back i and d */
      PB_HostsMerge(L"10.0.0.0/8;192.168.*.*", L"github.com;*.x.org", m, ARRAYSIZE(m));
      PB_HostsSplit(m, a, ARRAYSIZE(a), d, ARRAYSIZE(d));
      CHECK(wcscmp(a, L"10.0.0.0/8;192.168.*.*") == 0 && wcscmp(d, L"github.com;*.x.org") == 0); }
    { wchar_t out[16];                                          /* too long for the buffer: whole entries only, terminated */
      PB_HostsMerge(L"aaaa.com;bbbb.com", L"cccc.com;dddd.com", out, ARRAYSIZE(out));
      size_t m = wcslen(out);
      CHECK(m < 16 && (m == 0 || out[m - 1] != L';'));
      CHECK(wcscmp(out, L"aaaa.com;bbbb.com") == 0 || wcscmp(out, L"aaaa.com") == 0 || wcscmp(out, L"*") == 0); }

    /* ---- random input: never grows, never overruns, always terminated, well formed ---- */
    srand(777);
    const wchar_t alpha[] = L"ab01.*-:/;, \r\n\tfZ\x01";
    for (int it = 0; it < 100000; it++)
    {
        int n = rand() % 70; wchar_t* in = (wchar_t*)malloc(((size_t)n + 1 + 8) * sizeof(wchar_t));
        for (int i = 0; i < n; i++) in[i] = alpha[rand() % (int)(ARRAYSIZE(alpha) - 1)];
        in[n] = 0; for (int i = n + 1; i < n + 9; i++) in[i] = 0x7777;
        PB_ListNormalize(in);
        size_t m = wcslen(in);
        if (m > (size_t)n) { g_fails++; puts("  FAIL normalize grew the text"); }
        for (int i = n + 1; i < n + 9; i++) if (in[i] != 0x7777) { g_fails++; puts("  FAIL normalize wrote past the end"); break; }
        for (size_t i = 0; i < m; i++) if (in[i] < L' ' || in[i] == L',') { g_fails++; puts("  FAIL normalize left a control char or comma"); break; }
        if (m && (in[0] == L';' || in[m - 1] == L';' || in[0] == L' ' || in[m - 1] == L' ')) { g_fails++; puts("  FAIL normalize left an edge separator/blank"); }

        size_t k = m + 2; wchar_t* a = (wchar_t*)malloc((k + 4) * sizeof(wchar_t)); wchar_t* d = (wchar_t*)malloc((k + 4) * sizeof(wchar_t));
        for (size_t i = k; i < k + 4; i++) { a[i] = 0x7777; d[i] = 0x7777; }
        PB_HostsSplit(in, a, k, d, k);                           /* exact-size buffers */
        for (size_t i = k; i < k + 4; i++) if (a[i] != 0x7777 || d[i] != 0x7777) { g_fails++; puts("  FAIL split overran its buffers"); break; }
        if (!a[0] || !d[0]) { g_fails++; puts("  FAIL split produced an empty side (must be *)"); }
        free(in); free(a); free(d);
    }
    g_checks += 100000;

    return pbtest_done("test_hosts");
}
