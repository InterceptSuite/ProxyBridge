// test_gui_misc.c - helpers that live inside the GUI (gui\main.c and its ui\ headers, included as source):
//   - the updater's version parsing/comparison
//   - the EN/ZH string table: complete, aligned with its ids, and printf-style placeholders identical in both languages
//   - connection-log filters (include / exclude, wildcards) and the bounded log store
//   - UTF-8 <-> UTF-16 conversion helpers
// No window of the app is created except one plain EDIT control used by the log store.
#define wWinMain pb_real_wWinMain
#include "../gui/main.c"
#undef wWinMain
#include "pbtest.h"

static void ver(const wchar_t* s, int a, int b, int c)
{
    int v[3]; UpdParseVer(s, v);
    if (v[0] != a || v[1] != b || v[2] != c) { g_fails++; wprintf(L"  FAIL UpdParseVer(%ls) = %d.%d.%d, wanted %d.%d.%d\n", s, v[0], v[1], v[2], a, b, c); }
    g_checks++;
}
static int cmp(const wchar_t* x, const wchar_t* y) { int a[3], b[3]; UpdParseVer(x, a); UpdParseVer(y, b); return UpdVerCmp(a, b); }

// Collects the conversion characters of a printf-style format ("%d of %d" -> "dd"), skipping "%%".
static void conv(const wchar_t* f, char* out, size_t cap)
{
    size_t n = 0;
    for (; *f; f++)
    {
        if (*f != L'%') continue;
        f++;
        if (*f == L'%') continue;
        while (*f && wcschr(L"-+ #0123456789.lhIw", *f)) f++;
        if (*f && n + 1 < cap) out[n++] = (char)*f;
        if (!*f) break;
    }
    out[n] = 0;
}

static PBFilter F(const wchar_t* mode, const wchar_t* proc, const wchar_t* ip, const wchar_t* port, const wchar_t* proto, const wchar_t* action)
{
    PBFilter f; ZeroMemory(&f, sizeof f);
    lstrcpynW(f.mode, mode, 16); lstrcpynW(f.proc, proc, 256); lstrcpynW(f.ip, ip, 64); lstrcpynW(f.port, port, 16); lstrcpynW(f.proto, proto, 8); lstrcpynW(f.action, action, 16);
    return f;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hInst; (void)hPrev; (void)cmd; (void)show;
    setvbuf(stdout, NULL, _IONBF, 0);

    /* ================= updater: version parsing and comparison ================= */
    ver(L"4.2.0", 4, 2, 0);  ver(L"v4.2.0", 4, 2, 0);  ver(L"4.2.0-Beta", 4, 2, 0);  ver(L"4.0.13-Beta", 4, 0, 13);
    ver(L"4.10.2", 4, 10, 2); ver(L"4.2", 4, 2, 0);    ver(L"7", 7, 0, 0);          ver(L"", 0, 0, 0);   ver(L"abc", 0, 0, 0);  ver(L"1.2.3.4", 1, 2, 3);
    CHECK(cmp(L"4.10.0", L"4.9.0") > 0 && cmp(L"4.2.0", L"4.2.0") == 0 && cmp(L"4.1.9", L"4.2.0") < 0 && cmp(L"5.0.0", L"4.99.99") > 0);
    CHECK(cmp(L"v4.2.1", L"4.2.0-Beta") > 0 && cmp(L"4.2.0-Beta", L"4.2.0") == 0);
    CHECK(cmp(PB_VER_STRW, L"0.0.1") > 0);                                                       /* the app's own version parses and is real */
    { int v[3]; UpdParseVer(PB_VER_STRW, v); CHECK(v[0] == PB_VER_MAJOR && v[1] == PB_VER_MINOR && v[2] == PB_VER_PATCH); }   /* text and numbers agree */

    /* ================= string table ================= */
    int empty = 0, same = 0, badFmt = 0;
    for (int i = 0; i < S_COUNT; i++)
    {
        const wchar_t* en = g_strings[i][0]; const wchar_t* zh = g_strings[i][1];
        if (!en || !zh || !en[0] || !zh[0]) { empty++; wprintf(L"  FAIL string id %d is missing or empty in %ls\n", i, (!en || !en[0]) ? L"English" : L"Chinese"); continue; }
        if (!wcscmp(en, zh)) same++;
        char ce[32], cz[32]; conv(en, ce, sizeof ce); conv(zh, cz, sizeof cz);
        if (strcmp(ce, cz)) { badFmt++; wprintf(L"  FAIL string id %d: placeholders differ between English (%hs) and Chinese (%hs)\n", i, ce, cz); }
    }
    CHECK(empty == 0 && badFmt == 0);
    CHECK(S_COUNT > 100 && same * 5 < S_COUNT);                                                  /* most strings are really translated */
    /* anchors: a mis-ordered id/table pair shows up here */
    CHECK(wcsstr(g_strings[S_BTN_OK][0], L"OK") && wcsstr(g_strings[S_BTN_CANCEL][0], L"Cancel") && wcsstr(g_strings[S_DLG_RULES][0], L"Rules"));
    CHECK(wcsstr(g_strings[S_M_ENABLE][0], L"Enable") && wcsstr(g_strings[S_M_LOGALL][0], L"Every") && wcsstr(g_strings[S_CHK_LOCALHOST][0], L"ocalhost"));
    CHECK(wcsstr(g_strings[S_RULES_COUNT][0], L"%d") && wcsstr(g_strings[S_RULES_SEARCH][0], L"earch") && wcsstr(g_strings[S_TITLE_PAUSED][0], L"PAUSED"));
    g_lang = 0; CHECK(T(S_BTN_OK) == g_strings[S_BTN_OK][0]);
    g_lang = 1; CHECK(T(S_BTN_OK) == g_strings[S_BTN_OK][1]);
    g_lang = 7; CHECK(T(S_BTN_OK) == g_strings[S_BTN_OK][1]);                                    /* any non-zero language = Chinese, never out of range */
    g_lang = 0;

    /* ================= connection-log filters ================= */
    CHECK(ContainsCI(L"Chrome.EXE", L"chrome") && !ContainsCI(L"firefox", L"chrome") && ContainsCI(L"abc", L""));
    CHECK(GlobMatch(L"chrome.exe", L"chrome*") && GlobMatch(L"chrome.exe", L"*.exe") && GlobMatch(L"chrome.exe", L"c*e.e*e") && !GlobMatch(L"chrome.exe", L"*.bin"));
    CHECK(GlobMatch(L"chrome.exe", L"*") && GlobMatch(L"chrome.exe", L"") && GlobMatch(L"chrome.exe", L"rome"));          /* no '*' = contains */
    CHECK(!GlobMatch(L"chrome.exe", L"hrome*") && !GlobMatch(L"chrome.exe", L"*chrom"));                                    /* anchored when the pattern has no leading/trailing star */

    PBFilter f1 = F(L"Include", L"chrome*", L"*", L"*", L"All", L"All");
    CHECK(FilterRuleMatches(&f1, L"chrome.exe", L"1.2.3.4", L"443", L"TCP", L"Proxy") && !FilterRuleMatches(&f1, L"edge.exe", L"1.2.3.4", L"443", L"TCP", L"Proxy"));
    PBFilter f2 = F(L"Exclude", L"*", L"10.*", L"*", L"UDP", L"All");
    CHECK(FilterRuleMatches(&f2, L"x.exe", L"10.1.1.1", L"53", L"UDP", L"Direct") && !FilterRuleMatches(&f2, L"x.exe", L"10.1.1.1", L"53", L"TCP", L"Direct"));

    g_fltCount = 0;                                                                                  /* no filters: everything shows */
    CHECK(PassesLogFilters(L"a.exe", L"1.1.1.1", L"80", L"TCP", L"Direct"));
    g_flt[0] = F(L"Exclude", L"noisy*", L"*", L"*", L"All", L"All"); g_fltCount = 1;                 /* exclude only: everything but noisy */
    CHECK(!PassesLogFilters(L"noisy.exe", L"1.1.1.1", L"80", L"TCP", L"Direct") && PassesLogFilters(L"quiet.exe", L"1.1.1.1", L"80", L"TCP", L"Direct"));
    g_flt[0] = F(L"Include", L"chrome*", L"*", L"*", L"All", L"All"); g_fltCount = 1;                /* include only: only chrome */
    CHECK(PassesLogFilters(L"chrome.exe", L"1.1.1.1", L"80", L"TCP", L"Direct") && !PassesLogFilters(L"edge.exe", L"1.1.1.1", L"80", L"TCP", L"Direct"));
    g_flt[1] = F(L"Exclude", L"*", L"192.168.*", L"*", L"All", L"All"); g_fltCount = 2;              /* exclude wins over include */
    CHECK(PassesLogFilters(L"chrome.exe", L"8.8.8.8", L"80", L"TCP", L"Direct") && !PassesLogFilters(L"chrome.exe", L"192.168.1.5", L"80", L"TCP", L"Direct"));
    g_flt[0] = F(L"Include", L"*", L"*", L"443", L"TCP", L"Proxy"); g_flt[1] = F(L"Include", L"*", L"*", L"53", L"UDP", L"All"); g_fltCount = 2;   /* any include may match */
    CHECK(PassesLogFilters(L"a.exe", L"1.1.1.1", L"443", L"TCP", L"Proxy") && PassesLogFilters(L"a.exe", L"1.1.1.1", L"53", L"UDP", L"Direct") &&
          !PassesLogFilters(L"a.exe", L"1.1.1.1", L"443", L"TCP", L"Direct"));
    g_fltCount = 0;

    /* ================= log store: bounded, oldest dropped, auto-clear ================= */
    { static LogStore s; ZeroMemory(&s, sizeof s);
      s.edit = CreateWindowExW(0, L"EDIT", NULL, WS_POPUP | ES_MULTILINE, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
      CHECK(s.edit != NULL);
      g_autoClear = FALSE;
      for (int i = 0; i < LOG_MAX_LINES + 50; i++) { wchar_t l[40]; _snwprintf_s(l, 40, _TRUNCATE, L"line %d\r\n", i); LogStoreAdd(&s, l); }
      CHECK(s.count == LOG_MAX_LINES);
      CHECK(wcscmp(s.lines[0], L"line 50\r\n") == 0 && wcsncmp(s.lines[LOG_MAX_LINES - 1], L"line 4049", 9) == 0);     /* the first 50 were dropped */
      for (int i = 0; i < s.count; i++) free(s.lines[i]);
      s.count = 0; SetWindowTextW(s.edit, L"");
      g_autoClear = TRUE;
      for (int i = 0; i < AUTO_CLEAR_LINES + 1; i++) LogStoreAdd(&s, L"x\r\n");
      CHECK(s.count == 0);                                                                                              /* auto-clear wiped it at the threshold */
      DestroyWindow(s.edit); g_autoClear = TRUE; }

    /* ================= UTF-8 <-> UTF-16 helpers ================= */
    { wchar_t* w = U2Wdup("plain"); CHECK(w && !wcscmp(w, L"plain")); free(w); }
    { wchar_t* w = U2Wdup("caf\xC3\xA9 \xE4\xB8\xAD\xE6\x96\x87"); CHECK(w && !wcscmp(w, L"caf\x00e9 \x4e2d\x6587")); free(w); }
    { wchar_t* w = U2Wdup(NULL); CHECK(w && w[0] == 0); free(w); }
    { wchar_t* w = U2Wdup(""); CHECK(w && w[0] == 0); free(w); }
    { char buf[64]; W2Ux(L"caf\x00e9 \x4e2d", buf, sizeof buf); CHECK(!strcmp(buf, "caf\xC3\xA9 \xE4\xB8\xAD")); }
    { char buf[4]; memset(buf, 0x55, sizeof buf); W2Ux(L"this does not fit", buf, sizeof buf); CHECK(memchr(buf, 0, sizeof buf) != NULL); }   /* too small: still terminated */
    { char buf[8]; W2Ux(NULL, buf, sizeof buf); CHECK(buf[0] == 0); }
    { wchar_t ts[16]; GetTimePrefix(ts, 16); CHECK(wcslen(ts) == 11 && ts[0] == L'[' && ts[3] == L':' && ts[6] == L':' && ts[9] == L']'); }

    return pbtest_done("test_gui_misc");
}
