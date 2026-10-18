// test_rules_ui.c - drives the REAL Proxy Rules window (RulesDlgProc from gui\ui\dialogs.h) with a stubbed engine:
// search/filter, the row -> rule mapping (Edit / Clone / Remove / check boxes act on the rule you see), the
// keyboard shortcuts, Move Up/Down only without a search, and a reopened window starting unfiltered.
// Needs a desktop session (it creates real windows); the engine API is replaced by recording stubs.
#define wWinMain pb_real_wWinMain
#include "../gui/main.c"
#undef wWinMain
#include "pbtest.h"

/* ---- engine stubs: they only record what the window asked for ---- */
static UINT32 g_lastDeleted, g_lastEnabled, g_lastDisabled, g_lastMovedId, g_lastMovedPos, g_nextId = 1000;
static UINT32 StubAdd(const char* a, const char* b, const char* c, const char* d, PBRuleProtocol p, PBRuleAction e, UINT32 f, BOOL g) { (void)a;(void)b;(void)c;(void)d;(void)p;(void)e;(void)f;(void)g; return g_nextId++; }
static BOOL   StubEdit(UINT32 id, const char* a, const char* b, const char* c, const char* d, PBRuleProtocol p, PBRuleAction e, UINT32 f, BOOL g) { (void)id;(void)a;(void)b;(void)c;(void)d;(void)p;(void)e;(void)f;(void)g; return TRUE; }
static BOOL   StubDelete(UINT32 id)  { g_lastDeleted = id; return TRUE; }
static BOOL   StubEnable(UINT32 id)  { g_lastEnabled = id; return TRUE; }
static BOOL   StubDisable(UINT32 id) { g_lastDisabled = id; return TRUE; }
static BOOL   StubMove(UINT32 id, UINT32 pos) { g_lastMovedId = id; g_lastMovedPos = pos; return TRUE; }

static void AddRuleToProfile(const wchar_t* name, const wchar_t* proc, const wchar_t* hosts, const wchar_t* action, UINT32 nativeId)
{
    PBRule* r = &g_profile.rule[g_profile.ruleCount++];
    ZeroMemory(r, sizeof(*r));
    lstrcpynW(r->name, name, 128); lstrcpynW(r->proc, proc, PB_APPS_MAX); lstrcpynW(r->hosts, hosts, PB_HOSTS_MAX);
    lstrcpynW(r->ports, L"*", 128); lstrcpynW(r->proto, L"TCP", 8); lstrcpynW(r->action, action, 16);
    r->enabled = 1; r->nativeId = nativeId;
}

static HWND g_dlg, g_lv, g_search;
static int  Rows(void) { return ListView_GetItemCount(g_lv); }
static BOOL RowIs(int row, const wchar_t* name) { wchar_t b[128]; ListView_GetItemText(g_lv, row, 1, b, 128); return wcscmp(b, name) == 0; }
static void Type(const wchar_t* text) { SetWindowTextW(g_search, text); }              /* fires EN_CHANGE synchronously */
static void SelectRow(int row) { ListView_SetItemState(g_lv, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); }
static void Click(int id) { SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, id)); }
static BOOL HaveForeground(void) { return GetForegroundWindow() == g_dlg; }

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hPrev; (void)cmd; (void)show;
    setvbuf(stdout, NULL, _IONBF, 0);
    g_hInst = hInst;
    CreateDarkBrushes();                                       /* the same brushes the real app creates at startup */
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t sub[64]; _snwprintf_s(sub, 64, _TRUNCATE, L"pbtest_rulesui_%lu", GetCurrentProcessId()); wcscat_s(tmp, MAX_PATH, sub);
    CreateDirectoryW(tmp, NULL); SetEnvironmentVariableW(L"APPDATA", tmp);   /* SaveActive() writes the profile here */
    wcscpy_s(g_activeProfile, PB_NAME_MAX, L"uitest");
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS };
    InitCommonControlsEx(&icc);

    g_api.AddRule = StubAdd; g_api.EditRule = StubEdit; g_api.DeleteRule = StubDelete;
    g_api.EnableRule = StubEnable; g_api.DisableRule = StubDisable; g_api.MoveRuleToPosition = StubMove;

    ZeroMemory(&g_profile, sizeof(g_profile));
    PBConfig* c = &g_profile.cfg[g_profile.cfgCount++];
    c->storedId = 1; lstrcpynW(c->name, L"Burp", 128); lstrcpynW(c->type, L"SOCKS5", 16); lstrcpynW(c->host, L"127.0.0.1", 128); lstrcpynW(c->port, L"1080", 16);
    AddRuleToProfile(L"Chrome to Burp",  L"chrome.exe",           L"*",                       L"PROXY",  101);   /* index 0 */
    AddRuleToProfile(L"Firefox direct",  L"firefox.exe",          L"192.168.*.*",             L"DIRECT", 102);   /* index 1 */
    AddRuleToProfile(L"Chrome internal", L"chrome.exe; edge.exe", L"10.*.*.*;corp.local",     L"DIRECT", 103);   /* index 2 */
    AddRuleToProfile(L"Block telemetry", L"*",                    L"telemetry.example.com",   L"BLOCK",  104);   /* index 3 */
    AddRuleToProfile(L"curl github",     L"curl.exe",             L"github.com;*.github.com", L"PROXY",  105);   /* index 4 */
    g_profile.rule[0].cfgStoredId = 1; g_profile.rule[4].cfgStoredId = 1;

    g_dlg = CreateDialogParamW(hInst, MAKEINTRESOURCEW(IDD_RULES), NULL, RulesDlgProc, 0);
    CHECK(g_dlg != NULL);
    ShowWindow(g_dlg, SW_SHOW); SetForegroundWindow(g_dlg); SetActiveWindow(g_dlg);
    g_lv = GetDlgItem(g_dlg, IDC_RL_LIST); g_search = GetDlgItem(g_dlg, IDC_RL_SEARCH);
    CHECK(g_lv && g_search && GetDlgItem(g_dlg, IDC_RL_COUNT) && GetDlgItem(g_dlg, IDC_RL_CLEAR));
    if (!HaveForeground()) puts("  note: the window is not the foreground window here; focus-movement checks are skipped");

    /* 1. opens with the full list, an empty search box, reordering on, clear off */
    CHECK(Rows() == 5 && g_rlMapN == 5);
    CHECK(IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_UP)) && IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_DOWN)));
    CHECK(!IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_CLEAR)));

    /* 2. filter by process name (case-insensitive) */
    Type(L"CHROME");
    CHECK(Rows() == 2 && RowIs(0, L"Chrome to Burp") && RowIs(1, L"Chrome internal"));
    CHECK(g_rlMap[0] == 0 && g_rlMap[1] == 2);
    wchar_t cnt[160]; GetDlgItemTextW(g_dlg, IDC_RL_COUNT, cnt, 160);
    CHECK(wcsstr(cnt, L"2 of 5") != NULL);
    CHECK(!IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_UP)) && !IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_DOWN)));   /* no reordering of a partial view */
    CHECK(IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_CLEAR)));

    /* 3. several words must ALL match, across columns */
    Type(L"chrome corp");     CHECK(Rows() == 1 && RowIs(0, L"Chrome internal"));
    Type(L"chrome burp");     CHECK(Rows() == 1 && RowIs(0, L"Chrome to Burp"));       /* the proxy column is searched */
    Type(L"chrome nonsense"); CHECK(Rows() == 0);
    GetDlgItemTextW(g_dlg, IDC_RL_COUNT, cnt, 160); CHECK(wcsstr(cnt, L"0 of 5") != NULL);

    /* 4. hosts (IP and domain), action */
    Type(L"192.168");   CHECK(Rows() == 1 && RowIs(0, L"Firefox direct"));
    Type(L"github.com"); CHECK(Rows() == 1 && RowIs(0, L"curl github"));
    Type(L"block");     CHECK(Rows() == 1 && RowIs(0, L"Block telemetry"));
    Type(L"direct");    CHECK(Rows() == 2);

    /* 5. actions on a filtered list act on the RIGHT rule (row 1 of "chrome" is rule index 2, not 1) */
    Type(L"chrome");    CHECK(Rows() == 2);
    ListView_SetCheckState(g_lv, 1, FALSE);                                             /* untick "Chrome internal" */
    CHECK(g_profile.rule[2].enabled == 0 && g_profile.rule[0].enabled == 1 && g_profile.rule[1].enabled == 1);
    CHECK(g_lastDisabled == 103);
    ListView_SetCheckState(g_lv, 1, TRUE);
    CHECK(g_profile.rule[2].enabled == 1 && g_lastEnabled == 103);

    SelectRow(1);                                                                       /* "Chrome internal" = rule index 2 */
    Click(IDC_RL_CLONE);
    CHECK(g_profile.ruleCount == 6);
    CHECK(wcscmp(g_profile.rule[3].name, L"Chrome internal") == 0 && wcscmp(g_profile.rule[2].name, L"Chrome internal") == 0);   /* slotted right after its source */
    CHECK(g_lastMovedPos == 4);                                                         /* engine position = source index 2 + 2 */
    CHECK(Rows() == 3);                                                                 /* the clone matches the same search */
    CHECK(SelectedRuleIndex(g_lv) == 3);                                                /* and is selected */

    Click(IDC_RL_REMOVE);                                                               /* removes the selected clone (rule index 3) */
    CHECK(g_profile.ruleCount == 5 && g_lastDeleted >= 1000);
    CHECK(wcscmp(g_profile.rule[3].name, L"Block telemetry") == 0 && Rows() == 2);

    SelectRow(0);                                                                       /* "Chrome to Burp" */
    Click(IDC_RL_REMOVE);
    CHECK(g_lastDeleted == 101 && g_profile.ruleCount == 4);
    CHECK(wcscmp(g_profile.rule[0].name, L"Firefox direct") == 0);
    CHECK(Rows() == 1 && RowIs(0, L"Chrome internal"));
    CHECK(g_profile.rule[1].nativeId == 103);                                           /* the right engine rule survived */

    /* 6. Clear restores the full list and reordering */
    Click(IDC_RL_CLEAR);
    CHECK(Rows() == 4 && g_rlWordN == 0);
    CHECK(IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_UP)) && !IsWindowEnabled(GetDlgItem(g_dlg, IDC_RL_CLEAR)));
    GetDlgItemTextW(g_dlg, IDC_RL_SEARCH, cnt, 160); CHECK(cnt[0] == 0);

    /* 7. reordering on the full list still works */
    SelectRow(0);
    Click(IDC_RL_DOWN);
    CHECK(wcscmp(g_profile.rule[0].name, L"Chrome internal") == 0 && wcscmp(g_profile.rule[1].name, L"Firefox direct") == 0);
    CHECK(g_lastMovedId == g_profile.rule[1].nativeId && g_lastMovedPos == 2);
    CHECK(SelectedRuleIndex(g_lv) == 1 && RowIs(1, L"Firefox direct"));

    /* 8. keyboard: type-to-search from the list, Down / Enter to the list, Esc clears */
    SetFocus(g_lv);
    SendMessageW(g_lv, WM_CHAR, L'f', 0);                                               /* a printable key in the list starts a search */
    wchar_t t[16]; GetWindowTextW(g_search, t, 16);
    CHECK(wcscmp(t, L"f") == 0);
    if (HaveForeground()) CHECK(GetFocus() == g_search);
    CHECK(Rows() >= 1 && g_rlWordN == 1);
    SendMessageW(g_search, WM_KEYDOWN, VK_DOWN, 0);                                     /* Down: into the list, first row selected */
    CHECK(ListView_GetNextItem(g_lv, -1, LVNI_SELECTED) == 0);
    if (HaveForeground()) CHECK(GetFocus() == g_lv);
    SendMessageW(g_lv, WM_KEYDOWN, VK_ESCAPE, 0);                                       /* Esc in the list clears an active search */
    GetWindowTextW(g_search, t, 16);
    CHECK(t[0] == 0 && g_rlWordN == 0 && Rows() == 4);
    Type(L"firefox");  SendMessageW(g_search, WM_KEYDOWN, VK_ESCAPE, 0);                /* Esc in the box clears it */
    CHECK(GetWindowTextLengthW(g_search) == 0 && Rows() == 4);
    Type(L"firefox");  SendMessageW(g_search, WM_KEYDOWN, VK_RETURN, 0);                /* Enter hands over to the list */
    if (HaveForeground()) CHECK(GetFocus() == g_lv);
    Type(L""); SetFocus(g_lv); SendMessageW(g_lv, WM_CHAR, L' ', 0);                    /* space is NOT type-to-search (it toggles the check box) */
    CHECK(GetWindowTextLengthW(g_search) == 0);

    /* 9. odd input: a very long query, blanks only, more words than supported */
    wchar_t longq[300]; for (int i = 0; i < 299; i++) longq[i] = (i % 6 == 5) ? L' ' : L'a'; longq[299] = 0;
    Type(longq);  CHECK(Rows() == 0);
    Type(L"  \t  ");  CHECK(Rows() == 4 && g_rlWordN == 0);                             /* blanks only = no filter */
    Type(L"a b c d e f g h i j k");  CHECK(g_rlWordN == RL_MAX_WORDS);

    /* 10. a reopened window starts unfiltered */
    Type(L"firefox");
    DestroyWindow(g_dlg);
    g_dlg = CreateDialogParamW(hInst, MAKEINTRESOURCEW(IDD_RULES), NULL, RulesDlgProc, 0);
    g_lv = GetDlgItem(g_dlg, IDC_RL_LIST); g_search = GetDlgItem(g_dlg, IDC_RL_SEARCH);
    CHECK(Rows() == g_profile.ruleCount && g_rlWordN == 0 && GetWindowTextLengthW(g_search) == 0);
    DestroyWindow(g_dlg);

    return pbtest_done("test_rules_ui");
}
