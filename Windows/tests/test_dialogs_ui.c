// test_dialogs_ui.c - the other windows of the app, created from the real dialog procedures and resources with a
// stubbed engine: the rule editor (fields, the proxy-only localhost option, clean-up on OK), the proxy servers list,
// the log filters list and the About box. Needs a desktop session. (Message boxes are never opened by these cases.)
#define wWinMain pb_real_wWinMain
#include "../gui/main.c"
#undef wWinMain
#include "pbtest.h"

static UINT32 g_delProxy = 0;
static UINT32 StubAddProxy(PBProxyType t, const char* ip, unsigned short p, const char* u, const char* pw, BOOL sd) { (void)t; (void)ip; (void)p; (void)u; (void)pw; (void)sd; return 500; }
static BOOL   StubDelProxy(UINT32 id) { g_delProxy = id; return TRUE; }

static HWND g_dlg;
static void Set(int id, const wchar_t* t) { SetDlgItemTextW(g_dlg, id, t); }
static void Get(int id, wchar_t* out, int cch) { GetDlgItemTextW(g_dlg, id, out, cch); }
static BOOL Visible(int id) { return IsWindowVisible(GetDlgItem(g_dlg, id)); }
static BOOL Checked(int id) { return IsDlgButtonChecked(g_dlg, id) == BST_CHECKED; }
static void Combo(int id, int sel) { SendDlgItemMessageW(g_dlg, id, CB_SETCURSEL, sel, 0); SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(id, CBN_SELCHANGE), (LPARAM)GetDlgItem(g_dlg, id)); }
static int  ComboSel(int id) { return (int)SendDlgItemMessageW(g_dlg, id, CB_GETCURSEL, 0, 0); }
static int  ComboCount(int id) { return (int)SendDlgItemMessageW(g_dlg, id, CB_GETCOUNT, 0, 0); }

static PPRow* g_fakeRows; static AppList g_ppResult;
static int FakeEnum(PPRow** out) { *out = (PPRow*)malloc(3 * sizeof(PPRow)); memcpy(*out, g_fakeRows, 3 * sizeof(PPRow)); return 3; }
static VOID CALLBACK PickTimer(HWND h, UINT m, UINT_PTR id, DWORD t)
{
    (void)h; (void)m; (void)t;
    HWND d = FindWindowW(L"#32770", T(S_DLG_PROCPICK));
    if (!d) return;
    KillTimer(NULL, id);
    HWND lv = GetDlgItem(d, IDC_PP_LIST);
    for (int i = 0; i < ListView_GetItemCount(lv); i++) ListView_SetItemState(lv, i, LVIS_SELECTED, LVIS_SELECTED);
    SendMessageW(d, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(d, IDOK));
}

static HWND OpenRuleEditor(PBRule* r)
{
    HWND d = CreateDialogParamW(g_hInst, MAKEINTRESOURCEW(IDD_RULE), NULL, RuleEditDlgProc, (LPARAM)r);
    ShowWindow(d, SW_SHOW);          /* a hidden dialog reports every control as invisible */
    return d;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hPrev; (void)cmd; (void)show;
    setvbuf(stdout, NULL, _IONBF, 0);
    g_hInst = hInst;
    CreateDarkBrushes();
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t sub[64]; _snwprintf_s(sub, 64, _TRUNCATE, L"pbtest_dialogs_%lu", GetCurrentProcessId()); wcscat_s(tmp, MAX_PATH, sub);
    CreateDirectoryW(tmp, NULL); SetEnvironmentVariableW(L"APPDATA", tmp);
    wcscpy_s(g_activeProfile, PB_NAME_MAX, L"uitest");
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS };
    InitCommonControlsEx(&icc);
    g_api.AddProxyConfig = StubAddProxy; g_api.DeleteProxyConfig = StubDelProxy;

    ZeroMemory(&g_profile, sizeof(g_profile));
    PBConfig* a = &g_profile.cfg[g_profile.cfgCount++]; a->storedId = 1; a->nativeId = 11; lstrcpynW(a->name, L"Burp", 128); lstrcpynW(a->type, L"SOCKS5", 16); lstrcpynW(a->host, L"127.0.0.1", 128); lstrcpynW(a->port, L"1080", 16);
    PBConfig* b = &g_profile.cfg[g_profile.cfgCount++]; b->storedId = 2; b->nativeId = 12; lstrcpynW(b->name, L"Corp", 128);  lstrcpynW(b->type, L"HTTP", 16);   lstrcpynW(b->host, L"10.0.0.9", 128);   lstrcpynW(b->port, L"3128", 16);

    /* ================= rule editor ================= */
    { PBRule r; ZeroMemory(&r, sizeof r);
      lstrcpynW(r.name, L"My rule", 128); lstrcpynW(r.proc, L"chrome.exe; edge.exe", PB_APPS_MAX); lstrcpynW(r.hosts, L"10.*.*.*;github.com;*.google.com", PB_HOSTS_MAX);
      lstrcpynW(r.ports, L"80;443", 128); lstrcpynW(r.proto, L"TCP", 8); lstrcpynW(r.action, L"PROXY", 16); r.enabled = 1; r.localhost = 1; r.cfgStoredId = 2;
      g_dlg = OpenRuleEditor(&r);
      CHECK(g_dlg != NULL);
      wchar_t t[2048];
      Get(IDC_RE_NAME, t, 2048);   CHECK(!wcscmp(t, L"My rule"));
      Get(IDC_RE_APPS, t, 2048);   CHECK(!wcscmp(t, L"chrome.exe; edge.exe"));
      Get(IDC_RE_HOSTS, t, 2048);  CHECK(!wcscmp(t, L"10.*.*.*;\r\ngithub.com;\r\n*.google.com"));        /* one entry per line in the editor */
      Get(IDC_RE_PORTS, t, 2048);  CHECK(!wcscmp(t, L"80;443"));
      CHECK(Checked(IDC_RE_ENABLED) && Checked(IDC_RE_LOCALHOST));
      CHECK(ComboCount(IDC_RE_ACTION) == 2 + g_profile.cfgCount);                                          /* Direct, Block, one per proxy */
      CHECK(ComboSel(IDC_RE_ACTION) == 3);                                                                 /* proxy #2 (stored id 2) */
      CHECK(Visible(IDC_RE_LOCALHOST) && Visible(IDC_RE_EX_LOCAL));                                         /* a proxy is selected: the option is shown */
      Combo(IDC_RE_ACTION, 0);  CHECK(!Visible(IDC_RE_LOCALHOST) && !Visible(IDC_RE_EX_LOCAL));            /* Direct: hidden */
      Combo(IDC_RE_ACTION, 1);  CHECK(!Visible(IDC_RE_LOCALHOST));                                          /* Block: hidden */
      Combo(IDC_RE_ACTION, 2);  CHECK(Visible(IDC_RE_LOCALHOST) && Checked(IDC_RE_LOCALHOST));              /* back to a proxy: shown, still ticked */

      /* OK: multi-line, messy host text is cleaned into one ';' list; the rule picks up every field */
      Set(IDC_RE_NAME, L"");
      Set(IDC_RE_HOSTS, L"  a.com ;\r\n b.org ,\r\n\r\n 10.0.0.0\r\n");
      Set(IDC_RE_PORTS, L"");
      Combo(IDC_RE_ACTION, 3);
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDOK));
      CHECK(!wcscmp(r.name, L"ProxyBridge Rule"));                                                         /* empty name gets the default */
      CHECK(!wcscmp(r.hosts, L"a.com;b.org;10.0.0.0"));                                                    /* blanks, line breaks and empty entries removed */
      CHECK(!wcscmp(r.ports, L"*") && !wcscmp(r.action, L"PROXY") && r.cfgStoredId == 2 && r.localhost == 1 && r.enabled == 1);
      DestroyWindow(g_dlg); }

    /* line breaks after a ';' are formatting only */
    { PBRule r; ZeroMemory(&r, sizeof r); lstrcpynW(r.proc, L"*", 256); lstrcpynW(r.hosts, L"*", PB_HOSTS_MAX); lstrcpynW(r.ports, L"*", 128); lstrcpynW(r.proto, L"BOTH", 8); lstrcpynW(r.action, L"DIRECT", 16); r.enabled = 1;
      g_dlg = OpenRuleEditor(&r);
      Set(IDC_RE_HOSTS, L"x.com;\r\ny.org;\r\n");
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDOK));
      CHECK(!wcscmp(r.hosts, L"x.com;y.org"));
      DestroyWindow(g_dlg); }

    /* localhost is saved only for proxy rules, and an empty hosts box means "any host" */
    { PBRule r; ZeroMemory(&r, sizeof r); lstrcpynW(r.proc, L"x.exe", 256); lstrcpynW(r.hosts, L"*", PB_HOSTS_MAX); lstrcpynW(r.ports, L"*", 128); lstrcpynW(r.proto, L"BOTH", 8);
      lstrcpynW(r.action, L"PROXY", 16); r.cfgStoredId = 1; r.localhost = 1; r.enabled = 1;
      g_dlg = OpenRuleEditor(&r);
      Combo(IDC_RE_ACTION, 1);                                                                              /* Block */
      Set(IDC_RE_HOSTS, L"");
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDOK));
      CHECK(!wcscmp(r.action, L"BLOCK") && r.localhost == 0 && r.cfgStoredId == 0 && !wcscmp(r.hosts, L"*"));
      DestroyWindow(g_dlg); }
    { PBRule r; ZeroMemory(&r, sizeof r); lstrcpynW(r.proc, L"x.exe", 256); lstrcpynW(r.hosts, L"*", PB_HOSTS_MAX); lstrcpynW(r.ports, L"*", 128); lstrcpynW(r.proto, L"UDP", 8); lstrcpynW(r.action, L"DIRECT", 16); r.localhost = 1;
      g_dlg = OpenRuleEditor(&r);
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDOK));
      CHECK(!wcscmp(r.action, L"DIRECT") && r.localhost == 0 && !wcscmp(r.proto, L"UDP"));                  /* a stale flag on a Direct rule is dropped */
      DestroyWindow(g_dlg); }

    /* Cancel leaves the rule untouched */
    { PBRule r; ZeroMemory(&r, sizeof r); lstrcpynW(r.name, L"keep", 128); lstrcpynW(r.proc, L"x.exe", 256); lstrcpynW(r.hosts, L"1.1.1.1", PB_HOSTS_MAX); lstrcpynW(r.ports, L"*", 128); lstrcpynW(r.proto, L"TCP", 8); lstrcpynW(r.action, L"DIRECT", 16);
      g_dlg = OpenRuleEditor(&r);
      Set(IDC_RE_NAME, L"changed"); Set(IDC_RE_HOSTS, L"2.2.2.2");
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDCANCEL));
      CHECK(!wcscmp(r.name, L"keep") && !wcscmp(r.hosts, L"1.1.1.1"));
      DestroyWindow(g_dlg); }

    /* ================= Applications list: Browse / Running helpers ================= */
    { PBRule r; ZeroMemory(&r, sizeof r); lstrcpynW(r.proc, L"*", 256); lstrcpynW(r.hosts, L"*", PB_HOSTS_MAX); lstrcpynW(r.ports, L"*", 128); lstrcpynW(r.proto, L"BOTH", 8); lstrcpynW(r.action, L"DIRECT", 16);
      g_dlg = OpenRuleEditor(&r);
      static wchar_t t[PB_APPS_MAX]; int bad = -1, dup = -1;
      const wchar_t* one[] = { L"curl.exe", L"Chrome.exe" };
      CHECK(AppendApps(g_dlg, one, 2, &bad, &dup) == 2 && bad == 0);                                        /* "*" gives way to the first entry */
      Get(IDC_RE_APPS, t, PB_APPS_MAX);  CHECK(!wcscmp(t, L"curl.exe; Chrome.exe"));
      const wchar_t* two[] = { L"CHROME.EXE", L"edge.exe", L"a;b.exe", L"" };
      CHECK(AppendApps(g_dlg, two, 4, &bad, &dup) == 1 && bad == 2 && dup == 1);                            /* duplicate (any case) skipped, unusable names refused */
      Get(IDC_RE_APPS, t, PB_APPS_MAX);  CHECK(!wcscmp(t, L"curl.exe; Chrome.exe; edge.exe"));
      /* a nearly full list: a name that does not fit is refused whole, never cut */
      static wchar_t big[PB_APPS_MAX]; int k = 0; for (; k < PB_APPS_MAX - 12; k++) big[k] = L'x'; big[k] = 0;
      SendDlgItemMessageW(g_dlg, IDC_RE_APPS, EM_LIMITTEXT, 0, 0);
      Set(IDC_RE_APPS, big);
      const wchar_t* tail[] = { L"averylongname.exe", L"a.exe" };
      CHECK(AppendApps(g_dlg, tail, 2, &bad, &dup) == 1 && bad == 1);
      Get(IDC_RE_APPS, t, PB_APPS_MAX);  CHECK(wcslen(t) < PB_APPS_MAX && wcsstr(t, L"; a.exe") && !wcsstr(t, L"averylong"));
      DestroyWindow(g_dlg); }

    /* ================= running-programs picker (fake process list) ================= */
    {
      static PPRow fake[3]; g_fakeRows = fake;
      lstrcpynW(fake[0].name, L"alpha.exe", 260); lstrcpynW(fake[0].path, L"C:\\Apps\\alpha.exe", MAX_PATH); fake[0].pid = 4242; fake[0].instances = 3;
      lstrcpynW(fake[1].name, L"beta.exe", 260);  lstrcpynW(fake[1].path, L"C:\\My, Apps\\beta.exe", MAX_PATH); fake[1].pid = 77; fake[1].instances = 1;   /* comma: unusable as a path in the list */
      lstrcpynW(fake[2].name, L"gamma.exe", 260); fake[2].pid = 9; fake[2].instances = 1;                                                                   /* path unreadable */
      g_ppEnumerate = FakeEnum;
      g_dlg = CreateDialogParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROCPICK), NULL, ProcPickDlgProc, (LPARAM)&g_ppResult);
      ShowWindow(g_dlg, SW_SHOW);
      HWND lv = GetDlgItem(g_dlg, IDC_PP_LIST);
      CHECK(ListView_GetItemCount(lv) == 3 && !IsWindowEnabled(GetDlgItem(g_dlg, IDOK)));                   /* Add needs a selection */
      wchar_t t[64]; ListView_GetItemText(lv, 0, 1, t, 64); CHECK(!wcscmp(t, L"4242  (+2)"));              /* PID shown for reference only */
      Set(IDC_PP_SEARCH, L"APPS alp");  CHECK(ListView_GetItemCount(lv) == 1);                              /* every word, name or path, any case */
      Set(IDC_PP_SEARCH, L"");          CHECK(ListView_GetItemCount(lv) == 3);
      ListView_SetItemState(lv, 0, LVIS_SELECTED, LVIS_SELECTED);
      CHECK(IsWindowEnabled(GetDlgItem(g_dlg, IDOK)));
      CHECK(!wcscmp(PPChoose(&fake[0], FALSE), L"alpha.exe") && !wcscmp(PPChoose(&fake[0], TRUE), L"C:\\Apps\\alpha.exe"));
      CHECK(!wcscmp(PPChoose(&fake[1], TRUE), L"beta.exe") && !wcscmp(PPChoose(&fake[2], TRUE), L"gamma.exe"));   /* fall back to the name */
      DestroyWindow(g_dlg);
      /* modal run: select everything and press Add - the result holds names, never PIDs */
      SetTimer(NULL, 1, 50, PickTimer);
      CHECK(DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROCPICK), NULL, ProcPickDlgProc, (LPARAM)&g_ppResult) == 1);
      CHECK(g_ppResult.n == 3 && !wcscmp(g_ppResult.v[0], L"alpha.exe") && !wcscmp(g_ppResult.v[1], L"beta.exe") && !wcscmp(g_ppResult.v[2], L"gamma.exe"));
      AppListFree(&g_ppResult);
      /* the real enumerator finds this very program with its path */
      PPRow* rows = NULL; int n = PPEnumerateReal(&rows); BOOL me = FALSE;
      wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
      for (int i = 0; i < n; i++) if (!_wcsicmp(rows[i].path, exe)) me = TRUE;
      CHECK(n > 3 && me); free(rows);
    }

    /* ================= proxy servers list ================= */
    g_dlg = CreateDialogParamW(hInst, MAKEINTRESOURCEW(IDD_SERVERS), NULL, ServersDlgProc, 0);
    CHECK(g_dlg != NULL);
    { HWND lv = GetDlgItem(g_dlg, IDC_SV_LIST);
      CHECK(ListView_GetItemCount(lv) == 2);
      wchar_t t[128]; ListView_GetItemText(lv, 0, 0, t, 128); CHECK(!wcscmp(t, L"Burp"));
      ListView_SetItemState(lv, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDC_SV_REMOVE, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDC_SV_REMOVE));
      CHECK(g_delProxy == 11 && g_profile.cfgCount == 1 && g_profile.cfg[0].storedId == 2 && ListView_GetItemCount(lv) == 1);   /* the right proxy went */
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDC_SV_REMOVE, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDC_SV_REMOVE));            /* nothing selected: nothing happens */
      CHECK(g_profile.cfgCount == 1);
      DestroyWindow(g_dlg); }

    /* ================= log filters list ================= */
    g_profile.filterCount = 2;
    lstrcpynW(g_profile.filter[0].mode, L"Include", 16); lstrcpynW(g_profile.filter[0].proc, L"chrome*", 256); lstrcpynW(g_profile.filter[0].ip, L"*", 64); lstrcpynW(g_profile.filter[0].port, L"*", 16); lstrcpynW(g_profile.filter[0].proto, L"All", 8); lstrcpynW(g_profile.filter[0].action, L"All", 16);
    lstrcpynW(g_profile.filter[1].mode, L"Exclude", 16); lstrcpynW(g_profile.filter[1].proc, L"*", 256);      lstrcpynW(g_profile.filter[1].ip, L"10.*", 64); lstrcpynW(g_profile.filter[1].port, L"*", 16); lstrcpynW(g_profile.filter[1].proto, L"All", 8); lstrcpynW(g_profile.filter[1].action, L"All", 16);
    g_dlg = CreateDialogParamW(hInst, MAKEINTRESOURCEW(IDD_FILTERS), NULL, FiltersDlgProc, 0);
    CHECK(g_dlg != NULL);
    { HWND lv = GetDlgItem(g_dlg, IDC_FL_LIST);
      CHECK(ListView_GetItemCount(lv) == 2);
      ListView_SetItemState(lv, 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      SendMessageW(g_dlg, WM_COMMAND, MAKEWPARAM(IDC_FL_REMOVE, BN_CLICKED), (LPARAM)GetDlgItem(g_dlg, IDC_FL_REMOVE));
      CHECK(g_profile.filterCount == 1 && !wcscmp(g_profile.filter[0].mode, L"Include") && ListView_GetItemCount(lv) == 1);
      DestroyWindow(g_dlg); }

    /* ================= About box ================= */
    g_dlg = CreateDialogParamW(hInst, MAKEINTRESOURCEW(IDD_ABOUT), NULL, AboutDlgProc, 0);
    CHECK(g_dlg != NULL);
    { wchar_t t[256]; Get(IDC_AB_VER, t, 256); CHECK(wcsstr(t, PB_VER_STRW) != NULL);                    /* shows the real version */
      Get(IDC_AB_TITLE, t, 256); CHECK(wcsstr(t, L"ProxyBridge") != NULL);
      DestroyWindow(g_dlg); }

    return pbtest_done("test_dialogs_ui");
}
