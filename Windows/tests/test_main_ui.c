// test_main_ui.c - creates the REAL main window (same setup as wWinMain, engine stubbed) and drives the menu:
//   Proxy -> Enable ProxyBridge (the main switch)   menu item, title "(PAUSED)", tray tooltip, engine call, language rebuild
//   Settings -> Log Every Connection               default off, toggles, tells the engine, saved with the profile
// Needs a desktop session (it creates real windows).
#define wWinMain pb_real_wWinMain
#include "../gui/main.c"
#undef wWinMain
#include "pbtest.h"

static int  g_enabledCalls = 0, g_logAllCalls = 0;
static BOOL g_lastEnabledArg = TRUE, g_lastLogAllArg = FALSE;
static void StubSetEnabled(BOOL v) { g_enabledCalls++; g_lastEnabledArg = v; }
static void StubSetLogAll(BOOL v)  { g_logAllCalls++;  g_lastLogAllArg = v; }
static void StubSetTraffic(BOOL v) { (void)v; }
static void StubSetLog(PBLogCallback cb) { (void)cb; }
static void StubSetConn(PBConnectionCallback cb) { (void)cb; }

static PBProfile g_probe;

static PBFlow g_stubFlows[8]; static UINT32 g_stubN = 0; static int g_stubCalls = 0;
static UINT32 StubGetFlows(PBFlow* out, UINT32 max) { g_stubCalls++; UINT32 n = g_stubN < max ? g_stubN : max; memcpy(out, g_stubFlows, n * sizeof(PBFlow)); return n; }
/* lets the worker thread of an asynchronous poll finish and its result be applied, then stops the poll timer so the
   test controls every further poll itself */
static void PumpFlows(void)
{
    for (int i = 0; i < 600; i++)
    {
        MSG m; while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m);
        if (!g_flBusy) break;
        Sleep(5);
    }
    KillTimer(g_hMain, TIMER_FLOWS);
}
static void MkFlow(PBFlow* f, UINT64 id, DWORD pid, const char* name, const char* host, int port, int udp, int v6, UINT32 age, UINT64 sent, UINT64 recv, UINT32 proxy)
{
    ZeroMemory(f, sizeof(*f));
    f->id = id; f->pid = pid; f->port = (UINT16)port; f->is_udp = (UINT8)udp; f->is_ipv6 = (UINT8)v6; f->age_ms = age; f->sent = sent; f->received = recv; f->proxy_config_id = proxy;
    strcpy_s(f->name, sizeof f->name, name); strcpy_s(f->host, sizeof f->host, host);
}

static BOOL MenuChecked(HWND h, UINT id) { UINT st = GetMenuState(GetMenu(h), id, MF_BYCOMMAND); return st != (UINT)-1 && (st & MF_CHECKED); }
static BOOL MenuExists(HWND h, UINT id)  { return GetMenuState(GetMenu(h), id, MF_BYCOMMAND) != (UINT)-1; }

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hPrev; (void)cmd; (void)show;
    setvbuf(stdout, NULL, _IONBF, 0);
    g_hInst = hInst;
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t sub[64]; _snwprintf_s(sub, 64, _TRUNCATE, L"pbtest_mainui_%lu", GetCurrentProcessId()); wcscat_s(tmp, MAX_PATH, sub);
    CreateDirectoryW(tmp, NULL); SetEnvironmentVariableW(L"APPDATA", tmp);
    wcscpy_s(g_activeProfile, PB_NAME_MAX, L"uitest");
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);
    PB_ProfileDefaults(&g_profile, L"uitest");
    g_api.SetEnabled = StubSetEnabled; g_api.SetTrafficLoggingEnabled = StubSetTraffic; g_api.SetLogEveryConnection = StubSetLogAll;
    g_api.SetLogCallback = StubSetLog; g_api.SetConnectionCallback = StubSetConn;

    CreateDarkBrushes();
    WNDCLASSEXW wc; ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc; wc.hInstance = hInst;
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE); wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW); wc.hbrBackground = g_brBg; wc.lpszClassName = WND_CLASS;
    CHECK(RegisterClassExW(&wc) != 0);
    g_hMain = CreateWindowExW(0, WND_CLASS, APP_TITLE, WS_OVERLAPPEDWINDOW, 100, 100, 1000, 700, NULL, NULL, hInst, NULL);
    CHECK(g_hMain != NULL);
    BuildMainMenu(g_hMain); DrawMenuBar(g_hMain); TrayAdd(g_hMain); SyncMenuChecks(g_hMain); RebuildProfileMenu(g_hMain); UpdateTitle();
    g_api.SetEnabled(g_proxyEnabled);                       /* what startup does */

    /* 1. on by default: the item exists, is checked, and nothing says "paused" */
    wchar_t title[256]; GetWindowTextW(g_hMain, title, 256);
    CHECK(MenuExists(g_hMain, IDM_PROXY_ENABLE) && MenuChecked(g_hMain, IDM_PROXY_ENABLE));
    CHECK(g_proxyEnabled == TRUE && g_lastEnabledArg == TRUE);
    CHECK(wcsstr(title, L"PAUSED") == NULL && wcsstr(g_tray.szTip, L"PAUSED") == NULL);

    /* 2. switch off */
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_PROXY_ENABLE, 0), 0);
    GetWindowTextW(g_hMain, title, 256);
    CHECK(g_proxyEnabled == FALSE && g_lastEnabledArg == FALSE && g_enabledCalls == 2);   /* told the engine */
    CHECK(!MenuChecked(g_hMain, IDM_PROXY_ENABLE));
    CHECK(wcsstr(title, L"PAUSED") != NULL && wcsstr(title, g_activeProfile) != NULL);
    CHECK(g_trayAdded ? wcsstr(g_tray.szTip, L"PAUSED") != NULL : TRUE);
    CHECK(wcsncmp(g_tray.szTip, APP_TITLE, wcslen(APP_TITLE)) == 0);

    /* 3. switch back on */
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_PROXY_ENABLE, 0), 0);
    GetWindowTextW(g_hMain, title, 256);
    CHECK(g_proxyEnabled == TRUE && g_lastEnabledArg == TRUE && g_enabledCalls == 3);
    CHECK(MenuChecked(g_hMain, IDM_PROXY_ENABLE));
    CHECK(wcsstr(title, L"PAUSED") == NULL && wcsstr(g_tray.szTip, L"PAUSED") == NULL);

    /* 4. the paused state survives a menu rebuild (language switch) and shows the translated marker */
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_PROXY_ENABLE, 0), 0);               /* off again */
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_LANG_ZH, 0), 0);
    CHECK(MenuExists(g_hMain, IDM_PROXY_ENABLE) && !MenuChecked(g_hMain, IDM_PROXY_ENABLE));
    GetWindowTextW(g_hMain, title, 256);
    CHECK(wcsstr(title, L"\x5df2\x6682\x505c") != NULL);
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_LANG_EN, 0), 0);
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_PROXY_ENABLE, 0), 0);               /* on */
    CHECK(MenuChecked(g_hMain, IDM_PROXY_ENABLE) && g_proxyEnabled);

    /* 5. Log Every Connection: off by default, toggles, tells the engine, saved with the profile */
    CHECK(MenuExists(g_hMain, IDM_SET_LOGALL));
    CHECK(!MenuChecked(g_hMain, IDM_SET_LOGALL) && g_logEvery == FALSE && g_profile.logEveryConnection == 0);
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_SET_LOGALL, 0), 0);
    CHECK(g_logEvery == TRUE && g_lastLogAllArg == TRUE && g_logAllCalls == 1);
    CHECK(MenuChecked(g_hMain, IDM_SET_LOGALL) && g_profile.logEveryConnection == 1);
    PB_ProfileLoad(g_activeProfile, &g_probe);                                           /* it was saved */
    CHECK(g_probe.logEveryConnection == 1);
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_SET_LOGALL, 0), 0);
    CHECK(g_logEvery == FALSE && g_lastLogAllArg == FALSE && !MenuChecked(g_hMain, IDM_SET_LOGALL));
    PB_ProfileLoad(g_activeProfile, &g_probe);
    CHECK(g_probe.logEveryConnection == 0);
    PB_ProfileDefaults(&g_probe, L"x");                                                  /* a profile without the key: off */
    CHECK(g_probe.logEveryConnection == 0);

    /* 6. Live Connections tab */
    g_api.GetFlows = StubGetFlows;
    { TCITEMW ti; wchar_t tx[64]; ti.mask = TCIF_TEXT; ti.pszText = tx; ti.cchTextMax = 64;
      BOOL gi = TabCtrl_GetItem(g_hTab, 2, &ti); CHECK(TabCtrl_GetItemCount(g_hTab) == 3 && gi && !wcscmp(tx, L"Live Connections")); }
    CHECK(g_hFlows != NULL && !IsWindowVisible(g_hFlows) && g_fl == NULL && g_flSnap == NULL);          /* nothing is polled or held until opened */
    ShowWindow(g_hMain, SW_SHOWNOACTIVATE);
    g_stubN = 0;
    SelectTab(2);                                                                                      /* opening the tab polls at once (on a worker thread) */
    PumpFlows();
    CHECK(IsWindowVisible(g_hFlows) && !IsWindowVisible(g_hConnLog) && !IsWindowVisible(g_hActLog) && g_stubCalls >= 1 && g_flN == 0 && g_flBusy == 0);

    { PBFlow s[3];
      g_profile.cfgCount = 1; g_profile.cfg[0].nativeId = 5; lstrcpynW(g_profile.cfg[0].name, L"Burp", 128); lstrcpynW(g_profile.cfg[0].type, L"SOCKS5", 16); lstrcpynW(g_profile.cfg[0].host, L"127.0.0.1", 128); lstrcpynW(g_profile.cfg[0].port, L"1080", 16);
      g_profile.ruleCount = 1; g_profile.rule[0].nativeId = 21; lstrcpynW(g_profile.rule[0].name, L"Browsers", 128);
      MkFlow(&s[0], 11, 4312, "chrome.exe", "example.com", 443, 0, 0, 65000, 2048, 5u * 1024 * 1024, 5); s[0].rule_id = 21;
      MkFlow(&s[1], 12, 77,   "game.exe",   "203.0.113.7", 27015, 1, 0, 0xFFFFFFFFu, 0, 900, 5);
      MkFlow(&s[2], 13, 9,    "",           "2606:4700::1111", 443, 0, 1, 1000, 1, 1, 99);
      memcpy(g_stubFlows, s, sizeof s); g_stubN = 3;
      FlowsPoll();
      CHECK(g_flN == 3 && ListView_GetItemCount(g_hFlows) == 3 && g_stubCalls >= 2);
      ULONGLONG now = g_flNow; wchar_t t[128];
      int r = -1; for (int i = 0; i < g_flN; i++) if (g_fl[i].id == 11) r = i;
      FlowText(&g_fl[r], 0, now, t, 128); CHECK(!wcscmp(t, L"chrome.exe (4312)"));
      FlowText(&g_fl[r], 1, now, t, 128); CHECK(!wcscmp(t, L"example.com:443"));
      FlowText(&g_fl[r], 2, now, t, 128); CHECK(!wcscmp(t, L"TCP"));
      FlowText(&g_fl[r], 3, now, t, 128); CHECK(!wcscmp(t, L"1:05"));
      FlowText(&g_fl[r], 4, now, t, 128); CHECK(!wcscmp(t, L"Browsers : Burp (SOCKS5 127.0.0.1:1080)"));
      FlowRuleProxy(0, 5, t, 128);  CHECK(!wcscmp(t, L"Burp (SOCKS5 127.0.0.1:1080)"));                      /* the engine did not say which rule */
      FlowRuleProxy(55, 5, t, 128); CHECK(!wcscmp(t, L"Burp (SOCKS5 127.0.0.1:1080)"));                     /* a rule that is gone from the profile */
      FlowRuleProxy(21, 0, t, 128); CHECK(!wcscmp(t, L"Browsers : Burp (SOCKS5 127.0.0.1:1080)"));          /* proxy id 0 = the first proxy */
      FlowText(&g_fl[r], 5, now, t, 128); CHECK(!wcscmp(t, L"2.0 KB"));
      FlowText(&g_fl[r], 6, now, t, 128); CHECK(!wcscmp(t, L"5.0 MB"));
      for (int i = 0; i < g_flN; i++)
      {
          if (g_fl[i].id == 12) { FlowText(&g_fl[i], 2, now, t, 128); CHECK(!wcscmp(t, L"UDP")); FlowText(&g_fl[i], 3, now, t, 128); CHECK(!wcscmp(t, L"0:00")); FlowText(&g_fl[i], 6, now, t, 128); CHECK(!wcscmp(t, L"900 B")); }
          if (g_fl[i].id == 13) { FlowText(&g_fl[i], 0, now, t, 128); CHECK(!wcscmp(t, L"PID 9")); FlowText(&g_fl[i], 1, now, t, 128); CHECK(!wcscmp(t, L"[2606:4700::1111]:443")); FlowText(&g_fl[i], 4, now, t, 128); CHECK(!wcscmp(t, L"#99")); }
      }

      /* the list control asks for text on demand (virtual list: it keeps no text itself) */
      { NMLVDISPINFOW di; ZeroMemory(&di, sizeof di); wchar_t buf[64] = L"";
        di.hdr.hwndFrom = g_hFlows; di.hdr.idFrom = IDC_FLOWS; di.hdr.code = LVN_GETDISPINFOW;
        di.item.mask = LVIF_TEXT; di.item.iItem = 0; di.item.iSubItem = 1; di.item.pszText = buf; di.item.cchTextMax = 64;
        SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&di);
        CHECK(wcslen(buf) > 0 && wcschr(buf, L':') != NULL);
        di.item.iItem = 999; buf[0] = L'x'; SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&di); CHECK(buf[0] == 0);   /* out of range: empty, no crash */
        di.item.iItem = 0; di.item.iSubItem = 50; buf[0] = L'x'; SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&di); CHECK(buf[0] == 0); }

      /* newest first by default; clicking a header sorts by it, clicking again reverses */
      CHECK(g_fl[g_flView[0]].id == 13 || g_fl[g_flView[0]].firstSeen >= g_fl[g_flView[g_flN - 1]].firstSeen);
      { NMLISTVIEW nm; ZeroMemory(&nm, sizeof nm); nm.hdr.hwndFrom = g_hFlows; nm.hdr.idFrom = IDC_FLOWS; nm.hdr.code = LVN_COLUMNCLICK; nm.iSubItem = 1;
        SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&nm);                                       /* by target, ascending */
        CHECK(_stricmp(g_fl[g_flView[0]].host, g_fl[g_flView[1]].host) <= 0 && _stricmp(g_fl[g_flView[1]].host, g_fl[g_flView[2]].host) <= 0);
        SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&nm);                                       /* reversed */
        CHECK(_stricmp(g_fl[g_flView[0]].host, g_fl[g_flView[1]].host) >= 0 && _stricmp(g_fl[g_flView[1]].host, g_fl[g_flView[2]].host) >= 0);
        nm.iSubItem = 6; SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&nm);                      /* by received: biggest first */
        CHECK(g_fl[g_flView[0]].received >= g_fl[g_flView[1]].received && g_fl[g_flView[1]].received >= g_fl[g_flView[2]].received); }

      /* a flow that disappears turns grey and stays listed until "Clear closed" */
      PBFlow keep[2]; keep[0] = s[1]; keep[1] = s[2];
      FlowsApply(keep, 2, FALSE, now + 2000);
      CHECK(g_flN == 3);
      r = -1; for (int i = 0; i < g_flN; i++) if (g_fl[i].id == 11) r = i;
      CHECK(r >= 0 && g_fl[r].closedAt == now + 2000);
      FlowText(&g_fl[r], 3, now + 2000, t, 128); CHECK(!wcscmp(t, L"Closed 1:07"));                    /* total life, frozen */
      { int vi = -1; for (int i = 0; i < g_flN; i++) if (g_flView[i] == r) vi = i;
        NMLVCUSTOMDRAW cd; ZeroMemory(&cd, sizeof cd);
        cd.nmcd.hdr.hwndFrom = g_hFlows; cd.nmcd.hdr.idFrom = IDC_FLOWS; cd.nmcd.hdr.code = NM_CUSTOMDRAW;
        cd.nmcd.dwDrawStage = CDDS_PREPAINT; CHECK(SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&cd) == CDRF_NOTIFYITEMDRAW);
        cd.nmcd.dwDrawStage = CDDS_ITEMPREPAINT; cd.nmcd.dwItemSpec = (DWORD_PTR)vi; cd.clrText = RGB(1, 2, 3);
        SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&cd); CHECK(cd.clrText == RGB(128, 128, 128));   /* finished: grey */
        cd.nmcd.dwItemSpec = (DWORD_PTR)((vi + 1) % g_flN); cd.clrText = RGB(1, 2, 3);
        SendMessageW(g_hMain, WM_NOTIFY, IDC_FLOWS, (LPARAM)&cd); CHECK(cd.clrText == RGB(1, 2, 3)); }       /* live rows keep the theme colour */
      FlowsApply(keep, 2, FALSE, now + 3600000);                                                        /* an hour later: still there */
      CHECK(g_flN == 3 && g_fl[r].id == 11 && g_fl[r].closedAt == now + 2000);
      SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDC_FLOWS_CLEAR, BN_CLICKED), (LPARAM)g_hFlowsClear);   /* Clear closed */
      CHECK(g_flN == 2 && ListView_GetItemCount(g_hFlows) == 2);
      for (int i = 0; i < g_flN; i++) CHECK(g_fl[i].id != 11 && g_fl[i].closedAt == 0);                 /* live rows stay */
      now += 3600000;

      /* a truncated snapshot (more flows than were returned) never marks the missing ones as finished */
      PBFlow only[1]; only[0] = s[1];
      FlowsApply(only, 1, TRUE, now + 20000);
      for (int i = 0; i < g_flN; i++) CHECK(g_fl[i].closedAt == 0);
      FlowsApply(only, 1, FALSE, now + 21000);
      { int closed = 0; for (int i = 0; i < g_flN; i++) closed += g_fl[i].closedAt != 0; CHECK(closed == 1); }

      /* an idle UDP flow that wakes up again is a live row again with a fresh start */
      FlowsApply(s + 2, 1, FALSE, now + 22000);
      for (int i = 0; i < g_flN; i++) if (g_fl[i].id == 12) CHECK(g_fl[i].closedAt != 0);
      s[1].age_ms = 0xFFFFFFFFu;
      FlowsApply(s + 1, 1, FALSE, now + 23000);
      for (int i = 0; i < g_flN; i++) if (g_fl[i].id == 12) CHECK(g_fl[i].closedAt == 0 && g_fl[i].firstSeen == now + 23000);

      /* the engine/pipe going away (nothing returned) greys everything instead of crashing */
      g_stubN = 0; FlowsPoll();
      for (int i = 0; i < g_flN; i++) CHECK(g_fl[i].closedAt != 0);
    }

    /* memory stays bounded however many flows come and go */
    { PBFlow* big = (PBFlow*)calloc(400, sizeof(PBFlow));
      for (int round = 0; round < 6; round++)
      {
          for (int i = 0; i < 400; i++) MkFlow(&big[i], 1000 + round * 400 + i, 1, "x.exe", "h", 80, 0, 0, 10, 1, 1, 1);
          FlowsApply(big, 400, TRUE, GetTickCount64());
      }
      CHECK(g_flN <= FLOW_ROWS_MAX && g_flView != NULL);
      FlowsApply(big, 0, FALSE, GetTickCount64() + 1000);                                               /* everything finishes ... */
      for (int i = 0; i < g_flN; i++) CHECK(g_fl[i].closedAt != 0);
      for (int i = 0; i < 400; i++) MkFlow(&big[i], 90000 + i, 1, "new.exe", "h", 80, 0, 0, 10, 1, 1, 1);
      FlowsApply(big, 400, FALSE, GetTickCount64() + 2000);                                             /* ... and new ones replace the oldest finished */
      { int found = 0; for (int i = 0; i < g_flN; i++) if (g_fl[i].id >= 90000 && g_fl[i].closedAt == 0) found++; CHECK(found == 400 && g_flN <= FLOW_ROWS_MAX); }
      free(big); }

    /* the column titles follow the language */
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_LANG_ZH, 0), 0);
    { TCITEMW ti; wchar_t tx[64]; ti.mask = TCIF_TEXT; ti.pszText = tx; ti.cchTextMax = 64;
      CHECK(TabCtrl_GetItem(g_hTab, 2, &ti) && !wcscmp(tx, T(S_TAB_FLOWS)) && wcscmp(tx, L"Live Connections") != 0);
      HWND hd = ListView_GetHeader(g_hFlows); HDITEMW hi; wchar_t col[64]; hi.mask = HDI_TEXT; hi.pszText = col; hi.cchTextMax = 64;
      CHECK(Header_GetItem(hd, 0, &hi) && !wcscmp(col, T(S_FL_COL_APP))); }
    SendMessageW(g_hMain, WM_COMMAND, MAKEWPARAM(IDM_LANG_EN, 0), 0);

    /* leaving the tab stops polling and frees the snapshot buffer; the rows are kept, everything marked finished */
    SelectTab(0);
    CHECK(!IsWindowVisible(g_hFlows) && !IsWindowVisible(g_hFlowsClear) && g_flSnap == NULL && g_flN > 0);
    for (int i = 0; i < g_flN; i++) CHECK(g_fl[i].closedAt != 0);
    { UINT64 id0 = g_fl[0].id; PBFlow one; MkFlow(&one, id0, 5, "back.exe", "h", 1, 0, 0, 1000, 1, 1, 1); memcpy(g_stubFlows, &one, sizeof one); g_stubN = 1;
      SelectTab(2); PumpFlows();                                                                       /* coming back: a connection still running is live again */
      int alive = 0; for (int i = 0; i < g_flN; i++) alive += g_fl[i].closedAt == 0; CHECK(alive == 1 && IsWindowVisible(g_hFlowsClear));
      SelectTab(0); }
    { int c = g_stubCalls; MSG m; while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m); CHECK(g_stubCalls == c); }

    /* closing the tab while a poll is still out: the result is dropped and the buffer freed, nothing is left running */
    SelectTab(2); SelectTab(0); PumpFlows();
    CHECK(g_flBusy == 0 && g_flSnap == NULL && !g_flActive);
    { int c = g_stubCalls; MSG m; Sleep(1200); while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageW(&m); CHECK(g_stubCalls == c); }   /* the timer is off */

    TrayRemove();
    DestroyWindow(g_hMain);
    return pbtest_done("test_main_ui");
}
