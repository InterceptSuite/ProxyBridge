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

    TrayRemove();
    DestroyWindow(g_hMain);
    return pbtest_done("test_main_ui");
}
