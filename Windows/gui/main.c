// ProxyBridge GUI.
//
// Drives ProxyBridgeCore.dll and reads/writes %APPDATA%\ProxyBridge settings.json +
// *.pbprofile files.
//
// Threading: DLL log/connection callbacks fire on native threads; each formats a line and
// PostMessage()s a heap wide-string to the UI thread, which appends it and frees it.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <windowsx.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <stdio.h>
#include <stdlib.h>
#include "res/resource.h"
#include "api/pb_api.h"
#include "profile/profile.h"
#include "loc/loc.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")

// dark theme
#define C_BG      RGB(0x1E, 0x1E, 0x1E)   // window / edit background
#define C_PANEL   RGB(0x25, 0x25, 0x26)   // strip background
#define C_TEXT    RGB(0xD4, 0xD4, 0xD4)
#define C_DIM     RGB(0x8A, 0x8A, 0x8A)
#define C_TAB     RGB(0x2D, 0x2D, 0x30)   // inactive tab
#define C_TABSEL  RGB(0x1E, 0x1E, 0x1E)   // active tab (matches content)
#define C_TABHOT  RGB(0x3E, 0x3E, 0x42)   // hovered tab
#define C_ACCENT  RGB(0x00, 0x7A, 0xCC)   // active-tab top strip
#define C_MENU    RGB(0x2D, 0x2D, 0x30)
#define C_MENUHOT RGB(0x3E, 0x3E, 0x46)
#define C_LINE    RGB(0x3F, 0x3F, 0x46)
#define C_WARN    RGB(0xD7, 0xA5, 0x22)   // amber hint for the UDP note

static HBRUSH g_brBg, g_brPanel, g_brTab, g_brTabSel, g_brTabHot, g_brAccent, g_brMenu, g_brMenuHot;
static int    g_tabHot = -1;   // hovered tab index (owner-draw)

// Undocumented immersive-menu messages (as used by Windows Terminal's dark-mode shim).
#define WM_UAHDRAWMENU     0x0091
#define WM_UAHDRAWMENUITEM 0x0092
typedef union { struct { DWORD cx, cy; } rgsizeBar[2]; struct { DWORD cx, cy; } rgsizePopup[4]; } UAHMENUITEMMETRICS;
typedef struct { DWORD rgcx[4]; DWORD fUpdateMaxWidths : 2; } UAHMENUPOPUPMETRICS;
typedef struct { HMENU hmenu; HDC hdc; DWORD dwFlags; } UAHMENU;
typedef struct { int iPosition; UAHMENUITEMMETRICS umim; UAHMENUPOPUPMETRICS umpm; } UAHMENUITEM;
typedef struct { DRAWITEMSTRUCT dis; UAHMENU um; UAHMENUITEM umi; } UAHDRAWMENUITEM;

// uxtheme.dll dark-mode ordinals (1903+). Loaded dynamically.
typedef enum { APPMODE_DEFAULT, APPMODE_ALLOWDARK, APPMODE_FORCEDARK, APPMODE_FORCELIGHT, APPMODE_MAX } PreferredAppMode;
typedef PreferredAppMode (WINAPI *fnSetPreferredAppMode)(PreferredAppMode);
typedef BOOL (WINAPI *fnAllowDarkModeForWindow)(HWND, BOOL);
typedef void (WINAPI *fnFlushMenuThemes)(void);

#define WM_APP_LOG   (WM_APP + 1)
#define WM_APP_CONN  (WM_APP + 2)
#define WM_APP_TRAY  (WM_APP + 3)
#define WM_APP_TESTLINE (WM_APP + 4)   // proxy-checker worker -> one log line
#define WM_APP_TESTDONE (WM_APP + 5)   // proxy-checker worker -> testing finished

#define APP_TITLE     L"ProxyBridge"
#define WND_CLASS     L"ProxyBridgeNativeMainWnd"
#define MAX_LOG_CHARS 60000

// globals
static PBApi     g_api;
static HWND      g_hMain, g_hTab, g_hConnLog, g_hActLog;
static HWND      g_hConnSearch, g_hConnClear, g_hActSearch, g_hActClear;
static HFONT     g_hIcon;                 // Segoe MDL2 Assets glyph font for the menu-bar icons
static HFONT     g_hMenuFont;             // menu-bar font (owner-drawn top items => taller bar)
static RECT      g_rcTbSet, g_rcTbRules;  // menu-bar icon hit-rects (window-relative)
static int       g_tbHot = -1;            // hovered menu-bar icon: 0 = settings, 1 = rules
#define MENUBAR_EXTRA 12                  // extra height added to the menu row
#define IDC_CONN_SEARCH 3001
#define IDC_CONN_CLEAR  3002
#define IDC_ACT_SEARCH  3003
#define IDC_ACT_CLEAR   3004

// Per-log line store so the search box can filter without losing lines. New lines append to
// the edit only when they match the active filter; changing the filter re-renders from here.
#define LOG_MAX_LINES 4000
#define LOG_PEND_MAX  8000
typedef struct {
    HWND     edit;
    wchar_t* lines[LOG_MAX_LINES];
    int      count;
    wchar_t  filter[128];
    wchar_t* pend[LOG_PEND_MAX];   // queued by native callback threads, drained by the UI timer
    int      pendCount;
    CRITICAL_SECTION lock;
} LogStore;
static LogStore g_connStore, g_actStore;
#define TIMER_LOG 1                // batched log-flush timer
static int g_idleTicks = 0;        // consecutive idle flushes (for working-set trim)
static HFONT     g_hMono, g_hUi;
static HINSTANCE g_hInst;
static NOTIFYICONDATAW g_tray;
static BOOL      g_trayAdded = FALSE;
static UINT      g_wmTaskbarCreated = 0;   // shell broadcast when the taskbar reappear
static BOOL      g_reallyExit = FALSE;
static BOOL      g_started = FALSE;

static PBProfile g_profile;
static wchar_t   g_activeProfile[PB_NAME_MAX] = L"Default";
static BOOL      g_localhost = FALSE, g_trafficLog = TRUE, g_closeToTray = TRUE;
static BOOL      g_startup = FALSE;   // "Run at Startup" (schtasks logon task)
static BOOL      g_autoClear = TRUE;  // auto-clear logs past a line threshold to save memory
#define AUTO_CLEAR_LINES 500
static PBFilter  g_flt[PB_MAX_FILTER];  // connection-log filter snapshot (read by native cb)
static int       g_fltCount = 0;

static wchar_t   g_profNames[64][PB_NAME_MAX];
static int       g_profCount = 0;
static wchar_t   g_nameResult[PB_NAME_MAX];
static HMENU     g_switchMenu = NULL;   // the Profile > Switch submenu (rebuilt on demand)

// small helpers
static void W2Ux(const wchar_t* w, char* out, int cch)
{ WideCharToMultiByte(CP_UTF8, 0, w ? w : L"", -1, out, cch, NULL, NULL); }

static wchar_t* U2Wdup(const char* s)
{
    if (!s) s = "";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t* w = (wchar_t*)malloc((size_t)n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static int ProtoIdx(const wchar_t* s)  { if (!_wcsicmp(s, L"UDP")) return 1; if (!_wcsicmp(s, L"BOTH")) return 2; return 0; }
static int ActionIdx(const wchar_t* s) { if (!_wcsicmp(s, L"DIRECT")) return 1; if (!_wcsicmp(s, L"BLOCK")) return 2; return 0; }
static const wchar_t* ProtoName(int i)  { return i == 1 ? L"UDP" : i == 2 ? L"BOTH" : L"TCP"; }

// log panel + connection filters (split out)
#include "ui/logview.h"

// forward decls
static void SaveActive(void);
static UINT32 ResolveNativeCfg(UINT32 storedId);
static void ApplyConfigs(void);
static void ApplyRules(void);
static void UnapplyProfile(void);
static void SwitchToProfile(const wchar_t* name);
static void RebuildProfileMenu(HWND hwnd);
static void UpdateTitle(void);
static void SyncMenuChecks(HWND hwnd);
static void BuildMainMenu(HWND hwnd);
static void RelocalizeUI(HWND hwnd);
static UINT32 EngineAddRule(PBRule* r);
static void EngineEditRule(PBRule* r);
INT_PTR CALLBACK ServersDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK ServerEditDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK RulesDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK RuleEditDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK FiltersDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK FilterEditDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK NameDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK AboutDlgProc(HWND, UINT, WPARAM, LPARAM);

// DLL callbacks (native thread)
static void PBLogCb(const char* message)
{
    if (!g_hMain) return;
    wchar_t* body = U2Wdup(message);
    if (!body) return;
    wchar_t ts[16]; GetTimePrefix(ts, 16);
    size_t n = wcslen(ts) + wcslen(body) + 3;
    wchar_t* line = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (line) { _snwprintf_s(line, n, _TRUNCATE, L"%s%s\r\n", ts, body); LogStoreQueue(&g_actStore, line); }
    free(body);
}

static void PBConnCb(const char* proc, DWORD pid, const char* ip, unsigned short port, const char* info)
{
    if (!g_hMain || !g_trafficLog) return;
    wchar_t *wp = U2Wdup(proc), *wi = U2Wdup(ip), *wf = U2Wdup(info);
    // Connection-log filters: derive protocol/action from the proxy_info and drop non-matches.
    if (g_fltCount > 0)
    {
        wchar_t wport[16]; _snwprintf_s(wport, 16, _TRUNCATE, L"%u", port);
        const wchar_t* proto  = (info && strstr(info, "(UDP)")) ? L"UDP" : L"TCP";
        const wchar_t* action = (info && _strnicmp(info, "Direct", 6) == 0) ? L"Direct"
                              : (info && _strnicmp(info, "Block",  5) == 0) ? L"Blocked" : L"Proxy";
        if (!PassesLogFilters(wp ? wp : L"", wi ? wi : L"", wport, proto, action))
        { free(wp); free(wi); free(wf); return; }
    }
    wchar_t ts[16]; GetTimePrefix(ts, 16);
    size_t n = 64 + (wp ? wcslen(wp) : 0) + (wi ? wcslen(wi) : 0) + (wf ? wcslen(wf) : 0);
    wchar_t* line = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (line)
    {
        _snwprintf_s(line, n, _TRUNCATE, L"%s%s (PID:%lu) -> %s:%u  via %s\r\n",
                   ts, wp ? wp : L"?", pid, wi ? wi : L"?", port, wf ? wf : L"?");
        LogStoreQueue(&g_connStore, line);
    }
    free(wp); free(wi); free(wf);
}

// profile apply / persist
static void SaveActive(void) { PB_ProfileSave(g_activeProfile, &g_profile); }

static UINT32 ResolveNativeCfg(UINT32 storedId)
{
    for (int i = 0; i < g_profile.cfgCount; i++)
        if (g_profile.cfg[i].storedId == storedId) return g_profile.cfg[i].nativeId;
    return 0; // 0 => DLL uses first available config
}

static void ApplyConfigs(void)
{
    for (int i = 0; i < g_profile.cfgCount; i++)
    {
        PBConfig* c = &g_profile.cfg[i];
        int type = (_wcsicmp(c->type, L"HTTP") == 0) ? PB_PROXY_HTTP : PB_PROXY_SOCKS5;
        char h[256], u[256], p[256];
        W2Ux(c->host, h, sizeof(h)); W2Ux(c->user, u, sizeof(u)); W2Ux(c->pass, p, sizeof(p));
        c->nativeId = g_api.AddProxyConfig((PBProxyType)type, h, (unsigned short)_wtoi(c->port), u, p, c->sendDomain ? TRUE : FALSE);
        if (c->storedId == 0) c->storedId = c->nativeId;
    }
}

static void ApplyRules(void)
{
    for (int i = 0; i < g_profile.ruleCount; i++)
    {
        PBRule* r = &g_profile.rule[i];
        char proc[2048], hosts[512], ports[256], domains[512];
        W2Ux(r->proc, proc, sizeof(proc)); W2Ux(r->hosts, hosts, sizeof(hosts));
        W2Ux(r->ports, ports, sizeof(ports)); W2Ux(r->domains, domains, sizeof(domains));
        r->nativeId = g_api.AddRule(proc, hosts, ports, domains,
                                    (PBRuleProtocol)ProtoIdx(r->proto), (PBRuleAction)ActionIdx(r->action),
                                    ResolveNativeCfg(r->cfgStoredId));
        if (r->nativeId && !r->enabled) g_api.DisableRule(r->nativeId);
    }
}

// Add one rule to the engine, returning its (stable) native id. Enable state applied too.
static UINT32 EngineAddRule(PBRule* r)
{
    char proc[2048], hosts[512], ports[256], domains[512];
    W2Ux(r->proc, proc, sizeof(proc)); W2Ux(r->hosts, hosts, sizeof(hosts));
    W2Ux(r->ports, ports, sizeof(ports)); W2Ux(r->domains, domains, sizeof(domains));
    UINT32 id = g_api.AddRule(proc, hosts, ports, domains,
                              (PBRuleProtocol)ProtoIdx(r->proto), (PBRuleAction)ActionIdx(r->action),
                              ResolveNativeCfg(r->cfgStoredId));
    if (id && !r->enabled) g_api.DisableRule(id);
    return id;
}
// Edit an existing rule in place - keeps the same native id and list position.
static void EngineEditRule(PBRule* r)
{
    char proc[2048], hosts[512], ports[256], domains[512];
    W2Ux(r->proc, proc, sizeof(proc)); W2Ux(r->hosts, hosts, sizeof(hosts));
    W2Ux(r->ports, ports, sizeof(ports)); W2Ux(r->domains, domains, sizeof(domains));
    g_api.EditRule(r->nativeId, proc, hosts, ports, domains,
                   (PBRuleProtocol)ProtoIdx(r->proto), (PBRuleAction)ActionIdx(r->action),
                   ResolveNativeCfg(r->cfgStoredId));
    if (r->enabled) g_api.EnableRule(r->nativeId); else g_api.DisableRule(r->nativeId);
}

static void UnapplyProfile(void)
{
    for (int i = 0; i < g_profile.ruleCount; i++) if (g_profile.rule[i].nativeId) g_api.DeleteRule(g_profile.rule[i].nativeId);
    for (int i = 0; i < g_profile.cfgCount; i++) if (g_profile.cfg[i].nativeId) g_api.DeleteProxyConfig(g_profile.cfg[i].nativeId);
}

static void SwitchToProfile(const wchar_t* name)
{
    UnapplyProfile();
    PB_SetActiveProfile(name);
    lstrcpynW(g_activeProfile, name, PB_NAME_MAX);
    PB_ProfileLoad(name, &g_profile);
    g_localhost = g_profile.localhostViaProxy;
    g_trafficLog = g_profile.trafficLogging;
    g_closeToTray = g_profile.closeToTray;
    g_autoClear = g_profile.autoClearLogs;
    ApplyFilterSnapshot();
    g_api.SetLocalhostViaProxy(g_localhost);
    g_api.SetTrafficLoggingEnabled(g_trafficLog);
    ApplyConfigs();
    ApplyRules();
    SyncMenuChecks(g_hMain);
    RebuildProfileMenu(g_hMain);
    UpdateTitle();
}

static void UpdateTitle(void)
{
    wchar_t t[128]; _snwprintf_s(t, 128, _TRUNCATE, L"%s - %s", APP_TITLE, g_activeProfile);
    SetWindowTextW(g_hMain, t);
}

// Add an owner-drawn top-level menu item (so the menu row can be taller). The label pointer
// (a stable T() string) is kept as item data (for WM_DRAWITEM) and as the string (so Alt
// mnemonics still work).
static void AppendTopMenu(HMENU bar, HMENU sub, const wchar_t* label)
{
    MENUITEMINFOW mii; ZeroMemory(&mii, sizeof(mii)); mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_FTYPE | MIIM_SUBMENU | MIIM_DATA | MIIM_STRING;
    mii.fType = MFT_OWNERDRAW;
    mii.hSubMenu = sub;
    mii.dwItemData = (ULONG_PTR)label;
    mii.dwTypeData = (LPWSTR)label;
    mii.cch = (UINT)lstrlenW(label);
    InsertMenuItemW(bar, GetMenuItemCount(bar), TRUE, &mii);
}

// Builds the whole menu bar from the string table so a language switch can rebuild it live.
static void BuildMainMenu(HWND hwnd)
{
    HMENU bar = CreateMenu();

    HMENU proxy = CreatePopupMenu();
    AppendMenuW(proxy, MF_STRING, IDM_PROXY_SETTINGS, T(S_M_PROXY_SETTINGS));
    AppendMenuW(proxy, MF_STRING, IDM_PROXY_RULES,    T(S_M_PROXY_RULES));
    AppendMenuW(proxy, MF_STRING, IDM_LOG_FILTERS,    T(S_M_LOGFILTERS));
    AppendTopMenu(bar, proxy, T(S_M_PROXY));

    HMENU profile = CreatePopupMenu();
    AppendMenuW(profile, MF_STRING, IDM_PROFILE_NEW,    T(S_M_NEWPROFILE));
    AppendMenuW(profile, MF_STRING, IDM_PROFILE_RENAME, T(S_M_RENAME));
    AppendMenuW(profile, MF_STRING, IDM_PROFILE_DELETE, T(S_M_DELPROFILE));
    AppendMenuW(profile, MF_SEPARATOR, 0, NULL);
    AppendMenuW(profile, MF_STRING, IDM_PROFILE_IMPORT, T(S_M_IMPORT));
    AppendMenuW(profile, MF_STRING, IDM_PROFILE_EXPORT, T(S_M_EXPORT));
    AppendMenuW(profile, MF_SEPARATOR, 0, NULL);
    g_switchMenu = CreatePopupMenu();
    AppendMenuW(profile, MF_POPUP, (UINT_PTR)g_switchMenu, T(S_M_SWITCH));
    AppendTopMenu(bar, profile, T(S_M_PROFILE));

    HMENU settings = CreatePopupMenu();
    AppendMenuW(settings, MF_STRING, IDM_SET_LOCALHOST,   T(S_M_LOCALHOST));
    AppendMenuW(settings, MF_STRING, IDM_SET_TRAFFICLOG,  T(S_M_TRAFFIC));
    AppendMenuW(settings, MF_STRING, IDM_SET_CLOSETOTRAY, T(S_M_TRAY));
    AppendMenuW(settings, MF_STRING, IDM_SET_STARTUP,     T(S_M_STARTUP));
    AppendMenuW(settings, MF_STRING, IDM_SET_AUTOCLEAR,   T(S_M_AUTOCLEAR));
    AppendMenuW(settings, MF_SEPARATOR, 0, NULL);
    HMENU lang = CreatePopupMenu();
    AppendMenuW(lang, MF_STRING, IDM_LANG_EN, T(S_M_LANG_EN));
    AppendMenuW(lang, MF_STRING, IDM_LANG_ZH, T(S_M_LANG_ZH));
    AppendMenuW(settings, MF_POPUP, (UINT_PTR)lang, T(S_M_LANG));
    AppendTopMenu(bar, settings, T(S_M_SETTINGS));

    HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, IDM_HELP_DOCS,   T(S_M_DOCS));
    AppendMenuW(help, MF_STRING, IDM_HELP_UPDATE, T(S_M_UPDATE));
    AppendMenuW(help, MF_SEPARATOR, 0, NULL);
    AppendMenuW(help, MF_STRING, IDM_HELP_ABOUT,  T(S_M_ABOUT));
    AppendTopMenu(bar, help, T(S_M_HELP));

    HMENU old = GetMenu(hwnd);
    SetMenu(hwnd, bar);
    if (old) DestroyMenu(old);
}

static void RebuildProfileMenu(HWND hwnd)
{
    if (!g_switchMenu) return;
    while (GetMenuItemCount(g_switchMenu) > 0) DeleteMenu(g_switchMenu, 0, MF_BYPOSITION);
    g_profCount = PB_ProfileList(g_profNames, 64);
    for (int i = 0; i < g_profCount; i++)
    {
        UINT flags = MF_STRING | (_wcsicmp(g_profNames[i], g_activeProfile) == 0 ? MF_CHECKED : 0);
        AppendMenuW(g_switchMenu, flags, (UINT_PTR)(IDM_PROFILE_SWITCH_BASE + i), g_profNames[i]);
    }
    if (g_profCount == 0) AppendMenuW(g_switchMenu, MF_STRING | MF_GRAYED, IDM_PROFILE_SWITCH_BASE, L"-");
    DrawMenuBar(hwnd);
}

// Rebuild everything that carries text after a language change.
static void RelocalizeUI(HWND hwnd)
{
    BuildMainMenu(hwnd);
    RebuildProfileMenu(hwnd);
    SyncMenuChecks(hwnd);
    TCITEMW ti; ti.mask = TCIF_TEXT;
    ti.pszText = (LPWSTR)T(S_TAB_CONN); TabCtrl_SetItem(g_hTab, 0, &ti);
    ti.pszText = (LPWSTR)T(S_TAB_ACT);  TabCtrl_SetItem(g_hTab, 1, &ti);
    // The tab strip, the Clear buttons and the search cue banners all carry localized
    // text too - refresh them here so a language switch updates them without a restart.
    SetWindowTextW(g_hConnClear, T(S_BTN_CLEARLOGS));
    SetWindowTextW(g_hActClear,  T(S_BTN_CLEARLOGS));
    SendMessageW(g_hConnSearch, EM_SETCUEBANNER, TRUE, (LPARAM)T(S_SEARCH_CUE));
    SendMessageW(g_hActSearch,  EM_SETCUEBANNER, TRUE, (LPARAM)T(S_SEARCH_CUE));
    InvalidateRect(g_hTab, NULL, TRUE);
    UpdateTitle();
    DrawMenuBar(hwnd);
}

// single-instance + Run at Startup (split out)
#include "ui/startup.h"

// tray / layout / menu-checks
static void TrayAdd(HWND hwnd)
{
    ZeroMemory(&g_tray, sizeof(g_tray));
    g_tray.cbSize = sizeof(g_tray);
    g_tray.hWnd = hwnd; g_tray.uID = 1;
    g_tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_tray.uCallbackMessage = WM_APP_TRAY;
    g_tray.hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                     GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    lstrcpynW(g_tray.szTip, APP_TITLE, ARRAYSIZE(g_tray.szTip));
    // NIM_ADD fails if the shell's tray is not ready yet
    // broadcast re-adds the icon once the taskbar actually appears
    g_trayAdded = Shell_NotifyIconW(NIM_ADD, &g_tray);
}
static void TrayRemove(void) { if (g_trayAdded) { Shell_NotifyIconW(NIM_DELETE, &g_tray); g_trayAdded = FALSE; } }
static void ShowMainWindow(HWND hwnd) { ShowWindow(hwnd, SW_SHOW); ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); }

static void LayoutMain(HWND hwnd)
{
    RECT rc; GetClientRect(hwnd, &rc);
    int tabTop = 6, tabH = 32;               // small gap below the menu bar
    MoveWindow(g_hTab, 0, tabTop, rc.right, tabH, TRUE);
    int top = tabTop + tabH + 6;
    int barH = 30, clearW = 130, gap = 6;
    int searchW = rc.right - 4 - clearW - gap - 4;
    int logTop = top + barH + 4;
    int logH = rc.bottom - logTop - 4; if (logH < 0) logH = 0;
    // search box + Clear button row, then the log below (both tabs share the same rect)
    MoveWindow(g_hConnSearch, 4, top, searchW, barH - 6, TRUE);
    MoveWindow(g_hActSearch,  4, top, searchW, barH - 6, TRUE);
    MoveWindow(g_hConnClear,  4 + searchW + gap, top - 1, clearW, barH - 2, TRUE);
    MoveWindow(g_hActClear,   4 + searchW + gap, top - 1, clearW, barH - 2, TRUE);
    MoveWindow(g_hConnLog, 2, logTop, rc.right - 4, logH, TRUE);
    MoveWindow(g_hActLog,  2, logTop, rc.right - 4, logH, TRUE);
}
static void SelectTab(int idx)
{
    int c = (idx == 0) ? SW_SHOW : SW_HIDE;
    int a = (idx == 1) ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hConnLog, c); ShowWindow(g_hConnSearch, c); ShowWindow(g_hConnClear, c);
    ShowWindow(g_hActLog,  a); ShowWindow(g_hActSearch,  a); ShowWindow(g_hActClear,  a);
}
static void SyncMenuChecks(HWND hwnd)
{
    HMENU m = GetMenu(hwnd);
    CheckMenuItem(m, IDM_SET_LOCALHOST,   MF_BYCOMMAND | (g_localhost  ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(m, IDM_SET_TRAFFICLOG,  MF_BYCOMMAND | (g_trafficLog ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(m, IDM_SET_CLOSETOTRAY, MF_BYCOMMAND | (g_closeToTray? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(m, IDM_SET_STARTUP,     MF_BYCOMMAND | (g_startup    ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(m, IDM_SET_AUTOCLEAR,   MF_BYCOMMAND | (g_autoClear  ? MF_CHECKED : MF_UNCHECKED));
    int zh = (_wcsicmp(g_profile.language, L"zh") == 0);
    CheckMenuItem(m, IDM_LANG_EN, MF_BYCOMMAND | (zh ? MF_UNCHECKED : MF_CHECKED));
    CheckMenuItem(m, IDM_LANG_ZH, MF_BYCOMMAND | (zh ? MF_CHECKED : MF_UNCHECKED));
}

// file dialogs
static BOOL PickFile(HWND owner, BOOL save, wchar_t* path, int cch)
{
    OPENFILENAMEW ofn; ZeroMemory(&ofn, sizeof(ofn));
    path[0] = 0;
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"ProxyBridge Profile (*.pbprofile)\0*.pbprofile\0All Files\0*.*\0";
    ofn.lpstrFile = path; ofn.nMaxFile = cch;
    ofn.lpstrDefExt = L"pbprofile";
    ofn.Flags = save ? (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST)
                     : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST);
    return save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
}

// dark theme helpers (split out)
#include "ui/theme.h"
// update checker (split out)
#include "ui/update.h"

// Fully paints the (non-client, owner-drawn) menu bar dark: fills the bar, redraws each
// top-item label, and draws the two quick-access glyph icons right after the last item.
// Records the icon rects for hit-testing. Called on WM_NCPAINT / WM_NCACTIVATE / WM_SIZE.
static void DrawMenuBar2(HWND hwnd)
{
    if (!g_hMenuFont) return;
    HMENU bar = GetMenu(hwnd);
    MENUBARINFO mbi; mbi.cbSize = sizeof(mbi);
    if (!bar || !GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mbi)) return;
    RECT wr; GetWindowRect(hwnd, &wr);
    RECT br = mbi.rcBar; OffsetRect(&br, -wr.left, -wr.top);
    int barH = br.bottom - br.top;
    if (barH <= 0) return;

    HDC dc = GetWindowDC(hwnd);
    FillRect(dc, &br, g_brMenu);                       // whole bar dark

    HFONT of = (HFONT)SelectObject(dc, g_hMenuFont);
    SetBkMode(dc, TRANSPARENT);
    int count = GetMenuItemCount(bar);
    int lastRight = br.left + 8;
    for (int i = 0; i < count; i++)
    {
        RECT ir; if (!GetMenuItemRect(hwnd, bar, i, &ir)) continue;
        OffsetRect(&ir, -wr.left, -wr.top);
        wchar_t txt[64] = {0};
        MENUITEMINFOW mii; mii.cbSize = sizeof(mii); mii.fMask = MIIM_STRING;
        mii.dwTypeData = txt; mii.cch = 64;
        GetMenuItemInfoW(bar, i, TRUE, &mii);
        SetTextColor(dc, C_TEXT);
        DrawTextW(dc, txt, -1, &ir, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_HIDEPREFIX);
        if (ir.right > lastRight) lastRight = ir.right;
    }

    int iw = barH;                                     // square icon cells
    int startX = lastRight + 10;
    SetRect(&g_rcTbSet,   startX,          br.top, startX + iw,          br.top + barH);
    SetRect(&g_rcTbRules, startX + iw + 2, br.top, startX + iw + 2 + iw, br.top + barH);
    SelectObject(dc, g_hIcon);
    const wchar_t* glyph[2] = { L"\xE713", L"\xE8FD" }; // gear, list
    RECT* r[2] = { &g_rcTbSet, &g_rcTbRules };
    for (int i = 0; i < 2; i++)
    {
        FillRect(dc, r[i], (g_tbHot == i) ? g_brMenuHot : g_brMenu);
        SetTextColor(dc, (g_tbHot == i) ? C_TEXT : C_DIM);
        DrawTextW(dc, glyph[i], -1, r[i], DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    SelectObject(dc, of);
    ReleaseDC(hwnd, dc);
}

// main window proc
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == g_wmTaskbarCreated && g_wmTaskbarCreated) { TrayAdd(hwnd); return 0; }

    switch (msg)
    {
    case WM_CREATE:
    {
        g_wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
        ChangeWindowMessageFilterEx(hwnd, g_wmTaskbarCreated, MSGFLT_ALLOW, NULL);
        g_hUi   = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hMono = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                              FIXED_PITCH | FF_MODERN, L"Consolas");
        g_hTab = CreateWindowExW(0, WC_TABCONTROLW, NULL,
                                 WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_OWNERDRAWFIXED,
                                 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
        SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hUi, TRUE);
        TCITEMW ti; ti.mask = TCIF_TEXT;
        ti.pszText = (LPWSTR)T(S_TAB_CONN); TabCtrl_InsertItem(g_hTab, 0, &ti);
        ti.pszText = (LPWSTR)T(S_TAB_ACT);  TabCtrl_InsertItem(g_hTab, 1, &ti);

        DWORD es = WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER;
        g_hConnLog = CreateWindowExW(0, L"EDIT", NULL, es | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
        g_hActLog  = CreateWindowExW(0, L"EDIT", NULL, es,               0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
        SendMessageW(g_hConnLog, WM_SETFONT, (WPARAM)g_hMono, TRUE);
        SendMessageW(g_hActLog,  WM_SETFONT, (WPARAM)g_hMono, TRUE);
        SendMessageW(g_hConnLog, EM_SETLIMITTEXT, MAX_LOG_CHARS * 2, 0);
        SendMessageW(g_hActLog,  EM_SETLIMITTEXT, MAX_LOG_CHARS * 2, 0);

        // Per-tab search box + Clear button, one set per log.
        DWORD ss = WS_CHILD | ES_AUTOHSCROLL;
        g_hConnSearch = CreateWindowExW(0, L"EDIT", NULL, ss, 0,0,0,0, hwnd, (HMENU)IDC_CONN_SEARCH, g_hInst, NULL);
        g_hActSearch  = CreateWindowExW(0, L"EDIT", NULL, ss, 0,0,0,0, hwnd, (HMENU)IDC_ACT_SEARCH,  g_hInst, NULL);
        g_hConnClear  = CreateWindowExW(0, L"BUTTON", T(S_BTN_CLEARLOGS), WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 0,0,0,0, hwnd, (HMENU)IDC_CONN_CLEAR, g_hInst, NULL);
        g_hActClear   = CreateWindowExW(0, L"BUTTON", T(S_BTN_CLEARLOGS), WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 0,0,0,0, hwnd, (HMENU)IDC_ACT_CLEAR,  g_hInst, NULL);
        SendMessageW(g_hConnSearch, WM_SETFONT, (WPARAM)g_hUi, TRUE);
        SendMessageW(g_hActSearch,  WM_SETFONT, (WPARAM)g_hUi, TRUE);
        SendMessageW(g_hConnClear,  WM_SETFONT, (WPARAM)g_hUi, TRUE);
        SendMessageW(g_hActClear,   WM_SETFONT, (WPARAM)g_hUi, TRUE);
        SendMessageW(g_hConnSearch, EM_SETCUEBANNER, TRUE, (LPARAM)T(S_SEARCH_CUE));
        SendMessageW(g_hActSearch,  EM_SETCUEBANNER, TRUE, (LPARAM)T(S_SEARCH_CUE));
        LogStoreInit(&g_connStore, g_hConnLog);
        LogStoreInit(&g_actStore,  g_hActLog);
        SetTimer(hwnd, TIMER_LOG, 200, NULL);   // batch log updates ~5x/sec

        // Menu-bar quick-access icons are drawn on the (non-client) menu bar in WM_NCPAINT;
        // this is their glyph font. The menu-bar font is used to owner-draw the top-level
        // items so the menu row can be a bit taller.
        g_hIcon = CreateFontW(-18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, L"Segoe MDL2 Assets");
        NONCLIENTMETRICSW ncm; ncm.cbSize = sizeof(ncm);
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
            g_hMenuFont = CreateFontIndirectW(&ncm.lfMenuFont);

        // Dark theme: elevate to immersive dark mode, dark scrollbars on the log edits,
        // and hover tracking for the owner-drawn tabs.
        InitDarkMode(hwnd);
        SetWindowTheme(g_hConnLog, L"DarkMode_Explorer", NULL);
        SetWindowTheme(g_hActLog,  L"DarkMode_Explorer", NULL);
        SetWindowTheme(g_hTab,     L"DarkMode_Explorer", NULL);
        SetWindowSubclass(g_hTab, TabSubProc, 1, 0);

        LayoutMain(hwnd); SelectTab(0);
        return 0;
    }
    case WM_SIZE:  LayoutMain(hwnd); DrawMenuBar2(hwnd); return 0;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORSTATIC:
    {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        return (LRESULT)g_brBg;
    }
    case WM_MEASUREITEM:
    {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lp;
        if (mis->CtlType == ODT_MENU)
        {
            const wchar_t* s = (const wchar_t*)mis->itemData;
            wchar_t clean[64]; int j = 0;                 // measure visible text (drop '&')
            for (const wchar_t* p = s; p && *p && j < 63; p++) if (*p != L'&') clean[j++] = *p;
            clean[j] = 0;
            HDC dc = GetDC(hwnd);
            HFONT of = (HFONT)SelectObject(dc, g_hMenuFont ? g_hMenuFont : g_hUi);
            SIZE sz = {0}; GetTextExtentPoint32W(dc, clean, j, &sz);
            TEXTMETRICW tm; GetTextMetricsW(dc, &tm);
            SelectObject(dc, of); ReleaseDC(hwnd, dc);
            mis->itemWidth  = sz.cx + 16;                 // tight, normal-looking padding
            mis->itemHeight = tm.tmHeight + MENUBAR_EXTRA; // taller row
            return TRUE;
        }
        break;
    }
    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT d = (LPDRAWITEMSTRUCT)lp;
        if (d->CtlType == ODT_MENU)   // hover state while a top menu is highlighted
        {
            const wchar_t* txt = (const wchar_t*)d->itemData;
            BOOL hot = (d->itemState & (ODS_SELECTED | ODS_HOTLIGHT)) != 0;
            FillRect(d->hDC, &d->rcItem, hot ? g_brMenuHot : g_brMenu);
            SetBkMode(d->hDC, TRANSPARENT);
            SetTextColor(d->hDC, C_TEXT);
            HFONT of = (HFONT)SelectObject(d->hDC, g_hMenuFont ? g_hMenuFont : g_hUi);
            UINT f = DT_CENTER | DT_VCENTER | DT_SINGLELINE;
            if (d->itemState & ODS_NOACCEL) f |= DT_HIDEPREFIX;
            DrawTextW(d->hDC, txt ? txt : L"", -1, &d->rcItem, f);
            SelectObject(d->hDC, of);
            return TRUE;
        }
        if (d->CtlType == ODT_TAB || d->hwndItem == g_hTab)
        {
            BOOL sel = (d->itemState & ODS_SELECTED) != 0;
            BOOL hot = ((int)d->itemID == g_tabHot);
            FillRect(d->hDC, &d->rcItem, sel ? g_brTabSel : (hot ? g_brTabHot : g_brTab));
            if (sel)
            {
                RECT top = d->rcItem; top.bottom = top.top + 2;
                FillRect(d->hDC, &top, g_brAccent);
            }
            wchar_t txt[64] = {0};
            TCITEMW ti; ti.mask = TCIF_TEXT; ti.pszText = txt; ti.cchTextMax = 64;
            TabCtrl_GetItem(g_hTab, d->itemID, &ti);
            SetBkMode(d->hDC, TRANSPARENT);
            SetTextColor(d->hDC, sel ? C_TEXT : C_DIM);
            DrawTextW(d->hDC, txt, -1, &d->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        return 0;
    }
    case WM_UAHDRAWMENU:
    {
        UAHMENU* pum = (UAHMENU*)lp;
        MENUBARINFO mbi; mbi.cbSize = sizeof(mbi);
        GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mbi);
        RECT wr; GetWindowRect(hwnd, &wr);
        RECT r = mbi.rcBar; OffsetRect(&r, -wr.left, -wr.top);
        FillRect(pum->hdc, &r, g_brMenu);
        return TRUE;
    }
    case WM_UAHDRAWMENUITEM:
    {
        UAHDRAWMENUITEM* pmi = (UAHDRAWMENUITEM*)lp;
        wchar_t txt[128] = {0};
        MENUITEMINFOW mii; mii.cbSize = sizeof(mii);
        mii.fMask = MIIM_STRING; mii.dwTypeData = txt; mii.cch = 128;
        GetMenuItemInfoW(pmi->um.hmenu, (UINT)pmi->umi.iPosition, TRUE, &mii);
        BOOL hot = (pmi->dis.itemState & (ODS_HOTLIGHT | ODS_SELECTED)) != 0;
        FillRect(pmi->um.hdc, &pmi->dis.rcItem, hot ? g_brMenuHot : g_brMenu);
        SetBkMode(pmi->um.hdc, TRANSPARENT);
        SetTextColor(pmi->um.hdc,
                     (pmi->dis.itemState & (ODS_GRAYED | ODS_DISABLED)) ? C_DIM : C_TEXT);
        DrawTextW(pmi->um.hdc, txt, -1, &pmi->dis.rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_NCACTIVATE:
    case WM_NCPAINT:
    {
        LRESULT r = DefWindowProcW(hwnd, msg, wp, lp);
        PaintMenuBottomLine(hwnd);
        DrawMenuBar2(hwnd);
        return r;
    }
    case WM_NCMOUSEMOVE:
    {
        RECT wr; GetWindowRect(hwnd, &wr);
        POINT p = { GET_X_LPARAM(lp) - wr.left, GET_Y_LPARAM(lp) - wr.top };
        int hot = PtInRect(&g_rcTbSet, p) ? 0 : (PtInRect(&g_rcTbRules, p) ? 1 : -1);
        if (hot != g_tbHot)
        {
            g_tbHot = hot; DrawMenuBar2(hwnd);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE | TME_NONCLIENT, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    }
    case WM_NCMOUSELEAVE:
        if (g_tbHot != -1) { g_tbHot = -1; DrawMenuBar2(hwnd); }
        break;
    case WM_NCLBUTTONDOWN:
    {
        RECT wr; GetWindowRect(hwnd, &wr);
        POINT p = { GET_X_LPARAM(lp) - wr.left, GET_Y_LPARAM(lp) - wr.top };
        if (PtInRect(&g_rcTbSet, p))   { SendMessageW(hwnd, WM_COMMAND, IDM_PROXY_SETTINGS, 0); return 0; }
        if (PtInRect(&g_rcTbRules, p)) { SendMessageW(hwnd, WM_COMMAND, IDM_PROXY_RULES, 0);    return 0; }
        break;
    }
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->hwndFrom == g_hTab && nh->code == TCN_SELCHANGE) SelectTab(TabCtrl_GetCurSel(g_hTab));
        return 0;
    }
    case WM_TIMER:
        if (wp == TIMER_LOG)
        {
            int processed = LogStoreFlush(&g_connStore) + LogStoreFlush(&g_actStore);
            // When traffic has been idle for a couple of seconds, hand freed pages back to the
            // OS so memory drops after a burst instead of staying pinned in the working set.
            if (processed == 0) { if (++g_idleTicks == 10) SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1); }
            else g_idleTicks = 0;
        }
        return 0;
    case WM_APP_UPDATE:
    {
        UpdInfo* info = (UpdInfo*)lp;
        BOOL ok = (wp & 1) != 0, manual = (wp & 2) != 0;
        if (info)
        {
            if (ok && info->available)
                DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_UPDATE), hwnd, UpdateDlgProc, (LPARAM)info);
            else if (manual)
                MessageBoxW(hwnd, ok ? T(S_UPD_LATEST) : T(S_UPD_ERR), T(S_UPD_TITLE), MB_OK | MB_ICONINFORMATION);
            free(info);
        }
        return 0;
    }
    case WM_APP_TRAY:
        if (LOWORD(lp) == WM_LBUTTONDBLCLK) ShowMainWindow(hwnd);
        else if (LOWORD(lp) == WM_RBUTTONUP)
        {
            POINT pt; GetCursorPos(&pt);
            HMENU pm = CreatePopupMenu();
            AppendMenuW(pm, MF_STRING, IDM_TRAY_SHOW, T(S_TRAY_SHOW));
            AppendMenuW(pm, MF_SEPARATOR, 0, NULL);
            AppendMenuW(pm, MF_STRING, IDM_TRAY_EXIT, T(S_TRAY_EXIT));
            SetForegroundWindow(hwnd);
            TrackPopupMenu(pm, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(pm);
        }
        return 0;

    case WM_COMMAND:
    {
        WORD id = LOWORD(wp);
        if (id >= IDM_PROFILE_SWITCH_BASE && id < IDM_PROFILE_SWITCH_BASE + g_profCount)
        {
            int i = id - IDM_PROFILE_SWITCH_BASE;
            if (_wcsicmp(g_profNames[i], g_activeProfile) != 0) SwitchToProfile(g_profNames[i]);
            return 0;
        }
        switch (id)
        {
        case IDM_PROXY_SETTINGS: DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_SERVERS), hwnd, ServersDlgProc); return 0;
        case IDM_PROXY_RULES:    DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_RULES),   hwnd, RulesDlgProc);   return 0;
        case IDM_SET_LOCALHOST:
            g_localhost = !g_localhost; g_profile.localhostViaProxy = g_localhost;
            g_api.SetLocalhostViaProxy(g_localhost); SaveActive(); SyncMenuChecks(hwnd); return 0;
        case IDM_SET_TRAFFICLOG:
            g_trafficLog = !g_trafficLog; g_profile.trafficLogging = g_trafficLog;
            g_api.SetTrafficLoggingEnabled(g_trafficLog); SaveActive(); SyncMenuChecks(hwnd); return 0;
        case IDM_SET_CLOSETOTRAY:
            g_closeToTray = !g_closeToTray; g_profile.closeToTray = g_closeToTray;
            SaveActive(); SyncMenuChecks(hwnd); return 0;
        case IDM_SET_STARTUP:
            g_startup = !g_startup; StartupSet(g_startup);
            g_startup = StartupIsEnabled();   // reflect the real state
            SyncMenuChecks(hwnd); return 0;
        case IDM_SET_AUTOCLEAR:
            g_autoClear = !g_autoClear; g_profile.autoClearLogs = g_autoClear;
            SaveActive(); SyncMenuChecks(hwnd); return 0;
        case IDM_LOG_FILTERS:
            if (DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_FILTERS), hwnd, FiltersDlgProc))
            {
                ApplyFilterSnapshot(); SaveActive();
                LogStoreClear(&g_connStore);   // re-populate under the new filter set
            }
            return 0;
        case IDM_PROFILE_RENAME:
            if (_wcsicmp(g_activeProfile, L"Default") == 0)
            { MessageBoxW(hwnd, T(S_INFO_NORENAMEDEFAULT), APP_TITLE, MB_OK | MB_ICONINFORMATION); return 0; }
            if (DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_NAME), hwnd, NameDlgProc) && g_nameResult[0])
            {
                for (wchar_t* q = g_nameResult; *q; q++) if (wcschr(L"<>:\"/\\|?*", *q)) *q = L'_';
                if (_wcsicmp(g_nameResult, g_activeProfile) != 0)
                {
                    if (PB_ProfileRename(g_activeProfile, g_nameResult))
                    { lstrcpynW(g_activeProfile, g_nameResult, PB_NAME_MAX); RebuildProfileMenu(hwnd); UpdateTitle(); }
                    else MessageBoxW(hwnd, T(S_ERR_IMPORT), APP_TITLE, MB_OK | MB_ICONERROR);
                }
            }
            return 0;
        case IDM_LANG_EN: g_lang = 0; lstrcpynW(g_profile.language, L"en", 8); SaveActive(); RelocalizeUI(hwnd); return 0;
        case IDM_LANG_ZH: g_lang = 1; lstrcpynW(g_profile.language, L"zh", 8); SaveActive(); RelocalizeUI(hwnd); return 0;
        case IDC_CONN_CLEAR: LogStoreClear(&g_connStore); if (g_api.ClearConnectionLogs) g_api.ClearConnectionLogs(); return 0;
        case IDC_ACT_CLEAR:  LogStoreClear(&g_actStore); return 0;
        case IDC_CONN_SEARCH:
            if (HIWORD(wp) == EN_CHANGE)
            { GetWindowTextW(g_hConnSearch, g_connStore.filter, 128); LogStoreRebuild(&g_connStore); }
            return 0;
        case IDC_ACT_SEARCH:
            if (HIWORD(wp) == EN_CHANGE)
            { GetWindowTextW(g_hActSearch, g_actStore.filter, 128); LogStoreRebuild(&g_actStore); }
            return 0;
        case IDM_PROFILE_NEW:
            if (DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_NAME), hwnd, NameDlgProc) && g_nameResult[0])
            {
                for (wchar_t* q = g_nameResult; *q; q++) if (wcschr(L"<>:\"/\\|?*", *q)) *q = L'_';
                PBProfile* np = (PBProfile*)malloc(sizeof(PBProfile));  // too big for the stack
                if (np) { PB_ProfileDefaults(np, g_nameResult); PB_ProfileSave(g_nameResult, np); free(np); }
                SwitchToProfile(g_nameResult);
            }
            return 0;
        case IDM_PROFILE_DELETE:
            if (_wcsicmp(g_activeProfile, L"Default") == 0)
            { MessageBoxW(hwnd, T(S_INFO_NODELDEFAULT), APP_TITLE, MB_OK | MB_ICONINFORMATION); return 0; }
            {
                wchar_t toDel[PB_NAME_MAX]; lstrcpynW(toDel, g_activeProfile, PB_NAME_MAX);
                SwitchToProfile(L"Default");
                PB_ProfileDelete(toDel);
                RebuildProfileMenu(hwnd);
            }
            return 0;
        case IDM_PROFILE_IMPORT:
        {
            wchar_t src[MAX_PATH];
            if (PickFile(hwnd, FALSE, src, MAX_PATH))
            {
                wchar_t assigned[PB_NAME_MAX];
                if (PB_ProfileImport(src, assigned, PB_NAME_MAX)) SwitchToProfile(assigned);
                else MessageBoxW(hwnd, T(S_ERR_IMPORT), APP_TITLE, MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case IDM_PROFILE_EXPORT:
        {
            wchar_t dst[MAX_PATH];
            if (PickFile(hwnd, TRUE, dst, MAX_PATH))
            {
                if (!PB_ProfileExport(g_activeProfile, dst))
                    MessageBoxW(hwnd, T(S_ERR_EXPORT), APP_TITLE, MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case IDM_HELP_DOCS:
            ShellExecuteW(hwnd, L"open", L"https://interceptsuite.com/docs/proxybridge/", NULL, NULL, SW_SHOWNORMAL);
            return 0;
        case IDM_HELP_UPDATE:
            UpdStartCheck(hwnd, TRUE);   // manual: also reports "up to date" / errors
            return 0;
        case IDM_HELP_ABOUT:
            DialogBoxW(g_hInst, MAKEINTRESOURCEW(IDD_ABOUT), hwnd, AboutDlgProc);
            return 0;
        case IDM_TRAY_SHOW: ShowMainWindow(hwnd); return 0;
        case IDM_TRAY_EXIT: g_reallyExit = TRUE; DestroyWindow(hwnd); return 0;
        }
        return 0;
    }

    case WM_CLOSE:
        if (g_closeToTray && !g_reallyExit) { ShowWindow(hwnd, SW_HIDE); return 0; }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_api.Stop) g_api.Stop();
        TrayRemove();
        KillTimer(hwnd, TIMER_LOG);
        LogStoreFree(&g_connStore);    // release buffered + pending log lines + the lock
        LogStoreFree(&g_actStore);
        if (g_hMono) DeleteObject(g_hMono);
        if (g_hUi)   DeleteObject(g_hUi);
        if (g_hIcon) DeleteObject(g_hIcon);
        if (g_hMenuFont) DeleteObject(g_hMenuFont);
        if (g_brBg)     DeleteObject(g_brBg);
        if (g_brPanel)  DeleteObject(g_brPanel);
        if (g_brTab)    DeleteObject(g_brTab);
        if (g_brTabSel) DeleteObject(g_brTabSel);
        if (g_brTabHot) DeleteObject(g_brTabHot);
        if (g_brAccent) DeleteObject(g_brAccent);
        if (g_brMenu)   DeleteObject(g_brMenu);
        if (g_brMenuHot)DeleteObject(g_brMenuHot);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
// all dialogs (split out)
#include "ui/dialogs.h"


// entry point
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    (void)hPrev;
    g_hInst = hInst;
    BOOL startMinimized = (cmd && wcsstr(cmd, L"--minimized") != NULL);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    if (!PB_Load(&g_api))
    {
        MessageBoxW(NULL, L"Could not load ProxyBridgeCore.dll.\n"
                          L"Make sure it is in the same folder as this executable.",
                    APP_TITLE, MB_OK | MB_ICONERROR);
        return 1;
    }

    // Load the active profile.
    PB_GetActiveProfile(g_activeProfile, PB_NAME_MAX);
    PB_ProfileLoad(g_activeProfile, &g_profile);
    g_localhost   = g_profile.localhostViaProxy;
    g_trafficLog  = g_profile.trafficLogging;
    g_closeToTray = g_profile.closeToTray;
    g_lang        = (_wcsicmp(g_profile.language, L"zh") == 0) ? 1 : 0;

    // Refuse to start if another GUI or the CLI is already running - they'd both grab the
    // WinDivert driver and the same relay ports.
    if (AnotherInstanceRunning())
    {
        MessageBoxW(NULL, T(S_ERR_RUNNING), APP_TITLE, MB_OK | MB_ICONWARNING);
        return 0;
    }

    g_autoClear   = g_profile.autoClearLogs;
    g_startup     = StartupIsEnabled();
    ApplyFilterSnapshot();

    CreateDarkBrushes();   // needed for the window class background below

    WNDCLASSEXW wc; ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = g_brBg;
    wc.lpszClassName = WND_CLASS;
    wc.lpszMenuName = NULL;   // menu is built programmatically (localizable)
    if (!RegisterClassExW(&wc)) return 1;

    g_hMain = CreateWindowExW(0, WND_CLASS, APP_TITLE, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 1200, 820, NULL, NULL, hInst, NULL);
    if (!g_hMain) return 1;

    // Center on the working area of the monitor the window landed on (CW_USEDEFAULT places
    // it top-left otherwise).
    {
        RECT wr; GetWindowRect(g_hMain, &wr);
        int ww = wr.right - wr.left, wh = wr.bottom - wr.top;
        HMONITOR mon = MonitorFromWindow(g_hMain, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi; mi.cbSize = sizeof(mi);
        if (GetMonitorInfoW(mon, &mi))
        {
            int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - ww) / 2;
            int y = mi.rcWork.top  + (mi.rcWork.bottom - mi.rcWork.top - wh) / 2;
            SetWindowPos(g_hMain, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    BuildMainMenu(g_hMain);
    DrawMenuBar(g_hMain);
    TrayAdd(g_hMain);
    SyncMenuChecks(g_hMain);
    RebuildProfileMenu(g_hMain);
    UpdateTitle();

    // Wire callbacks + toggles, add configs (before Start so the UDP relay starts), start,
    // then add rules.
    g_api.SetLocalhostViaProxy(g_localhost);
    g_api.SetTrafficLoggingEnabled(g_trafficLog);
    g_api.SetLogCallback(PBLogCb);
    g_api.SetConnectionCallback(PBConnCb);
    ApplyConfigs();
    g_started = g_api.Start();
    if (g_started) { ApplyRules(); LogStoreAdd(&g_actStore, T(S_STARTED)); }
    else LogStoreAdd(&g_actStore, T(S_STARTFAIL));

    if (startMinimized) ShowWindow(g_hMain, SW_HIDE);   // launched by the logon task
    else { ShowWindow(g_hMain, show); UpdateWindow(g_hMain); }

    // Silent update check on startup (opt-out via the notification's "Don't Ask Again").
    if (PB_GetCheckUpdates()) UpdStartCheck(g_hMain, FALSE);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        if (IsDialogMessageW(g_hMain, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
