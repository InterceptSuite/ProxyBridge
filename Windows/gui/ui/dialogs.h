// ui/dialogs.h - all modal dialogs (Proxy Servers, Proxy Checker,
// Proxy Rules, Log Filters, and their edit sub-dialogs, plus the new-profile prompt).
//
// Unity-build include: pulled into main.c after the globals, theme helpers, log store,
// filter helpers and the profile/engine helpers it calls. Not a standalone header.
#ifndef PB_UI_DIALOGS_H
#define PB_UI_DIALOGS_H

// Subclass a ListView to (a) dark-theme its header via custom draw - it stays light
// otherwise - and (b) the header's empty right-hand area gets filled dark too.
static LRESULT CALLBACK ListDarkSubProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    if (m == WM_NOTIFY)
    {
        NMHDR* nh = (NMHDR*)l;
        if (nh->code == NM_CUSTOMDRAW && nh->hwndFrom == ListView_GetHeader(h))
        {
            NMCUSTOMDRAW* cd = (NMCUSTOMDRAW*)l;
            switch (cd->dwDrawStage)
            {
            case CDDS_PREPAINT:
                FillRect(cd->hdc, &cd->rc, g_brPanel);
                return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
            case CDDS_ITEMPREPAINT:
            {
                wchar_t txt[64] = {0};
                HDITEMW hi; hi.mask = HDI_TEXT; hi.pszText = txt; hi.cchTextMax = 64;
                Header_GetItem(nh->hwndFrom, (int)cd->dwItemSpec, &hi);
                FillRect(cd->hdc, &cd->rc, g_brPanel);
                SetBkMode(cd->hdc, TRANSPARENT);
                SetTextColor(cd->hdc, C_TEXT);
                RECT tr = cd->rc; tr.left += 6; tr.right -= 4;
                DrawTextW(cd->hdc, txt, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                RECT ln = { cd->rc.right - 1, cd->rc.top, cd->rc.right, cd->rc.bottom };
                FillRect(cd->hdc, &ln, g_brBg);   // subtle column divider
                return CDRF_SKIPDEFAULT;
            }
            case CDDS_POSTPAINT:
            {
                // Paint the empty area to the right of the last column dark; otherwise
                // it shows the default white header background (visible at the edge and
                // whenever the columns don't span the full width, e.g. after a drag).
                HWND hdr = nh->hwndFrom;
                int n = Header_GetItemCount(hdr);
                RECT last = {0, 0, 0, 0};
                if (n > 0) Header_GetItemRect(hdr, n - 1, &last);
                RECT hr; GetClientRect(hdr, &hr);
                if (hr.right > last.right)
                {
                    RECT fill = { last.right, hr.top, hr.right, hr.bottom };
                    FillRect(cd->hdc, &fill, g_brPanel);
                }
                return CDRF_DODEFAULT;
            }
            }
        }
    }
    return DefSubclassProc(h, m, w, l);
}

// Grow every column proportionally so the grid fills its full client width - no dead space
// on the right, and no single over-wide column. Idempotent: once the columns already span
// the width, re-calling it is a no-op (it never shrinks below the seeded widths).
#define PB_MAX_COLS 16
static void FillColumns(HWND lv, int count)
{
    if (count <= 0 || count > PB_MAX_COLS) return;
    RECT rc; GetClientRect(lv, &rc);
    int avail = rc.right - 4;                 // small margin to avoid a stray h-scrollbar
    if (avail <= 0) return;
    int w[PB_MAX_COLS]; int total = 0;
    for (int i = 0; i < count; i++) { w[i] = ListView_GetColumnWidth(lv, i); total += w[i]; }
    if (total <= 0 || avail <= total) return; // nothing to distribute (or would need to shrink)
    int extra = avail - total, given = 0;
    for (int i = 0; i < count; i++)
    {
        int add = (i == count - 1) ? (extra - given)      // last column soaks up the rounding
                                   : (int)((INT64)extra * w[i] / total);
        given += add;
        ListView_SetColumnWidth(lv, i, w[i] + add);
    }
}

// Dark-theme a report ListView: full-row select + double buffer (+ any extra ex-styles),
// dark colours, dark-drawn header. Columns/FillColumns are added by the caller.
static void DarkListView(HWND lv, DWORD extraExStyle)
{
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | extraExStyle);
    SetWindowTheme(lv, L"DarkMode_Explorer", NULL);
    ListView_SetBkColor(lv, C_PANEL);
    ListView_SetTextBkColor(lv, C_PANEL);
    ListView_SetTextColor(lv, C_TEXT);
    SetWindowSubclass(lv, ListDarkSubProc, 3, 0);
}

// Proxy Servers
// A Proxifier-style list of proxy servers with Add.../Edit.../Remove; the actual
// address/port/protocol/auth fields live in the IDD_SERVER sub-dialog.

static void InitServerList(HWND lv)
{
    DarkListView(lv, 0);
    struct { int s; int w; } cols[] = { {S_COL_NAME, 130}, {S_COL_ADDR, 160}, {S_COL_PORTS, 60}, {S_COL_TYPE, 80} };
    LVCOLUMNW c; c.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < 4; i++) { c.pszText = (LPWSTR)T(cols[i].s); c.cx = cols[i].w; ListView_InsertColumn(lv, i, &c); }
    FillColumns(lv, 4);
}
static void RefreshServerList(HWND lv)
{
    ListView_DeleteAllItems(lv);
    for (int i = 0; i < g_profile.cfgCount; i++)
    {
        PBConfig* c = &g_profile.cfg[i];
        LVITEMW it; ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT; it.iItem = i; it.pszText = c->name[0] ? c->name : c->host;
        ListView_InsertItem(lv, &it);
        ListView_SetItemText(lv, i, 1, c->host);
        ListView_SetItemText(lv, i, 2, c->port);
        ListView_SetItemText(lv, i, 3, c->type);
    }
}

// Edit sub-dialog. lParam is a PBConfig* seeded with current values (or zeroed for a new one);
// on OK it is written back and the dialog returns 1.
INT_PTR CALLBACK ServerEditDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)lp);
        PBConfig* c = (PBConfig*)lp;
        SetWindowTextW(dlg, T(S_DLG_SERVER));
        SetDlgItemTextW(dlg, IDC_SE_L_NAME,   T(S_L_NAME));
        SetDlgItemTextW(dlg, IDC_SE_G_SERVER, T(S_G_SERVER));
        SetDlgItemTextW(dlg, IDC_SE_G_AUTH,   T(S_G_AUTH));
        SetDlgItemTextW(dlg, IDC_SE_L_ADDR,   T(S_L_ADDR));
        SetDlgItemTextW(dlg, IDC_SE_L_PORT,   T(S_L_PORT));
        SetDlgItemTextW(dlg, IDC_SE_L_PROTO,  T(S_L_PROTO));
        SetDlgItemTextW(dlg, IDC_SE_AUTH,     T(S_CHK_ENABLE));
        SetDlgItemTextW(dlg, IDC_SE_SENDDOMAIN, T(S_CHK_SENDDOMAIN));
        SetDlgItemTextW(dlg, IDC_SE_L_USER,   T(S_L_USER));
        SetDlgItemTextW(dlg, IDC_SE_L_PASS,   T(S_L_PASS));
        SetDlgItemTextW(dlg, IDOK,            T(S_BTN_OK));
        SetDlgItemTextW(dlg, IDCANCEL,        T(S_BTN_CANCEL));
        HWND pr = GetDlgItem(dlg, IDC_SE_PROTO);
        SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)L"SOCKS5");
        SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)L"HTTP");
        SendMessageW(pr, CB_SETCURSEL, (_wcsicmp(c->type, L"HTTP") == 0) ? 1 : 0, 0);
        SetDlgItemTextW(dlg, IDC_SE_NAME, c->name);
        SetDlgItemTextW(dlg, IDC_SE_ADDR, c->host);
        if (c->port[0]) SetDlgItemTextW(dlg, IDC_SE_PORT, c->port); else SetDlgItemInt(dlg, IDC_SE_PORT, 1080, FALSE);
        SetDlgItemTextW(dlg, IDC_SE_USER, c->user);
        SetDlgItemTextW(dlg, IDC_SE_PASS, c->pass);
        CheckDlgButton(dlg, IDC_SE_SENDDOMAIN, c->sendDomain ? BST_CHECKED : BST_UNCHECKED);
        BOOL hasAuth = c->user[0] != 0;
        CheckDlgButton(dlg, IDC_SE_AUTH, hasAuth ? BST_CHECKED : BST_UNCHECKED);
        EnableWindow(GetDlgItem(dlg, IDC_SE_USER), hasAuth);
        EnableWindow(GetDlgItem(dlg, IDC_SE_PASS), hasAuth);
        InitDarkMode(dlg);
        return TRUE;
    }
    PB_DARK_CTLCOLORS;
    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDC_SE_AUTH:
        {
            BOOL on = IsDlgButtonChecked(dlg, IDC_SE_AUTH) == BST_CHECKED;
            EnableWindow(GetDlgItem(dlg, IDC_SE_USER), on);
            EnableWindow(GetDlgItem(dlg, IDC_SE_PASS), on);
            return TRUE;
        }
        case IDOK:
        {
            PBConfig* c = (PBConfig*)GetWindowLongPtrW(dlg, GWLP_USERDATA);
            int isHttp = (int)SendMessageW(GetDlgItem(dlg, IDC_SE_PROTO), CB_GETCURSEL, 0, 0) == 1;
            lstrcpynW(c->type, isHttp ? L"HTTP" : L"SOCKS5", 16);
            GetDlgItemTextW(dlg, IDC_SE_NAME, c->name, 128);
            GetDlgItemTextW(dlg, IDC_SE_ADDR, c->host, 128);
            c->sendDomain = (IsDlgButtonChecked(dlg, IDC_SE_SENDDOMAIN) == BST_CHECKED) ? 1 : 0;
            if (!c->name[0]) lstrcpynW(c->name, c->host[0] ? c->host : L"Proxy Server", 128);
            GetDlgItemTextW(dlg, IDC_SE_PORT, c->port, 16);
            if (IsDlgButtonChecked(dlg, IDC_SE_AUTH) == BST_CHECKED)
            {
                GetDlgItemTextW(dlg, IDC_SE_USER, c->user, 128);
                GetDlgItemTextW(dlg, IDC_SE_PASS, c->pass, 128);
            }
            else { c->user[0] = 0; c->pass[0] = 0; }
            if (!c->host[0]) { MessageBoxW(dlg, T(S_ERR_HOST), APP_TITLE, MB_OK | MB_ICONWARNING); return TRUE; }
            EndDialog(dlg, 1);
            return TRUE;
        }
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

// Proxy Checker
// A Proxifier-style multi-step check. The DLL streams log lines through a callback on a
// worker thread (it can block up to 10s on an unreachable proxy); each line is posted to
// the dialog which appends it to a read-only log - no blocking, no popup.
INT_PTR CALLBACK CheckerDlgProc(HWND, UINT, WPARAM, LPARAM);

static void CheckerLogCb(const char* line, void* user)
{
    HWND dlg = (HWND)user;
    int wn = MultiByteToWideChar(CP_ACP, 0, line, -1, NULL, 0);
    if (wn <= 0) return;
    wchar_t* w = (wchar_t*)malloc((size_t)wn * sizeof(wchar_t));
    if (!w) return;
    MultiByteToWideChar(CP_ACP, 0, line, -1, w, wn);
    PostMessageW(dlg, WM_APP_TESTLINE, 0, (LPARAM)w);   // dialog frees it
}
typedef struct { HWND dlg; UINT32 id; char host[256]; unsigned short port; } CheckerJob;
static DWORD WINAPI CheckerThread(LPVOID p)
{
    CheckerJob* j = (CheckerJob*)p;
    g_api.TestProxyConfigEx(j->id, j->host, j->port, CheckerLogCb, j->dlg);
    PostMessageW(j->dlg, WM_APP_TESTDONE, 0, 0);
    free(j);
    return 0;
}
static void CheckerStart(HWND dlg)
{
    CheckerJob* j = (CheckerJob*)calloc(1, sizeof(CheckerJob));
    if (!j) return;
    j->dlg = dlg;
    j->id  = (UINT32)(UINT_PTR)GetWindowLongPtrW(dlg, GWLP_USERDATA);
    wchar_t wh[256]; GetDlgItemTextW(dlg, IDC_CK_HOST, wh, 256);
    if (!wh[0]) lstrcpynW(wh, L"www.google.com", 256);
    WideCharToMultiByte(CP_ACP, 0, wh, -1, j->host, sizeof(j->host), NULL, NULL);
    UINT port = GetDlgItemInt(dlg, IDC_CK_PORT, NULL, FALSE);
    if (port == 0 || port > 65535) port = 80;
    j->port = (unsigned short)port;

    SetWindowTextW(GetDlgItem(dlg, IDC_CK_LOG), L"");
    EnableWindow(GetDlgItem(dlg, IDC_CK_RETEST), FALSE);
    HANDLE t = CreateThread(NULL, 0, CheckerThread, j, 0, NULL);
    if (t) CloseHandle(t);
    else { free(j); EnableWindow(GetDlgItem(dlg, IDC_CK_RETEST), TRUE); }
}

INT_PTR CALLBACK CheckerDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)lp);   // lParam = config nativeId
        SetWindowTextW(dlg, T(S_DLG_CHECKER));
        SetDlgItemTextW(dlg, IDC_CK_L_HOST, T(S_CK_HOST));
        SetDlgItemTextW(dlg, IDC_CK_L_PORT, T(S_L_PORT));
        SetDlgItemTextW(dlg, IDC_CK_RETEST, T(S_BTN_RETEST));
        SetDlgItemTextW(dlg, IDCANCEL, T(S_BTN_CLOSE));
        SetDlgItemTextW(dlg, IDC_CK_HOST, L"www.google.com");
        SetDlgItemInt(dlg, IDC_CK_PORT, 80, FALSE);
        SendDlgItemMessageW(dlg, IDC_CK_LOG, WM_SETFONT,
                            (WPARAM)(g_hMono ? g_hMono : (HFONT)GetStockObject(ANSI_FIXED_FONT)), TRUE);
        InitDarkMode(dlg);
        CheckerStart(dlg);
        return TRUE;
    PB_DARK_CTLCOLORS;
    case WM_APP_TESTLINE:
    {
        wchar_t* w = (wchar_t*)lp;
        if (w)
        {
            HWND e = GetDlgItem(dlg, IDC_CK_LOG);
            int len = GetWindowTextLengthW(e);
            SendMessageW(e, EM_SETSEL, len, len);
            SendMessageW(e, EM_REPLACESEL, FALSE, (LPARAM)w);
            SendMessageW(e, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
            free(w);
        }
        return TRUE;
    }
    case WM_APP_TESTDONE:
        EnableWindow(GetDlgItem(dlg, IDC_CK_RETEST), TRUE);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_CK_RETEST) { CheckerStart(dlg); return TRUE; }
        if (LOWORD(wp) == IDCANCEL)      { EndDialog(dlg, 0); return TRUE; }
        return FALSE;
    }
    return FALSE;
}

INT_PTR CALLBACK ServersDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowTextW(dlg, T(S_DLG_SERVERS));
        SetDlgItemTextW(dlg, IDC_SV_ADD,    T(S_BTN_ADDDOTS));
        SetDlgItemTextW(dlg, IDC_SV_EDIT,   T(S_BTN_EDITDOTS));
        SetDlgItemTextW(dlg, IDC_SV_REMOVE, T(S_BTN_REMOVE));
        SetDlgItemTextW(dlg, IDC_SV_CHECK,  T(S_BTN_CHECK));
        SetDlgItemTextW(dlg, IDCANCEL,      T(S_BTN_CLOSE));
        InitDarkMode(dlg);
        InitServerList(GetDlgItem(dlg, IDC_SV_LIST));
        RefreshServerList(GetDlgItem(dlg, IDC_SV_LIST));
        return TRUE;
    case WM_SIZE:
        FillColumns(GetDlgItem(dlg, IDC_SV_LIST), 4);
        return FALSE;
    PB_DARK_CTLCOLORS;
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_SV_LIST && nh->code == NM_DBLCLK)
            PostMessageW(dlg, WM_COMMAND, IDC_SV_EDIT, 0);
        return TRUE;
    }
    case WM_COMMAND:
    {
        HWND lv = GetDlgItem(dlg, IDC_SV_LIST);
        switch (LOWORD(wp))
        {
        case IDC_SV_ADD:
        {
            if (g_profile.cfgCount >= PB_MAX_CFG) { MessageBoxW(dlg, L"Config limit reached.", APP_TITLE, MB_OK); return TRUE; }
            PBConfig c; ZeroMemory(&c, sizeof(c));
            lstrcpynW(c.name, L"Proxy Server", 128);
            c.sendDomain = 1;   // default: let the proxy resolve DNS
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_SERVER), dlg, ServerEditDlgProc, (LPARAM)&c) == 1)
            {
                char h[256], u[256], p[256]; W2Ux(c.host, h, sizeof(h)); W2Ux(c.user, u, sizeof(u)); W2Ux(c.pass, p, sizeof(p));
                UINT32 id = g_api.AddProxyConfig((_wcsicmp(c.type, L"HTTP") == 0) ? PB_PROXY_HTTP : PB_PROXY_SOCKS5,
                                                 h, (unsigned short)_wtoi(c.port), u, p, c.sendDomain ? TRUE : FALSE);
                if (id > 0) { c.nativeId = id; c.storedId = PB_AllocConfigId(&g_profile); g_profile.cfg[g_profile.cfgCount++] = c; SaveActive(); RefreshServerList(lv); }
                else MessageBoxW(dlg, T(S_ERR_ADDCFG), APP_TITLE, MB_OK | MB_ICONERROR);
            }
            return TRUE;
        }
        case IDC_SV_EDIT:
        {
            int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= g_profile.cfgCount) return TRUE;
            PBConfig c = g_profile.cfg[sel];
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_SERVER), dlg, ServerEditDlgProc, (LPARAM)&c) == 1)
            {
                g_profile.cfg[sel] = c;
                char h[256], u[256], p[256]; W2Ux(c.host, h, sizeof(h)); W2Ux(c.user, u, sizeof(u)); W2Ux(c.pass, p, sizeof(p));
                g_api.EditProxyConfig(c.nativeId, (_wcsicmp(c.type, L"HTTP") == 0) ? PB_PROXY_HTTP : PB_PROXY_SOCKS5,
                                      h, (unsigned short)_wtoi(c.port), u, p, c.sendDomain ? TRUE : FALSE);
                SaveActive(); RefreshServerList(lv);
                ListView_SetItemState(lv, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            }
            return TRUE;
        }
        case IDC_SV_CHECK:
        {
            int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= g_profile.cfgCount) return TRUE;
            DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_CHECKER), dlg, CheckerDlgProc,
                            (LPARAM)(UINT_PTR)g_profile.cfg[sel].nativeId);
            return TRUE;
        }
        case IDC_SV_REMOVE:
        {
            int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= g_profile.cfgCount) return TRUE;
            g_api.DeleteProxyConfig(g_profile.cfg[sel].nativeId);
            for (int i = sel; i < g_profile.cfgCount - 1; i++) g_profile.cfg[i] = g_profile.cfg[i + 1];
            g_profile.cfgCount--;
            SaveActive(); RefreshServerList(lv);
            return TRUE;
        }
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    }
    }
    return FALSE;
}

// Proxification Rules
// List of rules with check-box enable/disable, Add.../Clone/Edit.../Remove, Move Up / Move Down ordering and a
// search box. The rule fields live in the IDD_RULE sub-dialog.

static BOOL g_rulesRefreshing = FALSE;   // guards the checkbox-change notification during refill

// Search. The list shows only the rules that contain EVERY word typed in the search box (case-insensitive) in
// their name, applications, hosts, ports, protocol, action or proxy. g_rlMap[row] is the index in g_profile.rule
// of the rule shown at that list row: every action works on rule indexes, never on row numbers, so Edit, Clone,
// Remove and the enable check boxes are correct while the list is filtered.
#define RL_MAX_WORDS 8
#define RL_WORD_LEN  64
static int     g_rlMap[PB_MAX_RULE];
static int     g_rlMapN = 0;
static wchar_t g_rlWord[RL_MAX_WORDS][RL_WORD_LEN];
static int     g_rlWordN = 0;

// The text shown in the "Proxy" column (also searched).
static void RuleProxyLabel(const PBRule* r, wchar_t* cfg, int cch)
{
    if (_wcsicmp(r->action, L"PROXY") == 0)
    {
        const PBConfig* c = NULL;
        for (int k = 0; k < g_profile.cfgCount; k++)
            if (g_profile.cfg[k].storedId == r->cfgStoredId) { c = &g_profile.cfg[k]; break; }
        if (c) _snwprintf_s(cfg, cch, _TRUNCATE, L"%s  %s  %s:%s", c->name[0] ? c->name : c->type, c->type, c->host, c->port);
        else   _snwprintf_s(cfg, cch, _TRUNCATE, L"#%u (missing)", r->cfgStoredId);
        cfg[cch - 1] = 0;
    }
    else lstrcpynW(cfg, L"\x2014", cch);   // em dash for Direct/Block
}

static void RulesSetFilterText(const wchar_t* text)
{
    g_rlWordN = 0;
    const wchar_t* p = text ? text : L"";
    while (*p && g_rlWordN < RL_MAX_WORDS)
    {
        while (*p && *p <= L' ') p++;
        if (!*p) break;
        int n = 0;
        while (*p && *p > L' ') { if (n < RL_WORD_LEN - 1) g_rlWord[g_rlWordN][n++] = *p; p++; }
        g_rlWord[g_rlWordN][n] = 0;
        g_rlWordN++;
    }
}

static BOOL RuleMatchesFilter(const PBRule* r)
{
    if (g_rlWordN == 0) return TRUE;
    wchar_t label[200]; RuleProxyLabel(r, label, 200);
    const wchar_t* name = r->name[0] ? r->name : L"ProxyBridge Rule";
    size_t cap = wcslen(name) + wcslen(r->proc) + wcslen(r->hosts) + wcslen(r->ports) + wcslen(r->proto) + wcslen(r->action) + wcslen(label) + 16;
    wchar_t* hay = (wchar_t*)malloc(cap * sizeof(wchar_t));
    if (!hay) return TRUE;                                  // out of memory: show the rule rather than hide it
    _snwprintf_s(hay, cap, _TRUNCATE, L"%s\n%s\n%s\n%s\n%s\n%s\n%s", name, r->proc, r->hosts, r->ports, r->proto, r->action, label);
    BOOL ok = TRUE;
    for (int i = 0; i < g_rlWordN && ok; i++) ok = ContainsCI(hay, g_rlWord[i]);
    free(hay);
    return ok;
}

static int RowOfRuleIndex(int idx)
{
    for (int i = 0; i < g_rlMapN; i++) if (g_rlMap[i] == idx) return i;
    return -1;
}
static int SelectedRuleIndex(HWND lv)
{
    int row = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    return (row >= 0 && row < g_rlMapN) ? g_rlMap[row] : -1;
}
static void SelectRuleIndex(HWND lv, int idx)
{
    int row = RowOfRuleIndex(idx);
    if (row < 0) return;
    ListView_SetItemState(lv, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(lv, row, FALSE);
}

static void InitRulesList(HWND lv)
{
    // Checkboxes give the enable/disable toggle in the first column.
    DarkListView(lv, LVS_EX_CHECKBOXES);
    struct { int s; int w; } cols[] = {
        {S_COL_ON, 36}, {S_COL_NAME, 130}, {S_COL_APPS, 160}, {S_COL_HOSTS, 200}, {S_COL_PORTS, 60},
        {S_COL_PROTO, 55}, {S_COL_ACTION, 65}, {S_COL_CFG, 190}
    };
    LVCOLUMNW c; c.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < 8; i++) { c.pszText = (LPWSTR)T(cols[i].s); c.cx = cols[i].w; ListView_InsertColumn(lv, i, &c); }
    SetWindowSubclass(lv, ListDarkSubProc, 3, 0);
    FillColumns(lv, 8);
}

// "n of m rules" while a search is active; reordering is only offered on the full list.
static void RulesUpdateChrome(HWND dlg)
{
    BOOL filtered = g_rlWordN > 0;
    wchar_t txt[160]; txt[0] = 0;
    if (filtered) _snwprintf_s(txt, ARRAYSIZE(txt), _TRUNCATE, T(S_RULES_COUNT), g_rlMapN, g_profile.ruleCount);
    SetDlgItemTextW(dlg, IDC_RL_COUNT, txt);
    EnableWindow(GetDlgItem(dlg, IDC_RL_UP),    !filtered);
    EnableWindow(GetDlgItem(dlg, IDC_RL_DOWN),  !filtered);
    EnableWindow(GetDlgItem(dlg, IDC_RL_CLEAR), filtered);
}

static void RefreshRulesList(HWND lv)
{
    g_rulesRefreshing = TRUE;
    ListView_DeleteAllItems(lv);
    g_rlMapN = 0;
    for (int i = 0; i < g_profile.ruleCount && g_rlMapN < PB_MAX_RULE; i++)
        if (RuleMatchesFilter(&g_profile.rule[i])) g_rlMap[g_rlMapN++] = i;
    for (int row = 0; row < g_rlMapN; row++)
    {
        const PBRule* r = &g_profile.rule[g_rlMap[row]];
        LVITEMW it; ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT; it.iItem = row; it.pszText = (LPWSTR)L"";
        ListView_InsertItem(lv, &it);
        ListView_SetItemText(lv, row, 1, r->name[0] ? (LPWSTR)r->name : (LPWSTR)L"ProxyBridge Rule");
        ListView_SetItemText(lv, row, 2, (LPWSTR)r->proc);
        ListView_SetItemText(lv, row, 3, (LPWSTR)r->hosts);
        ListView_SetItemText(lv, row, 4, (LPWSTR)r->ports);
        ListView_SetItemText(lv, row, 5, (LPWSTR)r->proto);
        ListView_SetItemText(lv, row, 6, (LPWSTR)r->action);
        wchar_t cfg[200]; RuleProxyLabel(r, cfg, 200);
        ListView_SetItemText(lv, row, 7, cfg);
        ListView_SetCheckState(lv, row, r->enabled ? TRUE : FALSE);
    }
    g_rulesRefreshing = FALSE;
    RulesUpdateChrome(GetParent(lv));
}

// Re-reads the search box and refilters, keeping the selected rule selected when it is still shown.
static void RulesApplyFilterFromBox(HWND dlg)
{
    HWND lv = GetDlgItem(dlg, IDC_RL_LIST);
    wchar_t text[256];
    GetDlgItemTextW(dlg, IDC_RL_SEARCH, text, ARRAYSIZE(text));
    int keep = SelectedRuleIndex(lv);
    RulesSetFilterText(text);
    RefreshRulesList(lv);
    SelectRuleIndex(lv, keep);
}

static void RulesFocusSearch(HWND dlg, wchar_t typed)
{
    HWND e = GetDlgItem(dlg, IDC_RL_SEARCH);
    SetFocus(e);
    if (typed)
    {
        wchar_t s[2] = { typed, 0 };
        SendMessageW(e, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);          // type-to-search: append at the end
        SendMessageW(e, EM_REPLACESEL, TRUE, (LPARAM)s);
    }
    else SendMessageW(e, EM_SETSEL, 0, (LPARAM)-1);                  // Ctrl+F: select the old text
}

static void RulesFocusList(HWND dlg)
{
    HWND lv = GetDlgItem(dlg, IDC_RL_LIST);
    if (g_rlMapN <= 0) return;
    if (ListView_GetNextItem(lv, -1, LVNI_SELECTED) < 0)
        ListView_SetItemState(lv, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    SetFocus(lv);
}

// Search box keys: Enter / Down go to the list, Esc clears the text (and only closes the dialog when empty).
static LRESULT CALLBACK RuleSearchProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)ref;
    HWND dlg = GetParent(h);
    switch (m)
    {
    case WM_GETDLGCODE:
    {
        LRESULT r = DefSubclassProc(h, m, w, l);
        const MSG* ms = (const MSG*)l;
        if (ms && ms->message == WM_KEYDOWN)
        {
            if (ms->wParam == VK_RETURN || ms->wParam == VK_DOWN) r |= DLGC_WANTMESSAGE;
            else if (ms->wParam == VK_ESCAPE && GetWindowTextLengthW(h) > 0) r |= DLGC_WANTMESSAGE;
        }
        return r;
    }
    case WM_KEYDOWN:
        if (w == VK_RETURN || w == VK_DOWN) { RulesFocusList(dlg); return 0; }
        if (w == VK_ESCAPE && GetWindowTextLengthW(h) > 0) { SetWindowTextW(h, L""); return 0; }   // EN_CHANGE refilters
        if (w == 'F' && GetKeyState(VK_CONTROL) < 0) { SendMessageW(h, EM_SETSEL, 0, (LPARAM)-1); return 0; }
        break;
    case WM_CHAR:
        if (w == VK_RETURN || w == VK_ESCAPE) return 0;               // no beep
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, RuleSearchProc, id);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

// List keys: Ctrl+F jumps to the search box, any printable character starts a search (type-to-search),
// Esc clears an active search.
static LRESULT CALLBACK RuleListProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)ref;
    HWND dlg = GetParent(h);
    switch (m)
    {
    case WM_GETDLGCODE:
    {
        LRESULT r = DefSubclassProc(h, m, w, l);
        const MSG* ms = (const MSG*)l;
        if (ms && ms->message == WM_KEYDOWN && ms->wParam == VK_ESCAPE && g_rlWordN > 0) r |= DLGC_WANTMESSAGE;
        return r;
    }
    case WM_KEYDOWN:
        if (w == 'F' && GetKeyState(VK_CONTROL) < 0) { RulesFocusSearch(dlg, 0); return 0; }
        if (w == VK_ESCAPE && g_rlWordN > 0) { SetDlgItemTextW(dlg, IDC_RL_SEARCH, L""); return 0; }
        break;
    case WM_CHAR:
        // Space is left to the list (it toggles the check box of the selected rule).
        if (w > L' ' && w != 0x7F && GetKeyState(VK_CONTROL) >= 0) { RulesFocusSearch(dlg, (wchar_t)w); return 0; }
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(h, RuleListProc, id);
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

// ---- Applications list: adding programs from Browse / Running ----
// Rules match programs by NAME (or by full path), never by PID: everything added here is a file name or a path.
typedef struct { wchar_t** v; int n; } AppList;

static void AppListAdd(AppList* l, const wchar_t* s)
{
    for (int i = 0; i < l->n; i++) if (!_wcsicmp(l->v[i], s)) return;          // no duplicates
    wchar_t* c = _wcsdup(s);
    wchar_t** nv = c ? (wchar_t**)realloc(l->v, ((size_t)l->n + 1) * sizeof(wchar_t*)) : NULL;
    if (!nv) { free(c); return; }
    l->v = nv; l->v[l->n++] = c;
}
static void AppListFree(AppList* l) { for (int i = 0; i < l->n; i++) free(l->v[i]); free(l->v); l->v = NULL; l->n = 0; }

// Does the ';' / ',' separated list already contain `name` (case-insensitive; blanks and surrounding quotes ignored)?
static BOOL AppListContains(const wchar_t* list, const wchar_t* name)
{
    size_t nl = wcslen(name);
    const wchar_t* p = list;
    while (*p)
    {
        while (*p == L';' || *p == L',' || *p == L' ' || *p == L'\t') p++;
        const wchar_t* s = p; while (*p && *p != L';' && *p != L',') p++;
        const wchar_t* e = p; while (e > s && (e[-1] == L' ' || e[-1] == L'\t')) e--;
        if (e - s >= 2 && *s == L'"' && e[-1] == L'"') { s++; e--; }
        if ((size_t)(e - s) == nl && _wcsnicmp(s, name, nl) == 0) return TRUE;
    }
    return FALSE;
}

// Appends names to the Applications box ("a.exe; b.exe"). A name already in the list is skipped, and a name that is
// empty, contains a list separator (';' ',' or a quote), or would not fit in PB_APPS_MAX is skipped as a whole - never
// cut in the middle. Returns how many were added; *skipped counts the ones that could not be (list full / unusable name).
static int AppendApps(HWND dlg, const wchar_t* const* names, int n, int* skipped, int* duplicates)
{
    int added = 0, bad = 0, dup = 0;
    HWND e = GetDlgItem(dlg, IDC_RE_APPS);
    wchar_t out[PB_APPS_MAX];
    GetWindowTextW(e, out, PB_APPS_MAX);
    if (out[0] == L'*' && out[1] == 0) out[0] = 0;                              // "any program" gives way to the first real entry
    for (int i = 0; i < n; i++)
    {
        const wchar_t* nm = names[i];
        size_t len = out[0] ? wcslen(out) : 0, nl = nm ? wcslen(nm) : 0;
        if (!nm || nl == 0 || wcspbrk(nm, L";,\"")) { bad++; continue; }
        if (AppListContains(out, nm)) { dup++; continue; }
        const wchar_t* sep = len == 0 ? L"" : (out[len - 1] == L';') ? L" " : L"; ";
        if (len + wcslen(sep) + nl >= PB_APPS_MAX) { bad++; continue; }
        _snwprintf_s(out + len, PB_APPS_MAX - len, _TRUNCATE, L"%s%s", sep, nm);
        added++;
    }
    if (added) SetWindowTextW(e, out);
    if (skipped) *skipped = bad;
    if (duplicates) *duplicates = dup;
    return added;
}

// AppendApps + the "list is full" message (kept apart so tests can call AppendApps without a message box)
static void ApplyApps(HWND dlg, const AppList* l)
{
    int bad = 0;
    AppendApps(dlg, (const wchar_t* const*)l->v, l->n, &bad, NULL);
    if (bad > 0)
    {
        wchar_t m[256]; _snwprintf_s(m, ARRAYSIZE(m), _TRUNCATE, T(S_PP_FULL), PB_APPS_MAX - 1, bad);
        MessageBoxW(dlg, m, APP_TITLE, MB_OK | MB_ICONWARNING);
    }
}

// Browse: the modern Windows file dialog. Unlike the old GetOpenFileName multi-select it accepts files from DIFFERENT
// folders (for example the results of a search), and has no fixed buffer to overflow. Adds the file NAMES.
static BOOL BrowseExecutables(HWND owner, AppList* out)
{
    BOOL got = FALSE;
    HRESULT co = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    IFileOpenDialog* fd = NULL;
    if (SUCCEEDED(CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileOpenDialog, (void**)&fd)))
    {
        DWORD opt = 0; IFileOpenDialog_GetOptions(fd, &opt);
        IFileOpenDialog_SetOptions(fd, opt | FOS_ALLOWMULTISELECT | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST);
        COMDLG_FILTERSPEC spec[2] = { { L"Executables", L"*.exe" }, { L"All Files", L"*.*" } };
        IFileOpenDialog_SetFileTypes(fd, 2, spec);
        IFileOpenDialog_SetFileTypeIndex(fd, 1);
        IFileOpenDialog_SetTitle(fd, L"Select Process Executable(s)");
        if (SUCCEEDED(IFileOpenDialog_Show(fd, owner)))
        {
            IShellItemArray* arr = NULL;
            if (SUCCEEDED(IFileOpenDialog_GetResults(fd, &arr)))
            {
                DWORD cnt = 0; IShellItemArray_GetCount(arr, &cnt);
                for (DWORD i = 0; i < cnt; i++)
                {
                    IShellItem* it = NULL;
                    if (FAILED(IShellItemArray_GetItemAt(arr, i, &it))) continue;
                    PWSTR path = NULL;
                    if (SUCCEEDED(IShellItem_GetDisplayName(it, SIGDN_FILESYSPATH, &path)) && path)
                    {
                        const wchar_t* base = path;
                        for (const wchar_t* q = path; *q; q++) if (*q == L'\\' || *q == L'/') base = q + 1;
                        if (*base) { AppListAdd(out, base); got = TRUE; }
                        CoTaskMemFree(path);
                    }
                    IShellItem_Release(it);
                }
                IShellItemArray_Release(arr);
            }
        }
        IFileOpenDialog_Release(fd);
    }
    if (SUCCEEDED(co)) CoUninitialize();
    return got;
}

// ---- Running-programs picker ----
// One row per running PROGRAM (same executable path; or same name when the path cannot be read). The PID shown is
// the lowest one of that program and is for reference only - nothing here ever writes a PID into a rule.
typedef struct { wchar_t name[260]; wchar_t path[MAX_PATH]; DWORD pid; int instances; } PPRow;

static int PPCompare(const void* a, const void* b)
{
    const PPRow* x = (const PPRow*)a; const PPRow* y = (const PPRow*)b;
    int c = _wcsicmp(x->name, y->name);
    return c ? c : _wcsicmp(x->path, y->path);
}

static int PPEnumerateReal(PPRow** out)
{
    *out = NULL;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    int cap = 256, n = 0;
    PPRow* rows = (PPRow*)calloc((size_t)cap, sizeof(PPRow));
    if (!rows) { CloseHandle(snap); return 0; }
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
    {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;           // Idle and System are not programs
        wchar_t path[MAX_PATH]; path[0] = 0;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (h) { DWORD len = MAX_PATH; if (!QueryFullProcessImageNameW(h, 0, path, &len)) path[0] = 0; CloseHandle(h); }
        int found = -1;
        for (int i = 0; i < n && found < 0; i++)
            if (path[0] ? (rows[i].path[0] && !_wcsicmp(rows[i].path, path)) : (!rows[i].path[0] && !_wcsicmp(rows[i].name, pe.szExeFile))) found = i;
        if (found >= 0) { rows[found].instances++; if (pe.th32ProcessID < rows[found].pid) rows[found].pid = pe.th32ProcessID; continue; }
        if (n == cap)
        {
            PPRow* g = (PPRow*)realloc(rows, (size_t)cap * 2 * sizeof(PPRow));
            if (!g) break;
            rows = g; cap *= 2;
        }
        PPRow* r = &rows[n++]; ZeroMemory(r, sizeof(*r));
        lstrcpynW(r->name, pe.szExeFile, 260); lstrcpynW(r->path, path, MAX_PATH); r->pid = pe.th32ProcessID; r->instances = 1;
    }
    CloseHandle(snap);
    qsort(rows, (size_t)n, sizeof(PPRow), PPCompare);
    *out = rows;
    return n;
}
static int (*g_ppEnumerate)(PPRow**) = PPEnumerateReal;       // replaced by a fake list in the tests

typedef struct { AppList* result; PPRow* rows; int n; int* shown; int shownN; } PPState;

static void PPRefill(HWND dlg, PPState* st)
{
    HWND lv = GetDlgItem(dlg, IDC_PP_LIST);
    wchar_t q[256]; GetDlgItemTextW(dlg, IDC_PP_SEARCH, q, ARRAYSIZE(q));
    wchar_t words[8][64]; int nw = 0;                           // every word must appear in the name or the path
    for (const wchar_t* p = q; *p && nw < 8; )
    {
        while (*p && *p <= L' ') p++;
        if (!*p) break;
        int k = 0; while (*p && *p > L' ') { if (k < 63) words[nw][k++] = *p; p++; }
        words[nw++][k] = 0;
    }
    SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv);
    st->shownN = 0;
    for (int i = 0; i < st->n; i++)
    {
        const PPRow* r = &st->rows[i];
        BOOL ok = TRUE;
        for (int w = 0; w < nw && ok; w++) ok = ContainsCI(r->name, words[w]) || ContainsCI(r->path, words[w]);
        if (!ok) continue;
        int row = st->shownN++;
        st->shown[row] = i;
        LVITEMW it; ZeroMemory(&it, sizeof(it)); it.mask = LVIF_TEXT; it.iItem = row; it.pszText = (LPWSTR)r->name;
        ListView_InsertItem(lv, &it);
        wchar_t pid[48];
        if (r->instances > 1) _snwprintf_s(pid, ARRAYSIZE(pid), _TRUNCATE, L"%lu  (+%d)", r->pid, r->instances - 1);
        else                  _snwprintf_s(pid, ARRAYSIZE(pid), _TRUNCATE, L"%lu", r->pid);
        ListView_SetItemText(lv, row, 1, pid);
        ListView_SetItemText(lv, row, 2, r->path[0] ? (LPWSTR)r->path : (LPWSTR)L"\x2014");
    }
    SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
    EnableWindow(GetDlgItem(dlg, IDOK), ListView_GetSelectedCount(lv) > 0);
    wchar_t status[200]; _snwprintf_s(status, ARRAYSIZE(status), _TRUNCATE, T(S_PP_STATUS), st->n);
    SetDlgItemTextW(dlg, IDC_PP_STATUS, status);
}

static void PPReload(HWND dlg, PPState* st)
{
    free(st->rows); free(st->shown);
    st->rows = NULL; st->shown = NULL; st->n = 0; st->shownN = 0;
    st->n = g_ppEnumerate(&st->rows);
    if (st->n < 0 || !st->rows) st->n = 0;
    st->shown = (int*)calloc((size_t)(st->n > 0 ? st->n : 1), sizeof(int));
    if (!st->shown) { free(st->rows); st->rows = NULL; st->n = 0; st->shown = (int*)calloc(1, sizeof(int)); }
    PPRefill(dlg, st);
}

// Only ever a name, or a path when "full path" is ticked and the path is usable in the list ("," ";" and quotes are not).
static const wchar_t* PPChoose(const PPRow* r, BOOL fullPath)
{
    if (fullPath && r->path[0] && !wcspbrk(r->path, L";,\"")) return r->path;
    return r->name;
}

INT_PTR CALLBACK ProcPickDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    PPState* st = (PPState*)GetWindowLongPtrW(dlg, GWLP_USERDATA);
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        st = (PPState*)calloc(1, sizeof(PPState));
        st->result = (AppList*)lp;
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)st);
        SetWindowTextW(dlg, T(S_DLG_PROCPICK));
        SetDlgItemTextW(dlg, IDC_PP_REFRESH,  T(S_PP_REFRESH));
        SetDlgItemTextW(dlg, IDC_PP_FULLPATH, T(S_PP_FULLPATH));
        SetDlgItemTextW(dlg, IDC_PP_NOTE,     T(S_PP_NOTE));
        SetDlgItemTextW(dlg, IDOK,            T(S_BTN_ADD));
        SetDlgItemTextW(dlg, IDCANCEL,        T(S_BTN_CANCEL));
        SendDlgItemMessageW(dlg, IDC_PP_SEARCH, EM_LIMITTEXT, 255, 0);
        SendDlgItemMessageW(dlg, IDC_PP_SEARCH, EM_SETCUEBANNER, TRUE, (LPARAM)T(S_PP_SEARCH));
        InitDarkMode(dlg);
        HWND lv = GetDlgItem(dlg, IDC_PP_LIST);
        DarkListView(lv, 0);
        struct { int s; int w; } cols[] = { {S_PP_COL_NAME, 150}, {S_PP_COL_PID, 80}, {S_PP_COL_PATH, 380} };
        LVCOLUMNW c; c.mask = LVCF_TEXT | LVCF_WIDTH;
        for (int i = 0; i < 3; i++) { c.pszText = (LPWSTR)T(cols[i].s); c.cx = cols[i].w; ListView_InsertColumn(lv, i, &c); }
        PPReload(dlg, st);
        return TRUE;
    }
    PB_DARK_CTLCOLORS;
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_PP_LIST && nh->code == LVN_ITEMCHANGED)
            EnableWindow(GetDlgItem(dlg, IDOK), ListView_GetSelectedCount(GetDlgItem(dlg, IDC_PP_LIST)) > 0);
        else if (nh->idFrom == IDC_PP_LIST && nh->code == NM_DBLCLK && ListView_GetSelectedCount(GetDlgItem(dlg, IDC_PP_LIST)) > 0)
            PostMessageW(dlg, WM_COMMAND, IDOK, 0);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDC_PP_SEARCH:  if (HIWORD(wp) == EN_CHANGE && st) PPRefill(dlg, st); return TRUE;
        case IDC_PP_REFRESH: if (st) PPReload(dlg, st); return TRUE;
        case IDOK:
        {
            HWND lv = GetDlgItem(dlg, IDC_PP_LIST);
            BOOL full = IsDlgButtonChecked(dlg, IDC_PP_FULLPATH) == BST_CHECKED;
            for (int row = ListView_GetNextItem(lv, -1, LVNI_SELECTED); row >= 0 && st; row = ListView_GetNextItem(lv, row, LVNI_SELECTED))
                if (row < st->shownN) AppListAdd(st->result, PPChoose(&st->rows[st->shown[row]], full));
            EndDialog(dlg, (st && st->result->n > 0) ? 1 : 0);
            return TRUE;
        }
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    case WM_DESTROY:
        if (st) { free(st->rows); free(st->shown); free(st); SetWindowLongPtrW(dlg, GWLP_USERDATA, 0); }
        return FALSE;
    }
    return FALSE;
}


// Edit sub-dialog. lParam is a PBRule* seeded with current values; on OK it is written back
// (name/proc/hosts/ports/domains/proto/action/cfgStoredId/enabled) and the dialog returns 1.
// "Also proxy localhost traffic" only means something for a PROXY rule (DIRECT / BLOCK never
// send traffic to a proxy), so show it only while the Action list has a proxy selected.
// Action list: 0 = Direct, 1 = Block, 2.. = one entry per proxy server.
static void RuleSyncLocalhostVisibility(HWND dlg)
{
    int asel = (int)SendMessageW(GetDlgItem(dlg, IDC_RE_ACTION), CB_GETCURSEL, 0, 0);
    int show = (asel >= 2) ? SW_SHOW : SW_HIDE;
    ShowWindow(GetDlgItem(dlg, IDC_RE_LOCALHOST), show);
    ShowWindow(GetDlgItem(dlg, IDC_RE_EX_LOCAL),  show);
}

INT_PTR CALLBACK RuleEditDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)lp);
        PBRule* r = (PBRule*)lp;
        SetWindowTextW(dlg, T(S_DLG_RULE));
        SetDlgItemTextW(dlg, IDC_RE_L_NAME,   T(S_L_NAME));
        SetDlgItemTextW(dlg, IDC_RE_ENABLED,  T(S_CHK_ENABLED));
        SetDlgItemTextW(dlg, IDC_RE_L_APPS,   T(S_L_APPS));
        SetDlgItemTextW(dlg, IDC_RE_L_HOSTS,  T(S_L_HOSTS));
        SetDlgItemTextW(dlg, IDC_RE_L_PORTS,  T(S_L_PORTS));
        SetDlgItemTextW(dlg, IDC_RE_L_PROTO,  T(S_L_PROTO));
        SetDlgItemTextW(dlg, IDC_RE_L_ACTION, T(S_L_ACTION));
        SetDlgItemTextW(dlg, IDC_RE_BROWSE,   T(S_BTN_BROWSE));
        SetDlgItemTextW(dlg, IDC_RE_RUNNING,  T(S_BTN_RUNNING));
        SetDlgItemTextW(dlg, IDC_RE_EX_APPS,    T(S_EX_APPS));
        SetDlgItemTextW(dlg, IDC_RE_EX_HOSTS,   T(S_EX_HOSTS));
        SetDlgItemTextW(dlg, IDC_RE_EX_PORTS,   T(S_EX_PORTS));
        SetDlgItemTextW(dlg, IDC_RE_UDPNOTE,    T(S_UDP_NOTE));
        SetDlgItemTextW(dlg, IDC_RE_LOCALHOST,  T(S_CHK_LOCALHOST));
        SetDlgItemTextW(dlg, IDC_RE_EX_LOCAL,   T(S_EX_LOCALHOST));
        SetDlgItemTextW(dlg, IDOK,            T(S_BTN_OK));
        SetDlgItemTextW(dlg, IDCANCEL,        T(S_BTN_CANCEL));
        HWND pr = GetDlgItem(dlg, IDC_RE_PROTO);
        SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)L"TCP");
        SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)L"UDP");
        SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)L"BOTH");
        // Action combo: Direct, Block, then one entry per configured proxy (item data = storedId).
        HWND ac = GetDlgItem(dlg, IDC_RE_ACTION);
        SendMessageW(ac, CB_SETITEMDATA, SendMessageW(ac, CB_ADDSTRING, 0, (LPARAM)L"Direct"), 0);
        SendMessageW(ac, CB_SETITEMDATA, SendMessageW(ac, CB_ADDSTRING, 0, (LPARAM)L"Block"),  0);
        for (int i = 0; i < g_profile.cfgCount; i++)
        {
            PBConfig* c = &g_profile.cfg[i];
            wchar_t label[320];
            _snwprintf_s(label, 320, _TRUNCATE, L"%s  %s  %s:%s", c->name[0] ? c->name : c->type, c->type, c->host, c->port);
            label[319] = 0;
            LRESULT idx = SendMessageW(ac, CB_ADDSTRING, 0, (LPARAM)label);
            SendMessageW(ac, CB_SETITEMDATA, idx, c->storedId);
        }
        SendMessageW(ac, CB_SETDROPPEDWIDTH, 360, 0);
        // Seed fields from the rule.
        SetDlgItemTextW(dlg, IDC_RE_NAME,    r->name[0]    ? r->name    : L"ProxyBridge Rule");
        SendDlgItemMessageW(dlg, IDC_RE_APPS, EM_LIMITTEXT, PB_APPS_MAX - 1, 0);
        SetDlgItemTextW(dlg, IDC_RE_APPS,    r->proc[0]    ? r->proc    : L"*");
        SetDlgItemTextW(dlg, IDC_RE_PORTS,   r->ports[0]   ? r->ports   : L"*");
        {
            // multiline editor: one entry per line (the line breaks are display-only, removed again on save)
            HWND he = GetDlgItem(dlg, IDC_RE_HOSTS);
            SendMessageW(he, EM_LIMITTEXT, PB_HOSTS_MAX * 3, 0);
            size_t fcap = wcslen(r->hosts) * 3 + 4;
            wchar_t* fmt = (wchar_t*)malloc(fcap * sizeof(wchar_t));
            if (fmt) { PB_ListFormat(r->hosts[0] ? r->hosts : L"*", fmt, fcap); SetWindowTextW(he, fmt); free(fmt); }
            else SetWindowTextW(he, L"*");
        }
        SendMessageW(pr, CB_SETCURSEL, ProtoIdx(r->proto[0] ? r->proto : L"BOTH"), 0);
        int target = 0;
        if (!_wcsicmp(r->action, L"BLOCK")) target = 1;
        else if (!_wcsicmp(r->action, L"DIRECT")) target = 0;
        else if (!_wcsicmp(r->action, L"PROXY"))
        {
            int n = (int)SendMessageW(ac, CB_GETCOUNT, 0, 0);
            for (int k = 2; k < n; k++)
                if ((UINT32)SendMessageW(ac, CB_GETITEMDATA, k, 0) == r->cfgStoredId) { target = k; break; }
        }
        SendMessageW(ac, CB_SETCURSEL, target, 0);
        CheckDlgButton(dlg, IDC_RE_ENABLED, r->enabled ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_RE_LOCALHOST, r->localhost ? BST_CHECKED : BST_UNCHECKED);
        RuleSyncLocalhostVisibility(dlg);
        InitDarkMode(dlg);
        return TRUE;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN:
        return DlgCtlColor(wp);
    case WM_CTLCOLORSTATIC:
    {
        HDC dc = (HDC)wp;
        int id = GetDlgCtrlID((HWND)lp);
        SetBkColor(dc, C_BG);
        if (id == IDC_RE_UDPNOTE) SetTextColor(dc, C_WARN);
        else if (id == IDC_RE_EX_APPS || id == IDC_RE_EX_HOSTS ||
                 id == IDC_RE_EX_PORTS || id == IDC_RE_EX_LOCAL) SetTextColor(dc, C_DIM);
        else SetTextColor(dc, C_TEXT);
        return (INT_PTR)g_brBg;
    }
    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDC_RE_ACTION:
            if (HIWORD(wp) == CBN_SELCHANGE) RuleSyncLocalhostVisibility(dlg);
            return TRUE;
        case IDC_RE_BROWSE:
        {
            AppList l = { 0 };                                 // file names only; files from different folders are fine
            if (BrowseExecutables(dlg, &l)) ApplyApps(dlg, &l);
            AppListFree(&l);
            return TRUE;
        }
        case IDC_RE_RUNNING:
        {
            AppList l = { 0 };                                 // program names (never PIDs) from the running programs
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROCPICK), dlg, ProcPickDlgProc, (LPARAM)&l) == 1) ApplyApps(dlg, &l);
            AppListFree(&l);
            return TRUE;
        }
        case IDOK:
        {
            PBRule* r = (PBRule*)GetWindowLongPtrW(dlg, GWLP_USERDATA);
            GetDlgItemTextW(dlg, IDC_RE_NAME,    r->name,    128);
            if (!r->name[0]) lstrcpynW(r->name, L"ProxyBridge Rule", 128);
            GetDlgItemTextW(dlg, IDC_RE_APPS,    r->proc,    PB_APPS_MAX);
            GetDlgItemTextW(dlg, IDC_RE_PORTS,   r->ports,   128);
            {
                // read the whole text (line breaks included), clean it up, and refuse - not cut - a list that is too long
                HWND he = GetDlgItem(dlg, IDC_RE_HOSTS);
                int hn = GetWindowTextLengthW(he);
                wchar_t* htxt = (wchar_t*)malloc(((size_t)hn + 1) * sizeof(wchar_t));
                if (!htxt) { MessageBoxW(dlg, L"Out of memory.", APP_TITLE, MB_OK | MB_ICONERROR); return TRUE; }
                GetWindowTextW(he, htxt, hn + 1);
                PB_ListNormalize(htxt);
                if (wcslen(htxt) >= PB_HOSTS_MAX)
                {
                    wchar_t m[96]; _snwprintf_s(m, ARRAYSIZE(m), _TRUNCATE, L"Target Hosts is too long (maximum %d characters).", PB_HOSTS_MAX - 1);
                    MessageBoxW(dlg, m, APP_TITLE, MB_OK | MB_ICONWARNING);
                    free(htxt);
                    return TRUE;
                }
                lstrcpynW(r->hosts, htxt, PB_HOSTS_MAX);
                free(htxt);
            }
            if (!r->proc[0])    lstrcpynW(r->proc,    L"*", 256);
            if (!r->hosts[0])   lstrcpynW(r->hosts,   L"*", PB_HOSTS_MAX);
            if (!r->ports[0])   lstrcpynW(r->ports,   L"*", 128);
            lstrcpynW(r->proto, ProtoName((int)SendMessageW(GetDlgItem(dlg, IDC_RE_PROTO), CB_GETCURSEL, 0, 0)), 8);
            HWND ac = GetDlgItem(dlg, IDC_RE_ACTION);
            int asel = (int)SendMessageW(ac, CB_GETCURSEL, 0, 0);
            if (asel == 0)      { lstrcpynW(r->action, L"DIRECT", 16); r->cfgStoredId = 0; }
            else if (asel == 1) { lstrcpynW(r->action, L"BLOCK",  16); r->cfgStoredId = 0; }
            else                { lstrcpynW(r->action, L"PROXY",  16);
                                  r->cfgStoredId = (UINT32)SendMessageW(ac, CB_GETITEMDATA, asel, 0); }
            r->enabled = (IsDlgButtonChecked(dlg, IDC_RE_ENABLED) == BST_CHECKED) ? 1 : 0;
            r->localhost = (asel >= 2 && IsDlgButtonChecked(dlg, IDC_RE_LOCALHOST) == BST_CHECKED) ? 1 : 0;   // only for PROXY rules
            EndDialog(dlg, 1);
            return TRUE;
        }
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

static void SwapRules(HWND lv, int a, int b)
{
    if (a < 0 || b < 0 || a >= g_profile.ruleCount || b >= g_profile.ruleCount) return;
    PBRule t = g_profile.rule[a]; g_profile.rule[a] = g_profile.rule[b]; g_profile.rule[b] = t;
    // Reorder inside the engine without recreating rules - the rule keeps its native id.
    // MoveRuleToPosition takes a 1-based position; the moved rule now sits at array index b.
    if (g_profile.rule[b].nativeId)
        g_api.MoveRuleToPosition(g_profile.rule[b].nativeId, (UINT32)(b + 1));
    SaveActive();
    RefreshRulesList(lv);
    SelectRuleIndex(lv, b);
}

INT_PTR CALLBACK RulesDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowTextW(dlg, T(S_DLG_RULES));
        SetDlgItemTextW(dlg, IDC_RL_ADD,    T(S_BTN_ADDDOTS));
        SetDlgItemTextW(dlg, IDC_RL_CLONE,  T(S_BTN_CLONE));
        SetDlgItemTextW(dlg, IDC_RL_EDIT,   T(S_BTN_EDITDOTS));
        SetDlgItemTextW(dlg, IDC_RL_REMOVE, T(S_BTN_REMOVE));
        SetDlgItemTextW(dlg, IDC_RL_UP,     T(S_BTN_UP));
        SetDlgItemTextW(dlg, IDC_RL_DOWN,   T(S_BTN_DOWN));
        SetDlgItemTextW(dlg, IDC_RL_HINT,   T(S_RULES_HINT));
        SetDlgItemTextW(dlg, IDCANCEL,      T(S_BTN_CLOSE));
        SetDlgItemTextW(dlg, IDC_RL_CLEAR,  L"\x2715");             // multiplication X
        InitDarkMode(dlg);
        InitRulesList(GetDlgItem(dlg, IDC_RL_LIST));
        g_rlWordN = 0; g_rlMapN = 0;                                  // always open with the full list
        SendDlgItemMessageW(dlg, IDC_RL_SEARCH, EM_LIMITTEXT, 255, 0);
        SendDlgItemMessageW(dlg, IDC_RL_SEARCH, EM_SETCUEBANNER, TRUE, (LPARAM)T(S_RULES_SEARCH));
        SetWindowSubclass(GetDlgItem(dlg, IDC_RL_SEARCH), RuleSearchProc, 4, 0);
        SetWindowSubclass(GetDlgItem(dlg, IDC_RL_LIST),   RuleListProc,   5, 0);
        RefreshRulesList(GetDlgItem(dlg, IDC_RL_LIST));
        return TRUE;
    case WM_SIZE:
        FillColumns(GetDlgItem(dlg, IDC_RL_LIST), 8);
        return FALSE;
    PB_DARK_CTLCOLORS;
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        HWND lv = GetDlgItem(dlg, IDC_RL_LIST);
        if (nh->idFrom == IDC_RL_LIST && nh->code == NM_DBLCLK)
        {
            PostMessageW(dlg, WM_COMMAND, IDC_RL_EDIT, 0);
        }
        else if (nh->idFrom == IDC_RL_LIST && nh->code == LVN_ITEMCHANGED && !g_rulesRefreshing)
        {
            NMLISTVIEW* nlv = (NMLISTVIEW*)lp;
            if ((nlv->uChanged & LVIF_STATE) && (nlv->uNewState & LVIS_STATEIMAGEMASK) &&
                nlv->iItem >= 0 && nlv->iItem < g_rlMapN)
            {
                int ri = g_rlMap[nlv->iItem];                         // row -> rule index
                BOOL checked = ListView_GetCheckState(lv, nlv->iItem);
                PBRule* r = &g_profile.rule[ri];
                if ((BOOL)r->enabled != checked)
                {
                    r->enabled = checked ? 1 : 0;
                    if (r->enabled) g_api.EnableRule(r->nativeId); else g_api.DisableRule(r->nativeId);
                    SaveActive();
                }
            }
        }
        return TRUE;
    }
    case WM_COMMAND:
    {
        HWND lv = GetDlgItem(dlg, IDC_RL_LIST);
        int sel = SelectedRuleIndex(lv);                              // index in g_profile.rule, not a row number
        switch (LOWORD(wp))
        {
        case IDC_RL_SEARCH:
            if (HIWORD(wp) == EN_CHANGE) RulesApplyFilterFromBox(dlg);
            return TRUE;
        case IDC_RL_CLEAR:
            SetDlgItemTextW(dlg, IDC_RL_SEARCH, L"");                 // EN_CHANGE refilters
            SetFocus(GetDlgItem(dlg, IDC_RL_SEARCH));
            return TRUE;
        case IDC_RL_ADD:
        {
            if (g_profile.ruleCount >= PB_MAX_RULE) { MessageBoxW(dlg, L"Rule limit reached.", APP_TITLE, MB_OK); return TRUE; }
            PBRule r; ZeroMemory(&r, sizeof(r));
            lstrcpynW(r.name, L"ProxyBridge Rule", 128);
            lstrcpynW(r.proc, L"*", 256); lstrcpynW(r.hosts, L"*", PB_HOSTS_MAX);
            lstrcpynW(r.ports, L"*", 128);
            lstrcpynW(r.proto, L"BOTH", 8); lstrcpynW(r.action, L"DIRECT", 16); r.enabled = 1;
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_RULE), dlg, RuleEditDlgProc, (LPARAM)&r) == 1)
            {
                UINT32 id = EngineAddRule(&r);          // appended at the end of the engine list
                if (id)
                {
                    r.nativeId = id; g_profile.rule[g_profile.ruleCount++] = r; SaveActive();
                    // a new rule that the active search hides would look like it was lost: show everything instead
                    if (g_rlWordN > 0 && !RuleMatchesFilter(&r)) SetDlgItemTextW(dlg, IDC_RL_SEARCH, L"");
                    RefreshRulesList(lv);
                    SelectRuleIndex(lv, g_profile.ruleCount - 1);
                }
                else MessageBoxW(dlg, T(S_ERR_ADDRULE), APP_TITLE, MB_OK | MB_ICONERROR);
            }
            return TRUE;
        }
        case IDC_RL_CLONE:
        {
            if (sel < 0 || sel >= g_profile.ruleCount) return TRUE;
            if (g_profile.ruleCount >= PB_MAX_RULE) { MessageBoxW(dlg, L"Rule limit reached.", APP_TITLE, MB_OK); return TRUE; }
            PBRule r = g_profile.rule[sel]; r.nativeId = 0;
            UINT32 id = EngineAddRule(&r);              // new engine rule (its own id), added at the end
            if (!id) { MessageBoxW(dlg, T(S_ERR_ADDRULE), APP_TITLE, MB_OK | MB_ICONERROR); return TRUE; }
            r.nativeId = id;
            for (int i = g_profile.ruleCount; i > sel + 1; i--) g_profile.rule[i] = g_profile.rule[i - 1];
            g_profile.rule[sel + 1] = r; g_profile.ruleCount++;
            g_api.MoveRuleToPosition(id, (UINT32)(sel + 2));   // slot it right after the source
            SaveActive(); RefreshRulesList(lv);
            SelectRuleIndex(lv, sel + 1);
            return TRUE;
        }
        case IDC_RL_EDIT:
        {
            if (sel < 0 || sel >= g_profile.ruleCount) return TRUE;
            PBRule r = g_profile.rule[sel];            // keeps nativeId - edited in place
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_RULE), dlg, RuleEditDlgProc, (LPARAM)&r) == 1)
            {
                g_profile.rule[sel] = r;
                EngineEditRule(&r);
                SaveActive(); RefreshRulesList(lv);
                SelectRuleIndex(lv, sel);              // stays unselected if the edit made it stop matching the search
            }
            return TRUE;
        }
        case IDC_RL_REMOVE:
        {
            if (sel < 0 || sel >= g_profile.ruleCount) return TRUE;
            if (g_profile.rule[sel].nativeId) g_api.DeleteRule(g_profile.rule[sel].nativeId);
            for (int i = sel; i < g_profile.ruleCount - 1; i++) g_profile.rule[i] = g_profile.rule[i + 1];
            g_profile.ruleCount--;
            SaveActive(); RefreshRulesList(lv);
            return TRUE;
        }
        case IDC_RL_UP:   if (g_rlWordN == 0 && sel > 0) SwapRules(lv, sel, sel - 1); return TRUE;
        case IDC_RL_DOWN: if (g_rlWordN == 0 && sel >= 0 && sel < g_profile.ruleCount - 1) SwapRules(lv, sel, sel + 1); return TRUE;
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    }
    }
    return FALSE;
}

// Log Filters
INT_PTR CALLBACK FilterEditDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static const wchar_t* kProto[]  = { L"All", L"TCP", L"UDP" };
    static const wchar_t* kAction[] = { L"All", L"Direct", L"Proxy", L"Blocked" };
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)lp);
        PBFilter* f = (PBFilter*)lp;
        SetWindowTextW(dlg, T(S_DLG_FILTER));
        SetDlgItemTextW(dlg, IDC_FE_L_MODE,   T(S_L_MODE));
        SetDlgItemTextW(dlg, IDC_FE_L_PROC,   T(S_L_PROC));
        SetDlgItemTextW(dlg, IDC_FE_L_IP,     T(S_L_IP));
        SetDlgItemTextW(dlg, IDC_FE_L_PORT,   T(S_L_PORT));
        SetDlgItemTextW(dlg, IDC_FE_L_PROTO,  T(S_L_PROTO));
        SetDlgItemTextW(dlg, IDC_FE_L_ACTION, T(S_L_ACTION));
        SetDlgItemTextW(dlg, IDOK, T(S_BTN_OK)); SetDlgItemTextW(dlg, IDCANCEL, T(S_BTN_CANCEL));
        HWND mode = GetDlgItem(dlg, IDC_FE_MODE), pr = GetDlgItem(dlg, IDC_FE_PROTO), ac = GetDlgItem(dlg, IDC_FE_ACTION);
        SendMessageW(mode, CB_ADDSTRING, 0, (LPARAM)L"Include");
        SendMessageW(mode, CB_ADDSTRING, 0, (LPARAM)L"Exclude");
        for (int i = 0; i < 3; i++) SendMessageW(pr, CB_ADDSTRING, 0, (LPARAM)kProto[i]);
        for (int i = 0; i < 4; i++) SendMessageW(ac, CB_ADDSTRING, 0, (LPARAM)kAction[i]);
        SendMessageW(mode, CB_SETCURSEL, (_wcsicmp(f->mode, L"Exclude") == 0) ? 1 : 0, 0);
        SetDlgItemTextW(dlg, IDC_FE_PROC, f->proc);
        SetDlgItemTextW(dlg, IDC_FE_IP,   f->ip);
        SetDlgItemTextW(dlg, IDC_FE_PORT, f->port);
        int pi = 0; if (!_wcsicmp(f->proto, L"TCP")) pi = 1; else if (!_wcsicmp(f->proto, L"UDP")) pi = 2;
        int ai = 0; if (!_wcsicmp(f->action, L"Direct")) ai = 1; else if (!_wcsicmp(f->action, L"Proxy")) ai = 2; else if (!_wcsicmp(f->action, L"Blocked")) ai = 3;
        SendMessageW(pr, CB_SETCURSEL, pi, 0);
        SendMessageW(ac, CB_SETCURSEL, ai, 0);
        InitDarkMode(dlg);
        return TRUE;
    }
    PB_DARK_CTLCOLORS;
    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDOK:
        {
            PBFilter* f = (PBFilter*)GetWindowLongPtrW(dlg, GWLP_USERDATA);
            int m = (int)SendMessageW(GetDlgItem(dlg, IDC_FE_MODE), CB_GETCURSEL, 0, 0);
            lstrcpynW(f->mode, m == 1 ? L"Exclude" : L"Include", 16);
            GetDlgItemTextW(dlg, IDC_FE_PROC, f->proc, 256);
            GetDlgItemTextW(dlg, IDC_FE_IP,   f->ip,   64);
            GetDlgItemTextW(dlg, IDC_FE_PORT, f->port, 16);
            int pi = (int)SendMessageW(GetDlgItem(dlg, IDC_FE_PROTO),  CB_GETCURSEL, 0, 0); if (pi < 0) pi = 0;
            int ai = (int)SendMessageW(GetDlgItem(dlg, IDC_FE_ACTION), CB_GETCURSEL, 0, 0); if (ai < 0) ai = 0;
            lstrcpynW(f->proto,  kProto[pi],  8);
            lstrcpynW(f->action, kAction[ai], 16);
            EndDialog(dlg, 1);
            return TRUE;
        }
        case IDCANCEL: EndDialog(dlg, 0); return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

static void InitFilterList(HWND lv)
{
    DarkListView(lv, 0);
    struct { int s; int w; } cols[] = {
        {S_COL_MODE, 70}, {S_COL_PROC, 150}, {S_COL_IP, 110}, {S_COL_PORTS, 70}, {S_COL_PROTO, 70}, {S_COL_ACTION, 90}
    };
    LVCOLUMNW c; c.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < 6; i++) { c.pszText = (LPWSTR)T(cols[i].s); c.cx = cols[i].w; ListView_InsertColumn(lv, i, &c); }
    SetWindowSubclass(lv, ListDarkSubProc, 3, 0);
    FillColumns(lv, 6);
}
static void RefreshFilterList(HWND lv)
{
    ListView_DeleteAllItems(lv);
    for (int i = 0; i < g_profile.filterCount; i++)
    {
        PBFilter* f = &g_profile.filter[i];
        LVITEMW it; ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT; it.iItem = i; it.pszText = f->mode[0] ? f->mode : (LPWSTR)L"Include";
        ListView_InsertItem(lv, &it);
        ListView_SetItemText(lv, i, 1, f->proc[0]   ? f->proc   : (LPWSTR)L"*");
        ListView_SetItemText(lv, i, 2, f->ip[0]     ? f->ip     : (LPWSTR)L"*");
        ListView_SetItemText(lv, i, 3, f->port[0]   ? f->port   : (LPWSTR)L"*");
        ListView_SetItemText(lv, i, 4, f->proto[0]  ? f->proto  : (LPWSTR)L"All");
        ListView_SetItemText(lv, i, 5, f->action[0] ? f->action : (LPWSTR)L"All");
    }
}
INT_PTR CALLBACK FiltersDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowTextW(dlg, T(S_DLG_FILTERS));
        SetDlgItemTextW(dlg, IDC_FL_DESC,   T(S_FL_DESC));
        SetDlgItemTextW(dlg, IDC_FL_ADD,    T(S_BTN_ADDDOTS));
        SetDlgItemTextW(dlg, IDC_FL_EDIT,   T(S_BTN_EDITDOTS));
        SetDlgItemTextW(dlg, IDC_FL_REMOVE, T(S_BTN_REMOVE));
        SetDlgItemTextW(dlg, IDCANCEL,      T(S_BTN_CLOSE));
        InitDarkMode(dlg);
        InitFilterList(GetDlgItem(dlg, IDC_FL_LIST));
        RefreshFilterList(GetDlgItem(dlg, IDC_FL_LIST));
        return TRUE;
    PB_DARK_CTLCOLORS;
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_FL_LIST && nh->code == NM_DBLCLK) PostMessageW(dlg, WM_COMMAND, IDC_FL_EDIT, 0);
        return TRUE;
    }
    case WM_COMMAND:
    {
        HWND lv = GetDlgItem(dlg, IDC_FL_LIST);
        int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        switch (LOWORD(wp))
        {
        case IDC_FL_ADD:
        {
            if (g_profile.filterCount >= PB_MAX_FILTER) { MessageBoxW(dlg, L"Filter limit reached.", APP_TITLE, MB_OK); return TRUE; }
            PBFilter f; ZeroMemory(&f, sizeof(f));
            lstrcpynW(f.mode, L"Include", 16); lstrcpynW(f.proto, L"All", 8); lstrcpynW(f.action, L"All", 16);
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_FILTER), dlg, FilterEditDlgProc, (LPARAM)&f) == 1)
            { g_profile.filter[g_profile.filterCount++] = f; RefreshFilterList(lv); }
            return TRUE;
        }
        case IDC_FL_EDIT:
        {
            if (sel < 0 || sel >= g_profile.filterCount) return TRUE;
            PBFilter f = g_profile.filter[sel];
            if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_FILTER), dlg, FilterEditDlgProc, (LPARAM)&f) == 1)
            { g_profile.filter[sel] = f; RefreshFilterList(lv);
              ListView_SetItemState(lv, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); }
            return TRUE;
        }
        case IDC_FL_REMOVE:
            if (sel < 0 || sel >= g_profile.filterCount) return TRUE;
            for (int i = sel; i < g_profile.filterCount - 1; i++) g_profile.filter[i] = g_profile.filter[i + 1];
            g_profile.filterCount--;
            RefreshFilterList(lv);
            return TRUE;
        case IDCANCEL: EndDialog(dlg, 1); return TRUE;   // nonzero => caller re-applies + saves
        }
        return FALSE;
    }
    }
    return FALSE;
}

// Name input dialog
INT_PTR CALLBACK NameDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)lp;
    switch (msg)
    {
    case WM_INITDIALOG:
        g_nameResult[0] = 0;
        SetWindowTextW(dlg, T(S_DLG_NEWPROFILE));
        SetDlgItemTextW(dlg, IDC_NAME_PROMPT, T(S_L_PROFNAME));
        SetDlgItemTextW(dlg, IDOK, T(S_BTN_OK));
        SetDlgItemTextW(dlg, IDCANCEL, T(S_BTN_CANCEL));
        InitDarkMode(dlg);
        SetFocus(GetDlgItem(dlg, IDC_NAME_EDIT));
        return FALSE;
    PB_DARK_CTLCOLORS;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) { GetDlgItemTextW(dlg, IDC_NAME_EDIT, g_nameResult, PB_NAME_MAX); EndDialog(dlg, 1); return TRUE; }
        if (LOWORD(wp) == IDCANCEL) { g_nameResult[0] = 0; EndDialog(dlg, 0); return TRUE; }
        return FALSE;
    }
    return FALSE;
}

// About dialog
static void AboutCenterLink(HWND dlg, int id)
{
    HWND h = GetDlgItem(dlg, id);
    SIZE sz = {0};
    SendMessageW(h, LM_GETIDEALSIZE, 0, (LPARAM)&sz);
    RECT cr; GetClientRect(dlg, &cr);
    RECT wr; GetWindowRect(h, &wr);
    POINT p = { wr.left, wr.top }; ScreenToClient(dlg, &p);
    MoveWindow(h, (cr.right - sz.cx) / 2, p.y, sz.cx, sz.cy, TRUE);
}
INT_PTR CALLBACK AboutDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static HFONT s_titleFont = NULL;
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowTextW(dlg, T(S_ABOUT_TITLE));
        SetDlgItemTextW(dlg, IDC_AB_TITLE,   APP_TITLE);
        SetDlgItemTextW(dlg, IDC_AB_VER,     T(S_AB_VERSION));
        SetDlgItemTextW(dlg, IDC_AB_DESC,    T(S_AB_DESC));
        SetDlgItemTextW(dlg, IDC_AB_AUTHOR,  T(S_AB_AUTHOR));
        SetDlgItemTextW(dlg, IDC_AB_WEB,     T(S_AB_WEB));
        SetDlgItemTextW(dlg, IDC_AB_GITHUB,  T(S_AB_GITHUB));
        SetDlgItemTextW(dlg, IDC_AB_LICENSE, T(S_AB_LICENSE));
        SetDlgItemTextW(dlg, IDCANCEL,       T(S_BTN_CLOSE));
        if (!s_titleFont)
            s_titleFont = CreateFontW(-34, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                      DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendDlgItemMessageW(dlg, IDC_AB_TITLE, WM_SETFONT, (WPARAM)s_titleFont, TRUE);
        InitDarkMode(dlg);
        AboutCenterLink(dlg, IDC_AB_WEB);
        AboutCenterLink(dlg, IDC_AB_GITHUB);
        return TRUE;
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLORSTATIC:
    {
        HDC dc = (HDC)wp;
        int id = GetDlgCtrlID((HWND)lp);
        SetBkColor(dc, C_BG);
        SetTextColor(dc, id == IDC_AB_TITLE ? C_ACCENT : (id == IDC_AB_DESC || id == 0 ? C_TEXT : C_DIM));
        return (INT_PTR)g_brBg;
    }
    case WM_NOTIFY:
    {
        LPNMHDR nh = (LPNMHDR)lp;
        if ((nh->code == NM_CLICK || nh->code == NM_RETURN) &&
            (nh->idFrom == IDC_AB_WEB || nh->idFrom == IDC_AB_GITHUB))
        {
            PNMLINK link = (PNMLINK)lp;
            ShellExecuteW(dlg, L"open", link->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDCANCEL || LOWORD(wp) == IDOK) { EndDialog(dlg, 0); return TRUE; }
        return FALSE;
    }
    return FALSE;
}

#endif // PB_UI_DIALOGS_H
