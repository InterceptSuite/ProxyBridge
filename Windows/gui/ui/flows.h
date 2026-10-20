// flows.h - the "Live Connections" tab: the proxied TCP connections and UDP flows that are active right now.
//
// While the tab is open the engine is asked for a snapshot once a second. This file keeps the rows between snapshots,
// notices the ones that vanished (they turn grey and stay listed until "Clear closed" is pressed; when FLOW_ROWS_MAX
// rows are held the oldest finished one is replaced) and feeds a virtual ListView, which stores no text of its own -
// cell text is produced on demand for the visible rows only. Leaving the tab stops the timer and frees the snapshot
// buffer, so polling costs nothing while it is not looked at; the finished rows are kept.
//
// Included by main.c (after the log view); the pieces that need a window are at the bottom.

#define FLOW_ROWS_MAX   1200      // hard cap on rows kept (live + finished); ~190 KB at most
#define FLOW_POLL_MS    1000
#define IDC_FLOWS       3010
#define IDC_FLOWS_CLEAR 3011
#define TIMER_FLOWS     2

typedef struct {
    UINT64    id;
    DWORD     pid;
    UINT32    proxyId;
    UINT32    ruleId;             // engine id of the rule that matched (0 = not known)
    ULONGLONG firstSeen;          // tick when the connection started (engine age when known, else first poll that saw it)
    ULONGLONG closedAt;           // 0 = still alive
    UINT64    sent, received;
    UINT16    port;
    UINT8     udp, v6;
    char      name[40];           // UTF-8
    char      host[64];           // UTF-8
} FlowRow;

static FlowRow* g_fl = NULL;      // rows, in the order they appeared
static int      g_flN = 0, g_flCap = 0;
static int*     g_flView = NULL;  // g_fl indexes in display order
static int      g_flSortCol = 3, g_flSortAsc = 0;   // default: newest first
static ULONGLONG g_flNow = 0;     // tick of the last poll (cell text is computed against it)
static HWND     g_hFlows = NULL, g_hFlowsClear = NULL;
static PBFlow*  g_flSnap = NULL;  // snapshot buffer, allocated only while the tab is open

static void FlowsClear(void)
{
    free(g_fl); free(g_flView);
    g_fl = NULL; g_flView = NULL; g_flN = g_flCap = 0;
}

// ---- display order ----
static int FlowCmp(const void* a, const void* b)
{
    const FlowRow* x = &g_fl[*(const int*)a]; const FlowRow* y = &g_fl[*(const int*)b];
    int c = 0;
    switch (g_flSortCol)
    {
    case 0:  c = _stricmp(x->name, y->name); if (!c) c = (x->pid > y->pid) - (x->pid < y->pid); break;
    case 1:  c = _stricmp(x->host, y->host); if (!c) c = (x->port > y->port) - (x->port < y->port); break;
    case 2:  c = (x->udp > y->udp) - (x->udp < y->udp); break;
    case 3:  c = (x->firstSeen > y->firstSeen) - (x->firstSeen < y->firstSeen); break;   // ascending = longest running first
    case 4:  c = (x->ruleId > y->ruleId) - (x->ruleId < y->ruleId); if (!c) c = (x->proxyId > y->proxyId) - (x->proxyId < y->proxyId); break;
    case 5:  c = (x->sent > y->sent) - (x->sent < y->sent); break;
    default: c = (x->received > y->received) - (x->received < y->received); break;
    }
    if (c == 0) c = (x->id > y->id) - (x->id < y->id);                 // stable
    return g_flSortAsc ? c : -c;
}
static void FlowsSortView(void)
{
    for (int i = 0; i < g_flN; i++) g_flView[i] = i;
    if (g_flN > 1) qsort(g_flView, (size_t)g_flN, sizeof(int), FlowCmp);
}

// ---- keeping the rows ----
static void FlowSet(FlowRow* r, const PBFlow* s)
{
    r->pid = s->pid; r->proxyId = s->proxy_config_id; r->ruleId = s->rule_id; r->port = s->port; r->udp = s->is_udp; r->v6 = s->is_ipv6;
    r->sent = s->sent; r->received = s->received;
    memcpy(r->name, s->name, sizeof(r->name)); r->name[sizeof(r->name) - 1] = 0;
    memcpy(r->host, s->host, sizeof(r->host)); r->host[sizeof(r->host) - 1] = 0;
}

// Merges one snapshot (n flows) into the rows. `truncated` = the engine had more flows than it returned, so a flow
// that is missing from the snapshot may still be alive and must not be marked finished.
static void FlowsApply(const PBFlow* snap, int n, BOOL truncated, ULONGLONG now)
{
    int oldN = g_flN;
    unsigned char* seen = oldN > 0 ? (unsigned char*)calloc((size_t)oldN, 1) : NULL;
    if (oldN > 0 && seen == NULL) return;                              // out of memory: keep what is shown

    for (int i = 0; i < n; i++)
    {
        const PBFlow* s = &snap[i];
        int j = 0;
        while (j < oldN && g_fl[j].id != s->id) j++;                   // a few hundred rows at most, once a second
        ULONGLONG start = (s->age_ms != 0xFFFFFFFFu && s->age_ms <= now) ? now - s->age_ms : now;
        if (j < oldN)
        {
            seen[j] = 1;
            FlowRow* r = &g_fl[j];
            if (r->closedAt) { r->closedAt = 0; r->firstSeen = start; } // an idle UDP flow that woke up again
            FlowSet(r, s);
        }
        else if (g_flN < FLOW_ROWS_MAX)
        {
            if (g_flN == g_flCap)
            {
                int nc = g_flCap ? g_flCap * 2 : 64;
                FlowRow* g = (FlowRow*)realloc(g_fl, (size_t)nc * sizeof(FlowRow));
                if (!g) continue;
                g_fl = g; g_flCap = nc;
            }
            FlowRow* r = &g_fl[g_flN++];
            ZeroMemory(r, sizeof(*r));
            r->id = s->id; r->firstSeen = start;
            FlowSet(r, s);
        }
        else                                                           // full: the oldest finished row makes room
        {
            int e = -1;
            for (int q = 0; q < oldN; q++)
                if (g_fl[q].closedAt && (e < 0 || g_fl[q].closedAt < g_fl[e].closedAt)) e = q;
            if (e >= 0)
            {
                seen[e] = 1;                                           // the new flow lives in this slot now
                FlowRow* r = &g_fl[e];
                ZeroMemory(r, sizeof(*r));
                r->id = s->id; r->firstSeen = start;
                FlowSet(r, s);
            }
        }
    }
    if (!truncated)
        for (int j = 0; j < oldN; j++)
            if (!seen[j] && g_fl[j].closedAt == 0) g_fl[j].closedAt = now;
    free(seen);

    int* v = (int*)realloc(g_flView, (size_t)(g_flN > 0 ? g_flN : 1) * sizeof(int));
    if (!v) { g_flN = 0; return; }
    g_flView = v;
    g_flNow = now;
    FlowsSortView();
}

// ---- cell text ----
static void FlowDuration(ULONGLONG ms, wchar_t* out, int cch)
{
    ULONGLONG s = ms / 1000;
    if (s >= 3600) _snwprintf_s(out, cch, _TRUNCATE, L"%llu:%02llu:%02llu", s / 3600, (s / 60) % 60, s % 60);
    else           _snwprintf_s(out, cch, _TRUNCATE, L"%llu:%02llu", s / 60, s % 60);
}
static void FlowBytes(UINT64 b, wchar_t* out, int cch)
{
    if (b < 1024)                  _snwprintf_s(out, cch, _TRUNCATE, L"%llu B", b);
    else if (b < 1024ull * 1024)   _snwprintf_s(out, cch, _TRUNCATE, L"%.1f KB", (double)b / 1024.0);
    else if (b < 1024ull << 20)    _snwprintf_s(out, cch, _TRUNCATE, L"%.1f MB", (double)b / (1024.0 * 1024.0));
    else                           _snwprintf_s(out, cch, _TRUNCATE, L"%.2f GB", (double)b / (1024.0 * 1024.0 * 1024.0));
}
static void FlowUtf8(const char* s, wchar_t* out, int cch)
{
    if (cch <= 0) return;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, cch) == 0) out[0] = 0;
}
// "Rule : Proxy Name (SOCKS5 host:port)" - which rule sent the connection through which proxy. A rule that is no longer
// in the profile (or an engine that does not say) leaves just the proxy; the engine uses the first proxy for id 0.
static void FlowRuleProxy(UINT32 ruleId, UINT32 proxyId, wchar_t* out, int cch)
{
    wchar_t rule[128]; rule[0] = 0;
    if (ruleId)
        for (int i = 0; i < g_profile.ruleCount; i++)
            if (g_profile.rule[i].nativeId == ruleId) { lstrcpynW(rule, g_profile.rule[i].name[0] ? g_profile.rule[i].name : g_profile.rule[i].proc, 128); break; }
    wchar_t prox[320];
    const PBConfig* c = NULL;
    for (int i = 0; i < g_profile.cfgCount && !c; i++)
        if (g_profile.cfg[i].nativeId == proxyId || (proxyId == 0 && i == 0)) c = &g_profile.cfg[i];
    if (c) _snwprintf_s(prox, ARRAYSIZE(prox), _TRUNCATE, L"%s (%s %s:%s)", c->name[0] ? c->name : c->host, c->type, c->host, c->port);
    else   _snwprintf_s(prox, ARRAYSIZE(prox), _TRUNCATE, L"#%lu", (unsigned long)proxyId);
    if (rule[0]) _snwprintf_s(out, cch, _TRUNCATE, L"%s : %s", rule, prox);
    else         lstrcpynW(out, prox, cch);
}

static void FlowText(const FlowRow* r, int col, ULONGLONG now, wchar_t* out, int cch)
{
    wchar_t a[96], b[64];
    if (cch <= 0) return;
    out[0] = 0;
    switch (col)
    {
    case 0:
        if (r->name[0]) { FlowUtf8(r->name, a, 96); _snwprintf_s(out, cch, _TRUNCATE, L"%s (%lu)", a, (unsigned long)r->pid); }
        else            _snwprintf_s(out, cch, _TRUNCATE, L"PID %lu", (unsigned long)r->pid);
        break;
    case 1:
        FlowUtf8(r->host, a, 96);
        if (wcschr(a, L':')) _snwprintf_s(out, cch, _TRUNCATE, L"[%s]:%u", a, r->port);       // an IPv6 literal
        else                 _snwprintf_s(out, cch, _TRUNCATE, L"%s:%u", a, r->port);
        break;
    case 2: lstrcpynW(out, r->udp ? L"UDP" : L"TCP", cch); break;
    case 3:
        if (r->closedAt) { FlowDuration(r->closedAt - r->firstSeen, b, 64); _snwprintf_s(out, cch, _TRUNCATE, L"%s %s", T(S_FL_CLOSED), b); }
        else             FlowDuration(now > r->firstSeen ? now - r->firstSeen : 0, out, cch);
        break;
    case 4: FlowRuleProxy(r->ruleId, r->proxyId, out, cch); break;
    case 5: FlowBytes(r->sent, out, cch); break;
    default: FlowBytes(r->received, out, cch); break;
    }
}

// ---- the window ----
static void DarkListView(HWND lv, DWORD extraExStyle);        // dialogs.h

static const int g_flColStr[7] = { S_FL_COL_APP, S_FL_COL_TARGET, S_FL_COL_PROTO, S_FL_COL_STATUS, S_FL_COL_PROXY, S_FL_COL_SENT, S_FL_COL_RECV };

static void FlowsSetColumns(void)
{
    for (int i = 0; i < 7; i++)
    {
        LVCOLUMNW c; c.mask = LVCF_TEXT; c.pszText = (LPWSTR)T(g_flColStr[i]);
        ListView_SetColumn(g_hFlows, i, &c);
    }
}

static HWND FlowsCreate(HWND parent)
{
    g_hFlows = CreateWindowExW(0, WC_LISTVIEWW, NULL,
                               WS_CHILD | WS_BORDER | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
                               0, 0, 0, 0, parent, (HMENU)(UINT_PTR)IDC_FLOWS, g_hInst, NULL);
    if (!g_hFlows) return NULL;
    DarkListView(g_hFlows, LVS_EX_LABELTIP);
    static const int w[7] = { 190, 250, 70, 120, 330, 90, 90 };
    LVCOLUMNW c; c.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < 7; i++) { c.pszText = (LPWSTR)T(g_flColStr[i]); c.cx = Sc(w[i]); ListView_InsertColumn(g_hFlows, i, &c); }
    g_hFlowsClear = CreateWindowExW(0, L"BUTTON", T(S_FL_CLEAR), WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
                                    0, 0, 0, 0, parent, (HMENU)(UINT_PTR)IDC_FLOWS_CLEAR, g_hInst, NULL);
    return g_hFlows;
}

// "Clear closed": removes every finished row; connections that are still alive stay.
static void FlowsClearClosed(void)
{
    int k = 0;
    for (int j = 0; j < g_flN; j++) if (g_fl[j].closedAt == 0) g_fl[k++] = g_fl[j];
    g_flN = k;
    if (g_flView) FlowsSortView();
    if (g_hFlows) { ListView_SetItemCountEx(g_hFlows, g_flN, LVSICF_NOINVALIDATEALL); InvalidateRect(g_hFlows, NULL, FALSE); }
}

// Merges the snapshot sitting in g_flSnap (n flows) into the rows and refreshes the list. UI thread.
static void FlowsShowSnapshot(UINT32 n)
{
    if (n > PB_FLOWS_MAX_GUI) n = PB_FLOWS_MAX_GUI;
    FlowsApply(g_flSnap, (int)n, n >= PB_FLOWS_MAX_GUI, GetTickCount64());
    ListView_SetItemCountEx(g_hFlows, g_flN, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(g_hFlows, NULL, FALSE);
}

// Asking the engine goes over a pipe to the service. The timer must never freeze the window if the service is slow,
// so the call runs on a short-lived worker thread and posts the result back; a poll that is still waiting is not
// started twice. (FlowsPoll is the same thing done in place, for the tests.)
#define WM_APP_FLOWS (WM_APP + 20)
static volatile LONG g_flBusy = 0;        // 1 while a worker owns g_flSnap
static BOOL          g_flActive = FALSE;  // the tab is open
static HWND          g_flMain = NULL;

static void FlowsPoll(void)
{
    if (!g_hFlows || !g_api.GetFlows || g_flBusy) return;
    if (!g_flSnap) g_flSnap = (PBFlow*)malloc(sizeof(PBFlow) * PB_FLOWS_MAX_GUI);
    if (!g_flSnap) return;
    FlowsShowSnapshot(g_api.GetFlows(g_flSnap, PB_FLOWS_MAX_GUI));
}

static DWORD WINAPI FlowsWorker(LPVOID arg)
{
    (void)arg;
    UINT32 n = g_api.GetFlows(g_flSnap, PB_FLOWS_MAX_GUI);
    PostMessageW(g_flMain, WM_APP_FLOWS, (WPARAM)n, 0);
    return 0;
}

static void FlowsPollAsync(void)
{
    if (!g_hFlows || !g_api.GetFlows || !g_flActive) return;
    if (InterlockedCompareExchange(&g_flBusy, 1, 0) != 0) return;     // the last call has not come back yet
    if (!g_flSnap) g_flSnap = (PBFlow*)malloc(sizeof(PBFlow) * PB_FLOWS_MAX_GUI);
    HANDLE t = g_flSnap ? CreateThread(NULL, 0, FlowsWorker, NULL, 0, NULL) : NULL;
    if (!t) { InterlockedExchange(&g_flBusy, 0); return; }
    CloseHandle(t);
}

// WM_APP_FLOWS: the worker is done and g_flSnap holds `n` flows.
static void FlowsOnResult(UINT32 n)
{
    if (g_flActive && g_flSnap) FlowsShowSnapshot(n);
    if (!g_flActive) { free(g_flSnap); g_flSnap = NULL; }              // the tab was closed while the call was out
    InterlockedExchange(&g_flBusy, 0);
}

// Opening the tab starts polling. Leaving it stops the timer and frees the snapshot buffer; the rows stay (what was
// alive is marked finished at that moment - if it is still running, the next poll after coming back revives it).
static void FlowsActivate(HWND main, BOOL on)
{
    if (!g_hFlows) return;
    g_flMain = main;
    g_flActive = on;
    if (on)
    {
        SetTimer(main, TIMER_FLOWS, FLOW_POLL_MS, NULL);
        FlowsPollAsync();
    }
    else
    {
        KillTimer(main, TIMER_FLOWS);
        if (!g_flBusy) { free(g_flSnap); g_flSnap = NULL; }            // a worker still using it frees it in FlowsOnResult
        ULONGLONG now = GetTickCount64();
        for (int j = 0; j < g_flN; j++) if (g_fl[j].closedAt == 0) g_fl[j].closedAt = now;
    }
}

// WM_NOTIFY from the list: cell text, header click sorting and grey text for finished connections.
static LRESULT FlowsNotify(LPARAM lp)
{
    LPNMHDR nh = (LPNMHDR)lp;
    switch (nh->code)
    {
    case LVN_GETDISPINFOW:
    {
        NMLVDISPINFOW* di = (NMLVDISPINFOW*)lp;
        if ((di->item.mask & LVIF_TEXT) && di->item.pszText && di->item.cchTextMax > 0)
        {
            di->item.pszText[0] = 0;
            if (di->item.iItem >= 0 && di->item.iItem < g_flN && di->item.iSubItem >= 0 && di->item.iSubItem < 7)
                FlowText(&g_fl[g_flView[di->item.iItem]], di->item.iSubItem, g_flNow, di->item.pszText, di->item.cchTextMax);
        }
        return 0;
    }
    case LVN_COLUMNCLICK:
    {
        int c = ((NMLISTVIEW*)lp)->iSubItem;
        if (c == g_flSortCol) g_flSortAsc = !g_flSortAsc; else { g_flSortCol = c; g_flSortAsc = (c <= 2); }
        if (g_flN > 0) { FlowsSortView(); InvalidateRect(g_hFlows, NULL, FALSE); }
        return 0;
    }
    case NM_CUSTOMDRAW:
    {
        NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)lp;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
        {
            int i = (int)cd->nmcd.dwItemSpec;
            if (i >= 0 && i < g_flN && g_fl[g_flView[i]].closedAt) cd->clrText = RGB(128, 128, 128);
            return CDRF_NEWFONT;
        }
        return CDRF_DODEFAULT;
    }
    }
    return 0;
}
