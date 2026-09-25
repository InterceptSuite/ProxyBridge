// ui/logview.h - log panel storage + connection-log filtering.
//
// Unity-build include: pulled into main.c after the globals (LogStore, g_connStore/
// g_actStore, g_autoClear, g_flt/g_fltCount, g_profile) it operates on. Not standalone.
#ifndef PB_UI_LOGVIEW_H
#define PB_UI_LOGVIEW_H

static void GetTimePrefix(wchar_t* buf, int cch)
{
    SYSTEMTIME st; GetLocalTime(&st);
    _snwprintf_s(buf, cch, _TRUNCATE, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
}

static void AppendToEdit(HWND edit, const wchar_t* line)
{
    int len = GetWindowTextLengthW(edit);
    if (len > MAX_LOG_CHARS)
    {
        SendMessageW(edit, EM_SETSEL, 0, len / 2);
        SendMessageW(edit, EM_REPLACESEL, FALSE, (LPARAM)L"");
        len = GetWindowTextLengthW(edit);
    }
    SendMessageW(edit, EM_SETSEL, len, len);
    SendMessageW(edit, EM_REPLACESEL, FALSE, (LPARAM)line);
}

// Case-insensitive substring test (avoids a shlwapi dependency).
static BOOL ContainsCI(const wchar_t* hay, const wchar_t* needle)
{
    if (!needle || !needle[0]) return TRUE;
    size_t nl = wcslen(needle);
    for (const wchar_t* p = hay; *p; p++)
        if (_wcsnicmp(p, needle, nl) == 0) return TRUE;
    return FALSE;
}
static BOOL LogLineMatches(const LogStore* s, const wchar_t* line)
{
    return s->filter[0] ? ContainsCI(line, s->filter) : TRUE;
}

// connection-log filters (include/exclude rules)
static const wchar_t* StrStrCI(const wchar_t* hay, const wchar_t* needle, size_t nlen)
{
    for (; *hay; hay++) if (_wcsnicmp(hay, needle, nlen) == 0) return hay;
    return NULL;
}
static BOOL GlobMatch(const wchar_t* text, const wchar_t* pattern)
{
    if (!pattern[0] || wcscmp(pattern, L"*") == 0) return TRUE;
    if (!wcschr(pattern, L'*')) return ContainsCI(text, pattern);   // non-glob = contains
    size_t tlen = wcslen(text), plen = wcslen(pattern);
    BOOL leadStar = (pattern[0] == L'*'), trailStar = (pattern[plen - 1] == L'*');
    const wchar_t* tpos = text; const wchar_t* p = pattern;
    BOOL firstPart = TRUE; const wchar_t* lastPtr = NULL; size_t lastLen = 0;
    while (*p)
    {
        if (*p == L'*') { p++; continue; }
        const wchar_t* e = p; while (*e && *e != L'*') e++;
        size_t len = (size_t)(e - p);
        const wchar_t* found = StrStrCI(tpos, p, len);
        if (!found) return FALSE;
        if (firstPart && !leadStar && found != text) return FALSE;   // must start with first part
        lastPtr = p; lastLen = len; tpos = found + len; firstPart = FALSE; p = e;
    }
    if (!trailStar && lastLen > 0)
        if (tlen < lastLen || _wcsnicmp(text + tlen - lastLen, lastPtr, lastLen) != 0) return FALSE;
    return TRUE;
}
static BOOL FTextMatch(const wchar_t* actual, const wchar_t* pattern)
{
    if (!pattern[0] || _wcsicmp(pattern, L"*") == 0 || _wcsicmp(pattern, L"All") == 0) return TRUE;
    return GlobMatch(actual, pattern);
}
static BOOL FilterEq(const wchar_t* field, const wchar_t* actual)   // combo fields (proto/action)
{
    return (!field[0] || _wcsicmp(field, L"All") == 0) ? TRUE : (_wcsicmp(field, actual) == 0);
}
static BOOL FilterRuleMatches(const PBFilter* f, const wchar_t* proc, const wchar_t* ip,
                              const wchar_t* port, const wchar_t* proto, const wchar_t* action)
{
    return FTextMatch(proc, f->proc) && FTextMatch(ip, f->ip) && FTextMatch(port, f->port) &&
           FilterEq(f->proto, proto) && FilterEq(f->action, action);
}
// Excludes run first (any match hides). Then includes: if any exist, at least one must match.
static SRWLOCK g_filterSnapshotLock = SRWLOCK_INIT;
static BOOL PassesLogFiltersLocked(const wchar_t* proc, const wchar_t* ip, const wchar_t* port,
                             const wchar_t* proto, const wchar_t* action)
{
    if (g_fltCount == 0) return TRUE;
    for (int i = 0; i < g_fltCount; i++)
        if (_wcsicmp(g_flt[i].mode, L"Exclude") == 0 &&
            FilterRuleMatches(&g_flt[i], proc, ip, port, proto, action)) return FALSE;
    BOOL hasInc = FALSE;
    for (int i = 0; i < g_fltCount; i++)
        if (_wcsicmp(g_flt[i].mode, L"Include") == 0)
        { hasInc = TRUE; if (FilterRuleMatches(&g_flt[i], proc, ip, port, proto, action)) return TRUE; }
    return !hasInc;
}
static BOOL PassesLogFilters(const wchar_t* proc, const wchar_t* ip, const wchar_t* port,
                             const wchar_t* proto, const wchar_t* action)
{
    AcquireSRWLockShared(&g_filterSnapshotLock);
    BOOL pass = PassesLogFiltersLocked(proc, ip, port, proto, action);
    ReleaseSRWLockShared(&g_filterSnapshotLock);
    return pass;
}
static void ApplyFilterSnapshot(void)
{
    AcquireSRWLockExclusive(&g_filterSnapshotLock);
    g_fltCount = g_profile.filterCount;
    if (g_fltCount < 0) g_fltCount = 0;
    if (g_fltCount > PB_MAX_FILTER) g_fltCount = PB_MAX_FILTER;
    for (int i = 0; i < g_fltCount; i++) g_flt[i] = g_profile.filter[i];
    ReleaseSRWLockExclusive(&g_filterSnapshotLock);
}
// History owns each line once. Ring eviction never moves the other pointers.
static void LogStoreDropOldest(LogStore* s)
{
    wchar_t* line = s->lines[s->head];
    s->bytes -= (wcslen(line) + 1) * sizeof(wchar_t);
    free(line);
    s->lines[s->head] = NULL;
    s->head = (s->head + 1) % LOG_MAX_LINES;
    s->count--;
}
static void LogStoreResetHistory(LogStore* s)
{
    while (s->count) LogStoreDropOldest(s);
    s->head = 0;
}
static void LogStoreKeep(LogStore* s, wchar_t* line)
{
    size_t bytes = (wcslen(line) + 1) * sizeof(wchar_t);
    while (s->count && (s->count == LOG_MAX_LINES || bytes > LOG_STORE_BYTES - s->bytes))
        LogStoreDropOldest(s);
    s->lines[(s->head + s->count) % LOG_MAX_LINES] = line;
    s->count++;
    s->bytes += bytes;
}
static void LogStoreAutoClear(LogStore* s)
{
    if (g_autoClear && s->count > AUTO_CLEAR_LINES)
    {
        LogStoreResetHistory(s);
        SetWindowTextW(s->edit, L"");
    }
}
static BOOL LogStoreAdd(LogStore* s, const wchar_t* line)
{
    if (wcslen(line) > MAX_LOG_CHARS) return FALSE;
    wchar_t* copy = _wcsdup(line);
    if (!copy) return FALSE;
    LogStoreKeep(s, copy);
    if (LogLineMatches(s, copy)) AppendToEdit(s->edit, copy);
    LogStoreAutoClear(s);
    return TRUE;
}
static void LogStoreRebuild(LogStore* s)
{
    SetWindowTextW(s->edit, L"");
    for (int i = 0; i < s->count; i++)
    {
        const wchar_t* line = s->lines[(s->head + i) % LOG_MAX_LINES];
        if (LogLineMatches(s, line)) AppendToEdit(s->edit, line);
    }
}
// Caller holds the pending lock exclusively.
static void LogStoreResetPending(LogStore* s)
{
    while (s->pendCount)
    {
        free(s->pend[s->pendHead]);
        s->pend[s->pendHead] = NULL;
        s->pendHead = (s->pendHead + 1) % LOG_PEND_MAX;
        s->pendCount--;
    }
    s->pendHead = 0;
    s->pendBytes = 0;
}
static void LogStoreClear(LogStore* s)
{
    LogStoreResetHistory(s);
    AcquireSRWLockExclusive(&s->lock);
    LogStoreResetPending(s);
    s->dropped = 0;
    ReleaseSRWLockExclusive(&s->lock);
    s->reported = s->reportAt = 0;
    SetWindowTextW(s->edit, L"");
}
static void LogStoreInit(LogStore* s, HWND edit)
{
    s->edit = edit;
    AcquireSRWLockExclusive(&s->lock);
    s->accepting = TRUE;
    ReleaseSRWLockExclusive(&s->lock);
}
// Native producer transfers ownership even on rejection. Both count and bytes are
// bounded. Drop new log entries on overload; this never discards traffic packets.
static void LogStoreNoteDrop(LogStore* s)
{
    AcquireSRWLockExclusive(&s->lock);
    if (s->accepting && s->dropped != ~(ULONGLONG)0) s->dropped++;
    ReleaseSRWLockExclusive(&s->lock);
}
static void LogStoreQueue(LogStore* s, wchar_t* line)
{
    if (!line) return;
    size_t chars = wcslen(line);
    if (chars > MAX_LOG_CHARS) { LogStoreNoteDrop(s); free(line); return; }
    size_t bytes = (chars + 1) * sizeof(wchar_t);
    AcquireSRWLockExclusive(&s->lock);
    if (s->accepting && s->pendCount < LOG_PEND_MAX && bytes <= LOG_STORE_BYTES - s->pendBytes)
    {
        s->pend[(s->pendHead + s->pendCount) % LOG_PEND_MAX] = line;
        s->pendCount++;
        s->pendBytes += bytes;
        line = NULL;
    }
    else if (s->accepting && s->dropped != ~(ULONGLONG)0) s->dropped++;
    ReleaseSRWLockExclusive(&s->lock);
    free(line);
}
// UI thread: bound each timer slice by both line count and characters. The static
// batch is UI-thread only; no per-flush allocation and no lock during edit updates.
static int LogStoreFlush(LogStore* s)
{
    wchar_t* local[LOG_FLUSH_LINES];
    static wchar_t batch[MAX_LOG_CHARS + 1];
    int n = 0;
    size_t chars = 0;
    AcquireSRWLockExclusive(&s->lock);
    while (s->pendCount && n < LOG_FLUSH_LINES)
    {
        wchar_t* line = s->pend[s->pendHead];
        size_t length = wcslen(line);
        if (length > MAX_LOG_CHARS - chars) break;
        chars += length;
        local[n++] = line;
        s->pend[s->pendHead] = NULL;
        s->pendHead = (s->pendHead + 1) % LOG_PEND_MAX;
        s->pendCount--;
        s->pendBytes -= (length + 1) * sizeof(wchar_t);
    }
    ReleaseSRWLockExclusive(&s->lock);
    size_t off = 0;
    for (int i = 0; i < n; i++)
    {
        wchar_t* line = local[i];
        if (LogLineMatches(s, line))
        {
            size_t length = wcslen(line);
            memcpy(batch + off, line, length * sizeof(wchar_t));
            off += length;
        }
        LogStoreKeep(s, line);
    }
    if (off) { batch[off] = 0; AppendToEdit(s->edit, batch); }
    LogStoreAutoClear(s);
    return n;
}
// UI-only summary, at most once per five seconds. No recursive producer callback.
// Keep the count on allocation failure, so a later timer can report it.
static BOOL LogStoreReportDrops(LogStore* s, ULONGLONG now, const wchar_t* format)
{
    if (now < s->reportAt) return FALSE;
    AcquireSRWLockShared(&s->lock);
    ULONGLONG dropped = s->dropped;
    ReleaseSRWLockShared(&s->lock);
    if (dropped == s->reported) return FALSE;
    wchar_t line[256], ts[16];
    GetTimePrefix(ts, ARRAYSIZE(ts));
    int prefix = _snwprintf_s(line, ARRAYSIZE(line), _TRUNCATE, L"%s", ts);
    if (prefix < 0) return FALSE;
    _snwprintf_s(line + prefix, ARRAYSIZE(line) - prefix, _TRUNCATE, format, dropped);
    s->reportAt = now + 5000;
    // Do not let the summary itself trigger auto-clear and immediately disappear.
    if (g_autoClear && s->count >= AUTO_CLEAR_LINES) {
        LogStoreResetHistory(s); SetWindowTextW(s->edit, L"");
    }
    if (!LogStoreAdd(s, line)) return FALSE;
    s->reported = dropped;
    return TRUE;
}
static void LogStoreFree(LogStore* s)
{
    AcquireSRWLockExclusive(&s->lock);
    s->accepting = FALSE;     // late producers can safely reject against the static lock
    LogStoreResetPending(s);
    ReleaseSRWLockExclusive(&s->lock);
    LogStoreResetHistory(s);
}

#endif // PB_UI_LOGVIEW_H
