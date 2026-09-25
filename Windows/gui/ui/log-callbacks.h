// Core emits at most1023 UTF-8 bytes for a process/activity message,63 for an
// address and159 for proxy info. Conversion uses stack storage; only the final
// owned queue line allocates. Reject oversized inputs rather than truncate keys.
static BOOL LogUtf8(const char* text, wchar_t* out, int capacity)
{
    return MultiByteToWideChar(CP_UTF8, 0, text ? text : "", -1, out, capacity) != 0;
}
static void PBLogCb(const char* message)
{
    wchar_t body[1024], ts[16];
    if (!LogUtf8(message, body, ARRAYSIZE(body))) { LogStoreNoteDrop(&g_actStore); return; }
    GetTimePrefix(ts, ARRAYSIZE(ts));
    size_t n = wcslen(ts) + wcslen(body) + 3;
    wchar_t* line = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (line) {
        _snwprintf_s(line, n, _TRUNCATE, L"%s%s\r\n", ts, body);
        LogStoreQueue(&g_actStore, line);
    }
    else LogStoreNoteDrop(&g_actStore);
}
static void PBConnCb(const char* proc, DWORD pid, const char* ip, unsigned short port, const char* info)
{
    if (!InterlockedCompareExchange(&g_connectionLogEnabled, 0, 0)) return;
    wchar_t wp[1024], wi[64], wf[160], wport[16], ts[16];
    if (!LogUtf8(proc, wp, ARRAYSIZE(wp)) || !LogUtf8(ip, wi, ARRAYSIZE(wi)) ||
        !LogUtf8(info, wf, ARRAYSIZE(wf))) { LogStoreNoteDrop(&g_connStore); return; }
    _snwprintf_s(wport, ARRAYSIZE(wport), _TRUNCATE, L"%u", port);
    const wchar_t* proto = (info && strstr(info, "(UDP)")) ? L"UDP" : L"TCP";
    const wchar_t* action = (info && _strnicmp(info, "Direct", 6) == 0) ? L"Direct"
                         : (info && _strnicmp(info, "Block", 5) == 0) ? L"Blocked" : L"Proxy";
    if (!PassesLogFilters(wp, wi, wport, proto, action)) return;
    GetTimePrefix(ts, ARRAYSIZE(ts));
    size_t n = 64 + wcslen(wp) + wcslen(wi) + wcslen(wf);
    wchar_t* line = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (line) {
        _snwprintf_s(line, n, _TRUNCATE, L"%s%s (PID:%lu) -> %s:%u  via %s\r\n",
                     ts, wp, pid, wi, port, wf);
        LogStoreQueue(&g_connStore, line);
    }
    else LogStoreNoteDrop(&g_connStore);
}
