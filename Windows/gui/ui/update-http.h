// Synchronous worker-only HTTP. No window handles or messages.
// Open a GET request and read the response headers. On success returns the request handle
// and hands back the session/connection handles for cleanup; NULL on any failure.
static HINTERNET UpdOpenGet(const wchar_t* url, HINTERNET* sOut, HINTERNET* cOut, UpdWork* job)
{
    *sOut = *cOut = NULL;
    if (UpdCancelled(job)) return NULL;
    URL_COMPONENTS uc; wchar_t host[256] = {0}, path[2048] = {0};
    ZeroMemory(&uc, sizeof(uc)); uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 2047;
    if (!WinHttpCrackUrl(url, 0, 0, &uc)) return NULL;
    BOOL https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    HINTERNET s = WinHttpOpen(L"ProxyBridge-UpdateChecker", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return NULL;
    if (!WinHttpSetTimeouts(s, 5000, 10000, 15000, 15000)) { WinHttpCloseHandle(s); return NULL; }
    HINTERNET c = WinHttpConnect(s, host, uc.nPort, 0);
    if (!c) { WinHttpCloseHandle(s); return NULL; }
    HINTERNET r = WinHttpOpenRequest(c, L"GET", path, NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
    if (!r || UpdCancelled(job) ||
        !WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(r, NULL))
    {
        if (r) WinHttpCloseHandle(r);
        WinHttpCloseHandle(c); WinHttpCloseHandle(s);
        return NULL;
    }
    DWORD status=0, statusSize=sizeof(status);
    if (UpdCancelled(job) || !WinHttpQueryHeaders(r,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,&status,&statusSize,WINHTTP_NO_HEADER_INDEX) || status!=200) {
        WinHttpCloseHandle(r);WinHttpCloseHandle(c);WinHttpCloseHandle(s);return NULL;
    }
    *sOut = s; *cOut = c;
    return r;
}
static void UpdCloseGet(HINTERNET s, HINTERNET c, HINTERNET r)
{
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    if (s) WinHttpCloseHandle(s);
}

// GET a URL into a malloc'd NUL-terminated buffer (caller frees). Follows redirects.
static char* UpdHttpGet(const wchar_t* url, DWORD* outLen, UpdWork* job)
{
    HINTERNET s, c, r = UpdOpenGet(url, &s, &c, job);
    if (!r) return NULL;
    char* buf = NULL; DWORD cap = 0, len = 0, avail;
    for (;;)
    {
        if (UpdCancelled(job) || !WinHttpQueryDataAvailable(r, &avail) || avail > 1048576u - len) { free(buf); buf = NULL; break; }
        if (avail == 0) break;
        if (len + avail + 1 > cap)
        {
            DWORD ncap = (len + avail + 1) * 2;
            char* nb = (char*)realloc(buf, ncap);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb; cap = ncap;
        }
        DWORD read = 0;
        if (!WinHttpReadData(r, buf + len, avail, &read) || read == 0) { free(buf); buf = NULL; break; }
        len += read;
    }
    if (buf) buf[len] = 0;
    UpdCloseGet(s, c, r);
    if (buf && outLen) *outLen = len;
    return buf;
}

// The destination was uniquely reserved by the UI; publish only complete writes.
static BOOL UpdDownload(const wchar_t* url, const wchar_t* dest, UpdWork* job)
{
    HINTERNET s, c, r = UpdOpenGet(url, &s, &c, job);
    if (!r) return FALSE;
    BOOL ok = FALSE;
    DWORD total = 0, tsz = sizeof(total);
    WinHttpQueryHeaders(r, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &total, &tsz, WINHTTP_NO_HEADER_INDEX);
    HANDLE f = CreateFileW(dest, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE)
    {
        BYTE buf[16384]; ULONGLONG got = 0; DWORD avail; ok = TRUE;
        for (;;)
        {
            if (UpdCancelled(job) || !WinHttpQueryDataAvailable(r, &avail)) { ok = FALSE; break; }
            if (avail == 0) break;
            DWORD toread = avail > sizeof(buf) ? sizeof(buf) : avail, read = 0;
            if (!WinHttpReadData(r, buf, toread, &read) || read == 0) { ok = FALSE; break; }
            DWORD written = 0;
            if (!WriteFile(f, buf, read, &written, NULL) || written != read) { ok = FALSE; break; }
            got += read;
            if (total > 0) InterlockedExchange(&job->progress, (LONG)(got >= total ? 100 : got * 100 / total));
        }
        if (ok && (!got || (total && got != total))) ok = FALSE;
        CloseHandle(f);
    }
    UpdCloseGet(s, c, r);
    return ok && !UpdCancelled(job);
}


