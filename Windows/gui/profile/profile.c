// profile.c - settings.json + *.pbprofile I/O (see profile.h).
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "profile.h"
#include "json.h"

// UTF-8 <-> UTF-16
static void u2w(const char* s, wchar_t* out, int cch)
{
    if (cch <= 0) return;
    out[0] = 0;
    if (!s) return;
    // Convert at most cch-1 source bytes: a UTF-16 string is never longer than its UTF-8 source, so the
    // result always fits (an over-long value is cut, never overflows or stays unterminated).
    size_t sl = strlen(s);
    if (sl > (size_t)(cch - 1)) sl = (size_t)(cch - 1);
    if (sl == 0) return;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, (int)sl, out, cch - 1);
    out[n > 0 ? n : 0] = 0;
}
static void w2u(const wchar_t* w, char* out, int cch)
{
    if (cch <= 0) return;
    out[0] = 0;
    if (!w) return;
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cch, NULL, NULL)) out[0] = 0;   // too small: empty, never unterminated
}

// ---- Target Domains list helpers (see profile.h) ----
void PB_ListNormalize(wchar_t* s)
{
    if (!s) return;
    wchar_t* w = s;            // write position; never passes the read position, so this is in place
    const wchar_t* r = s;
    BOOL any = FALSE;
    while (*r)
    {
        while (*r && (*r == L';' || *r == L',' || *r <= L' ')) r++;   // separators, blanks, line breaks, controls
        if (!*r) break;
        if (any) *w++ = L';';
        wchar_t* lastKept = w;                                          // end of the entry without trailing blanks
        while (*r && *r != L';' && *r != L',')
        {
            wchar_t c = *r++;
            if (c < L' ') continue;                                     // a line break/tab inside an entry is ignored
            *w++ = c;
            if (c != L' ') lastKept = w;
        }
        w = lastKept;
        any = TRUE;
    }
    *w = 0;
}

void PB_ListFormat(const wchar_t* in, wchar_t* out, size_t cch)
{
    if (!out || cch == 0) return;
    size_t o = 0;
    for (const wchar_t* p = in ? in : L""; *p && o + 1 < cch; p++)
    {
        out[o++] = *p;
        if (*p == L';')
        {
            if (o + 3 > cch) break;
            out[o++] = L'\r'; out[o++] = L'\n';
        }
    }
    out[o] = 0;
}

// ---- Target Hosts: IPs and domains as one list (see profile.h) ----
// An entry is an address pattern when it is made of digits and . - / * (IPv4 forms such as 10.0.0.0/8,
// 192.168.*.*, 10.1-5.*.7, 1.2.3.4-1.2.3.9) or, if it contains ':', of hex digits and : . - / * (IPv6).
// Everything else (github.com, *.github.com) is a domain name.
static BOOL IsIpToken(const wchar_t* s, size_t n)
{
    BOOL colon = FALSE, digitOrStar = FALSE;
    for (size_t i = 0; i < n; i++) if (s[i] == L':') colon = TRUE;
    for (size_t i = 0; i < n; i++)
    {
        wchar_t c = s[i];
        BOOL digit = (c >= L'0' && c <= L'9');
        BOOL hex   = (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
        BOOL punct = (c == L'.' || c == L'-' || c == L'/' || c == L'*' || c == L':');
        if (digit || c == L'*') digitOrStar = TRUE;
        if (!(digit || punct || (colon && hex))) return FALSE;
    }
    return digitOrStar;
}

static BOOL HostsPresent(const wchar_t* s)
{
    return s && s[0] && !(s[0] == L'*' && s[1] == 0);
}

void PB_HostsMerge(const wchar_t* ips, const wchar_t* doms, wchar_t* out, size_t cch)
{
    if (!out || cch == 0) return;
    out[0] = 0;
    BOOL a = HostsPresent(ips), d = HostsPresent(doms);
    if (!a && !d) { if (cch >= 2) { out[0] = L'*'; out[1] = 0; } return; }
    size_t la = a ? wcslen(ips) : 0, ld = d ? wcslen(doms) : 0;
    size_t total = la + ((a && d) ? 1 : 0) + ld;
    wchar_t* t = (wchar_t*)malloc((total + 1) * sizeof(wchar_t));
    if (!t) { if (cch >= 2) { out[0] = L'*'; out[1] = 0; } return; }
    size_t o = 0;
    if (a) { memcpy(t, ips, la * sizeof(wchar_t)); o = la; }
    if (a && d) t[o++] = L';';
    if (d) { memcpy(t + o, doms, ld * sizeof(wchar_t)); o += ld; }
    t[o] = 0;
    if (total <= cch - 1) memcpy(out, t, (total + 1) * sizeof(wchar_t));
    else
    {
        // too long for the buffer: keep whole entries only
        memcpy(out, t, (cch - 1) * sizeof(wchar_t));
        out[cch - 1] = 0;
        if (t[cch - 1] != L';') { wchar_t* semi = wcsrchr(out, L';'); if (semi) *semi = 0; else out[0] = 0; }
    }
    free(t);
    if (!out[0] && cch >= 2) { out[0] = L'*'; out[1] = 0; }
}

void PB_HostsSplit(const wchar_t* merged, wchar_t* ips, size_t ipsCch, wchar_t* doms, size_t domsCch)
{
    if (ipsCch)  ips[0] = 0;
    if (domsCch) doms[0] = 0;
    size_t io = 0, dd = 0;
    BOOL any = FALSE;
    const wchar_t* p = merged ? merged : L"";
    while (*p)
    {
        while (*p == L';' || *p == L',' || (*p && *p <= L' ')) p++;
        if (!*p) break;
        const wchar_t* s = p;
        while (*p && *p != L';' && *p != L',') p++;
        const wchar_t* e = p;
        while (e > s && e[-1] <= L' ') e--;
        size_t n = (size_t)(e - s);
        if (n == 0) continue;
        if (n == 1 && s[0] == L'*') { any = TRUE; continue; }
        BOOL isIp = IsIpToken(s, n);
        wchar_t* out = isIp ? ips : doms; size_t* pos = isIp ? &io : &dd; size_t cch = isIp ? ipsCch : domsCch;
        size_t need = n + (*pos ? 1 : 0);
        if (*pos + need + 1 > cch) continue;                 // cannot happen with correctly sized buffers; never overflows
        if (*pos) out[(*pos)++] = L';';
        memcpy(out + *pos, s, n * sizeof(wchar_t)); *pos += n; out[*pos] = 0;
    }
    if (any || (!io && !dd)) io = dd = 0;
    if (!io && ipsCch  >= 2) { ips[0]  = L'*'; ips[1]  = 0; }
    if (!dd && domsCch >= 2) { doms[0] = L'*'; doms[1] = 0; }
}

// paths
static void base_dir(wchar_t* out, int cch)
{
    wchar_t appdata[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) appdata[0] = 0;
    _snwprintf_s(out, cch, _TRUNCATE, L"%s\\ProxyBridge", appdata);
}
static void settings_path(wchar_t* out, int cch)
{ wchar_t b[MAX_PATH]; base_dir(b, MAX_PATH); _snwprintf_s(out, cch, _TRUNCATE, L"%s\\settings.json", b); }
static void profiles_dir(wchar_t* out, int cch)
{ wchar_t b[MAX_PATH]; base_dir(b, MAX_PATH); _snwprintf_s(out, cch, _TRUNCATE, L"%s\\profiles", b); }
static void profile_path(const wchar_t* name, wchar_t* out, int cch)
{ wchar_t d[MAX_PATH]; profiles_dir(d, MAX_PATH); _snwprintf_s(out, cch, _TRUNCATE, L"%s\\%s.pbprofile", d, name); }
static void ensure_dirs(void)
{
    wchar_t b[MAX_PATH], d[MAX_PATH];
    base_dir(b, MAX_PATH); CreateDirectoryW(b, NULL);
    profiles_dir(d, MAX_PATH); CreateDirectoryW(d, NULL);
}

// file helpers
static char* read_file(const wchar_t* path, DWORD* outLen)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > (64u * 1024u * 1024u)) { CloseHandle(h); return NULL; }
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    if (!ok) { free(buf); return NULL; }
    buf[rd] = 0;
    if (rd >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF)
    { memmove(buf, buf + 3, rd - 3 + 1); rd -= 3; }
    if (outLen) *outLen = rd;
    return buf;
}

static BOOL write_file_atomic(const wchar_t* path, const char* data, size_t len)
{
    wchar_t tmp[MAX_PATH]; _snwprintf_s(tmp, MAX_PATH, _TRUNCATE, L"%s.tmp", path);
    HANDLE h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, (DWORD)len, &wr, NULL) && wr == (DWORD)len;
    CloseHandle(h);
    if (!ok) { DeleteFileW(tmp); return FALSE; }
    if (!MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING)) { DeleteFileW(tmp); return FALSE; }
    return TRUE;
}

// settings.json - all fields loaded/saved together so each public accessor only touches
// the one it cares about while preserving the rest.
typedef struct { int checkUpd, startWin; char lastCheck[64]; char activeName[256]; } Settings;

static void settings_load(Settings* s)
{
    s->checkUpd = 1; s->startWin = 0;
    strcpy_s(s->lastCheck,  sizeof(s->lastCheck),  "0001-01-01T00:00:00");
    strcpy_s(s->activeName, sizeof(s->activeName), "Default");
    wchar_t sp[MAX_PATH]; settings_path(sp, MAX_PATH);
    DWORD len = 0; char* txt = read_file(sp, &len);
    if (!txt) return;
    JVal* root = json_parse(txt, len);
    if (root)
    {
        s->checkUpd = json_bool(root, "CheckForUpdatesOnStartup", 1);
        s->startWin = json_bool(root, "StartWithWindows", 0);
        const char* lc = json_str(root, "LastUpdateCheck", NULL);
        if (lc) strncpy_s(s->lastCheck, sizeof(s->lastCheck), lc, _TRUNCATE);
        const char* an = json_str(root, "ActiveProfileName", NULL);
        if (an) strncpy_s(s->activeName, sizeof(s->activeName), an, _TRUNCATE);
        json_free(root);
    }
    free(txt);
}

static void settings_save(const Settings* s)
{
    ensure_dirs();
    wchar_t sp[MAX_PATH]; settings_path(sp, MAX_PATH);
    StrBuf b; sb_init(&b);
    sb_put(&b, "{\n");
    sb_put(&b, "  \"CheckForUpdatesOnStartup\": "); sb_put(&b, s->checkUpd ? "true" : "false"); sb_put(&b, ",\n");
    sb_put(&b, "  \"LastUpdateCheck\": "); sb_json_str(&b, s->lastCheck); sb_put(&b, ",\n");
    sb_put(&b, "  \"StartWithWindows\": "); sb_put(&b, s->startWin ? "true" : "false"); sb_put(&b, ",\n");
    sb_put(&b, "  \"ActiveProfileName\": "); sb_json_str(&b, s->activeName); sb_put(&b, "\n}\n");
    write_file_atomic(sp, b.buf, b.len);
    sb_free(&b);
}

void PB_GetActiveProfile(wchar_t* out, int cch)
{
    Settings s; settings_load(&s);
    u2w(s.activeName, out, cch);
}

void PB_SetActiveProfile(const wchar_t* name)
{
    Settings s; settings_load(&s);
    w2u(name, s.activeName, sizeof(s.activeName));
    settings_save(&s);
}

BOOL PB_GetCheckUpdates(void)
{
    Settings s; settings_load(&s);
    return s.checkUpd ? TRUE : FALSE;
}

void PB_SetCheckUpdates(BOOL enable)
{
    Settings s; settings_load(&s);
    s.checkUpd = enable ? 1 : 0;
    settings_save(&s);
}

// *.pbprofile
void PB_ProfileDefaults(PBProfile* p, const wchar_t* name)
{
    (void)name;
    ZeroMemory(p, sizeof(*p));
    p->trafficLogging    = 1;
    p->autoClearLogs     = 1;
    p->closeToTray       = 1;
    p->fontZoom          = 100;
    lstrcpynW(p->language, L"en", 8);
}

// Makes proxy-config ids unique and non-zero and positions the allocator past every id in use.
// Older profiles stored the engine's per-session id here, so duplicates and gaps are possible; a
// duplicate keeps its id for the first config (rules referencing it stay with that one) and the
// later ones get fresh ids.
static void normalize_cfg_ids(PBProfile* p)
{
    UINT32 hi = 0;
    for (int i = 0; i < p->cfgCount; i++) if (p->cfg[i].storedId > hi) hi = p->cfg[i].storedId;
    for (int i = 0; i < p->ruleCount; i++) if (p->rule[i].cfgStoredId > hi) hi = p->rule[i].cfgStoredId;
    if (p->nextCfgId <= hi) p->nextCfgId = hi + 1;
    if (p->nextCfgId == 0) p->nextCfgId = 1;
    for (int j = 0; j < p->cfgCount; j++)
    {
        BOOL dup = (p->cfg[j].storedId == 0);
        for (int i = 0; i < j && !dup; i++) if (p->cfg[i].storedId == p->cfg[j].storedId) dup = TRUE;
        if (dup) p->cfg[j].storedId = p->nextCfgId++;
    }
}

UINT32 PB_AllocConfigId(PBProfile* p)
{
    if (p->nextCfgId == 0) normalize_cfg_ids(p);
    return p->nextCfgId++;
}

void PB_ProfileLoad(const wchar_t* name, PBProfile* p)
{
    PB_ProfileDefaults(p, name);
    wchar_t pp[MAX_PATH]; profile_path(name, pp, MAX_PATH);
    DWORD len = 0; char* txt = read_file(pp, &len);
    if (!txt) return;
    JVal* root = json_parse(txt, len);
    if (root && root->type == J_OBJ)
    {
        // Older profiles had one global "LocalhostViaProxy"; it is now per rule. Use the old value as
        // each rule's default so an upgraded profile keeps behaving the same.
        int oldGlobalLocalhost = json_bool(root, "LocalhostViaProxy", 0);
        p->trafficLogging    = json_bool(root, "IsTrafficLoggingEnabled", 1);
        p->autoClearLogs     = json_bool(root, "AutoClearConnectionLogs", 1);
        p->closeToTray       = json_bool(root, "CloseToTray", 1);
        p->nextCfgId         = (UINT32)json_long(root, "NextProxyConfigId", 0);
        p->fontZoom          = (int)json_long(root, "FontZoom", 100);
        if (p->fontZoom < 60 || p->fontZoom > 300) p->fontZoom = 100;
        u2w(json_str(root, "Language", "en"), p->language, 8);

        JVal* cfgs = json_get(root, "ProxyConfigs");
        if (cfgs && cfgs->type == J_ARR)
            for (JVal* c = cfgs->child; c && p->cfgCount < PB_MAX_CFG; c = c->next)
            {
                if (c->type != J_OBJ) continue;
                PBConfig* cf = &p->cfg[p->cfgCount++];
                cf->storedId = (UINT32)json_long(c, "Id", 0);
                u2w(json_str(c, "Name", ""), cf->name, 128);
                u2w(json_str(c, "Type", "SOCKS5"), cf->type, 16);
                u2w(json_str(c, "Host", ""), cf->host, 128);
                u2w(json_str(c, "Port", ""), cf->port, 16);
                u2w(json_str(c, "Username", ""), cf->user, 128);
                u2w(json_str(c, "Password", ""), cf->pass, 128);
                cf->sendDomain = json_bool(c, "SendDomainToProxy", 1);   // default on
            }

        JVal* rules = json_get(root, "ProxyRules");
        if (rules && rules->type == J_ARR)
            for (JVal* r = rules->child; r && p->ruleCount < PB_MAX_RULE; r = r->next)
            {
                if (r->type != J_OBJ) continue;
                PBRule* ru = &p->rule[p->ruleCount++];
                u2w(json_str(r, "Name", "ProxyBridge Rule"), ru->name, 128);
                u2w(json_str(r, "ProcessName", "*"), ru->proc, PB_APPS_MAX);
                u2w(json_str(r, "TargetPorts", "*"), ru->ports, 128);
                {
                    // the file keeps IPs and domains in two keys; the GUI shows them as one list
                    wchar_t* wi = (wchar_t*)malloc(PB_HOSTS_MAX * sizeof(wchar_t));
                    wchar_t* wd = (wchar_t*)malloc(PB_HOSTS_MAX * sizeof(wchar_t));
                    if (wi && wd)
                    {
                        u2w(json_str(r, "TargetHosts", "*"), wi, PB_HOSTS_MAX);
                        u2w(json_str(r, "TargetDomains", "*"), wd, PB_HOSTS_MAX);
                        PB_ListNormalize(wi); PB_ListNormalize(wd);     // older/hand-edited files may hold stray line breaks
                        PB_HostsMerge(wi, wd, ru->hosts, PB_HOSTS_MAX);
                    }
                    else lstrcpynW(ru->hosts, L"*", PB_HOSTS_MAX);
                    free(wi); free(wd);
                }
                u2w(json_str(r, "Protocol", "TCP"), ru->proto, 8);
                u2w(json_str(r, "Action", "PROXY"), ru->action, 16);
                ru->enabled = json_bool(r, "IsEnabled", 1);
                ru->localhost = json_bool(r, "LocalhostViaProxy", oldGlobalLocalhost);
                ru->cfgStoredId = (UINT32)json_long(r, "ProxyConfigId", 0);
            }

        normalize_cfg_ids(p);

        JVal* filters = json_get(root, "LogFilters");
        if (filters && filters->type == J_ARR)
            for (JVal* f = filters->child; f && p->filterCount < PB_MAX_FILTER; f = f->next)
            {
                if (f->type != J_OBJ) continue;
                PBFilter* fi = &p->filter[p->filterCount++];
                u2w(json_str(f, "Mode", "Include"), fi->mode, 16);
                u2w(json_str(f, "ProcessName", ""), fi->proc, 256);
                u2w(json_str(f, "Ip", ""), fi->ip, 64);
                u2w(json_str(f, "Port", ""), fi->port, 16);
                u2w(json_str(f, "Protocol", "All"), fi->proto, 8);
                u2w(json_str(f, "Action", "All"), fi->action, 16);
            }
    }
    if (root) json_free(root);
    free(txt);
}

static void put_kv_str(StrBuf* b, const char* indent, const char* key, const wchar_t* wval, const char* trail)
{
    // UTF-8 worst case is 3 bytes per UTF-16 unit; sized from the actual string so nothing is cut or overflows
    size_t cap = (wval ? wcslen(wval) : 0) * 3 + 4;
    char* tmp = (char*)malloc(cap);
    if (tmp) w2u(wval, tmp, (int)cap);
    sb_put(b, indent); sb_put(b, "\""); sb_put(b, key); sb_put(b, "\": ");
    sb_json_str(b, tmp ? tmp : ""); sb_put(b, trail);
    free(tmp);
}

BOOL PB_ProfileSave(const wchar_t* name, const PBProfile* p)
{
    ensure_dirs();
    char tmp[1024];
    StrBuf b; sb_init(&b);
    sb_put(&b, "{\n");
    sb_put(&b, "  \"Version\": \"1.0\",\n");
    put_kv_str(&b, "  ", "Name", name, ",\n");
    sb_put(&b, "  \"IsTrafficLoggingEnabled\": ");  sb_put(&b, p->trafficLogging ? "true" : "false");    sb_put(&b, ",\n");
    sb_put(&b, "  \"AutoClearConnectionLogs\": ");  sb_put(&b, p->autoClearLogs ? "true" : "false");     sb_put(&b, ",\n");
    put_kv_str(&b, "  ", "Language", p->language, ",\n");
    sb_put(&b, "  \"CloseToTray\": ");              sb_put(&b, p->closeToTray ? "true" : "false");       sb_put(&b, ",\n");
    { char zb[48]; _snprintf_s(zb, sizeof(zb), _TRUNCATE, "  \"FontZoom\": %d,\n", p->fontZoom); sb_put(&b, zb); }
    { char nb[64]; _snprintf_s(nb, sizeof(nb), _TRUNCATE, "  \"NextProxyConfigId\": %u,\n", (unsigned)(p->nextCfgId ? p->nextCfgId : 1)); sb_put(&b, nb); }

    sb_put(&b, "  \"ProxyConfigs\": [");
    for (int i = 0; i < p->cfgCount; i++)
    {
        const PBConfig* c = &p->cfg[i];
        sb_put(&b, i ? ",\n" : "\n"); sb_put(&b, "    {\n");
        snprintf(tmp, sizeof(tmp), "%u", c->storedId);
        sb_put(&b, "      \"Id\": "); sb_put(&b, tmp); sb_put(&b, ",\n");
        put_kv_str(&b, "      ", "Name", c->name, ",\n");
        put_kv_str(&b, "      ", "Type", c->type, ",\n");
        put_kv_str(&b, "      ", "Host", c->host, ",\n");
        put_kv_str(&b, "      ", "Port", c->port, ",\n");
        put_kv_str(&b, "      ", "Username", c->user, ",\n");
        put_kv_str(&b, "      ", "Password", c->pass, ",\n");
        sb_put(&b, "      \"SendDomainToProxy\": "); sb_put(&b, c->sendDomain ? "true" : "false"); sb_put(&b, "\n");
        sb_put(&b, "    }");
    }
    sb_put(&b, p->cfgCount ? "\n  ],\n" : "],\n");

    sb_put(&b, "  \"ProxyRules\": [");
    for (int i = 0; i < p->ruleCount; i++)
    {
        const PBRule* r = &p->rule[i];
        sb_put(&b, i ? ",\n" : "\n"); sb_put(&b, "    {\n");
        put_kv_str(&b, "      ", "Name", r->name, ",\n");
        put_kv_str(&b, "      ", "ProcessName", r->proc, ",\n");
        {
            // IPs -> TargetHosts, domain names -> TargetDomains (the format macOS, Linux and older versions read)
            size_t hn = wcslen(r->hosts) + 2;
            wchar_t* wi = (wchar_t*)malloc(hn * sizeof(wchar_t));
            wchar_t* wd = (wchar_t*)malloc(hn * sizeof(wchar_t));
            if (wi && wd) PB_HostsSplit(r->hosts, wi, hn, wd, hn);
            else { if (wi) wcscpy_s(wi, hn, L"*"); if (wd) wcscpy_s(wd, hn, L"*"); }
            put_kv_str(&b, "      ", "TargetHosts", wi ? wi : L"*", ",\n");
            put_kv_str(&b, "      ", "TargetPorts", r->ports, ",\n");
            put_kv_str(&b, "      ", "TargetDomains", wd ? wd : L"*", ",\n");
            free(wi); free(wd);
        }
        put_kv_str(&b, "      ", "Protocol", r->proto, ",\n");
        put_kv_str(&b, "      ", "Action", r->action, ",\n");
        sb_put(&b, "      \"IsEnabled\": "); sb_put(&b, r->enabled ? "true" : "false"); sb_put(&b, ",\n");
        sb_put(&b, "      \"LocalhostViaProxy\": "); sb_put(&b, r->localhost ? "true" : "false"); sb_put(&b, ",\n");
        snprintf(tmp, sizeof(tmp), "%u", r->cfgStoredId);
        sb_put(&b, "      \"ProxyConfigId\": "); sb_put(&b, tmp); sb_put(&b, "\n");
        sb_put(&b, "    }");
    }
    sb_put(&b, p->ruleCount ? "\n  ],\n" : "],\n");

    sb_put(&b, "  \"LogFilters\": [");
    for (int i = 0; i < p->filterCount; i++)
    {
        const PBFilter* f = &p->filter[i];
        sb_put(&b, i ? ",\n" : "\n"); sb_put(&b, "    {\n");
        put_kv_str(&b, "      ", "Mode", f->mode, ",\n");
        put_kv_str(&b, "      ", "ProcessName", f->proc, ",\n");
        put_kv_str(&b, "      ", "Ip", f->ip, ",\n");
        put_kv_str(&b, "      ", "Port", f->port, ",\n");
        put_kv_str(&b, "      ", "Protocol", f->proto, ",\n");
        put_kv_str(&b, "      ", "Action", f->action, "\n");
        sb_put(&b, "    }");
    }
    sb_put(&b, p->filterCount ? "\n  ]\n" : "]\n");
    sb_put(&b, "}\n");

    wchar_t pp[MAX_PATH]; profile_path(name, pp, MAX_PATH);
    BOOL ok = write_file_atomic(pp, b.buf, b.len);
    sb_free(&b);
    return ok;
}

// management
int PB_ProfileList(wchar_t names[][PB_NAME_MAX], int maxNames)
{
    ensure_dirs();
    wchar_t dir[MAX_PATH], pat[MAX_PATH];
    profiles_dir(dir, MAX_PATH);
    _snwprintf_s(pat, MAX_PATH, _TRUNCATE, L"%s\\*.pbprofile", dir);
    WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW(pat, &fd);
    int n = 0;
    if (h != INVALID_HANDLE_VALUE)
    {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wchar_t nm[PB_NAME_MAX]; lstrcpynW(nm, fd.cFileName, PB_NAME_MAX);
            size_t l = wcslen(nm);
            if (l > 10 && _wcsicmp(nm + l - 10, L".pbprofile") == 0) nm[l - 10] = 0;
            if (n < maxNames) lstrcpynW(names[n++], nm, PB_NAME_MAX);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return n;
}

BOOL PB_ProfileDelete(const wchar_t* name)
{
    wchar_t pp[MAX_PATH]; profile_path(name, pp, MAX_PATH);
    return DeleteFileW(pp);
}

BOOL PB_ProfileRename(const wchar_t* oldName, const wchar_t* newName)
{
    if (!newName || !newName[0]) return FALSE;
    wchar_t src[MAX_PATH], dst[MAX_PATH];
    profile_path(oldName, src, MAX_PATH);
    profile_path(newName, dst, MAX_PATH);
    if (GetFileAttributesW(dst) != INVALID_FILE_ATTRIBUTES) return FALSE;   // target exists
    if (!MoveFileW(src, dst)) return FALSE;
    // Repoint the active-profile setting if we just renamed the active one.
    wchar_t active[PB_NAME_MAX]; PB_GetActiveProfile(active, PB_NAME_MAX);
    if (_wcsicmp(active, oldName) == 0) PB_SetActiveProfile(newName);
    return TRUE;
}

BOOL PB_ProfileExport(const wchar_t* name, const wchar_t* destPath)
{
    wchar_t pp[MAX_PATH]; profile_path(name, pp, MAX_PATH);
    return CopyFileW(pp, destPath, FALSE);
}

BOOL PB_ProfileImport(const wchar_t* srcPath, wchar_t* assignedName, int cch)
{
    const wchar_t* fn = wcsrchr(srcPath, L'\\'); fn = fn ? fn + 1 : srcPath;
    wchar_t base[PB_NAME_MAX]; lstrcpynW(base, fn, PB_NAME_MAX);
    size_t l = wcslen(base);
    if (l > 10 && _wcsicmp(base + l - 10, L".pbprofile") == 0) base[l - 10] = 0;
    if (!base[0]) lstrcpynW(base, L"Imported", PB_NAME_MAX);
    for (wchar_t* q = base; *q; q++) if (wcschr(L"<>:\"/\\|?*", *q)) *q = L'_';

    wchar_t name[PB_NAME_MAX]; lstrcpynW(name, base, PB_NAME_MAX);
    for (int i = 2; i <= 99; i++)
    {
        wchar_t pp[MAX_PATH]; profile_path(name, pp, MAX_PATH);
        if (GetFileAttributesW(pp) == INVALID_FILE_ATTRIBUTES) break;
        _snwprintf_s(name, PB_NAME_MAX, _TRUNCATE, L"%s (%d)", base, i);
    }
    ensure_dirs();
    wchar_t dpp[MAX_PATH]; profile_path(name, dpp, MAX_PATH);
    if (!CopyFileW(srcPath, dpp, FALSE)) return FALSE;
    lstrcpynW(assignedName, name, cch);
    return TRUE;
}
