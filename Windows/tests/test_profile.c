// test_profile.c - profile files (gui\profile\profile.c): loading old-format files, saving the cross-platform
// format, long Target Hosts lists, per-rule localhost, Log Every Connection, and hostile (oversized) input.
// Uses a private %APPDATA% so the real profiles are never touched.
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "../gui/profile/profile.h"
#include "pbtest.h"

static PBProfile g, h;     /* a profile is large (many rules x long host lists): keep them off the stack */

static void write_file(const wchar_t* path, const char* txt)
{
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD w; WriteFile(f, txt, (DWORD)strlen(txt), &w, NULL); CloseHandle(f);
}
static char* read_file(const wchar_t* path)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return _strdup("");
    DWORD n = GetFileSize(f, NULL), r; char* b = (char*)malloc(n + 1); ReadFile(f, b, n, &r, NULL); b[n] = 0; CloseHandle(f); return b;
}
static void rm_tree(const wchar_t* dir)
{
    wchar_t pat[MAX_PATH]; _snwprintf_s(pat, MAX_PATH, _TRUNCATE, L"%s\\*", dir);
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat, &fd);
    if (f != INVALID_HANDLE_VALUE)
    {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            wchar_t p[MAX_PATH]; _snwprintf_s(p, MAX_PATH, _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) rm_tree(p); else DeleteFileW(p);
        } while (FindNextFileW(f, &fd));
        FindClose(f);
    }
    RemoveDirectoryW(dir);
}

int main(void)
{
    wchar_t root[MAX_PATH]; GetTempPathW(MAX_PATH, root);
    wchar_t sub[64]; _snwprintf_s(sub, 64, _TRUNCATE, L"pbtest_profile_%lu", GetCurrentProcessId());
    wcscat_s(root, MAX_PATH, sub);
    CreateDirectoryW(root, NULL); SetEnvironmentVariableW(L"APPDATA", root);
    wchar_t dir[MAX_PATH], pdir[MAX_PATH];
    _snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%s\\ProxyBridge", root); CreateDirectoryW(dir, NULL);
    _snwprintf_s(pdir, MAX_PATH, _TRUNCATE, L"%s\\profiles", dir); CreateDirectoryW(pdir, NULL);
    wchar_t p1[MAX_PATH]; _snwprintf_s(p1, MAX_PATH, _TRUNCATE, L"%s\\old.pbprofile", pdir);

    /* 1. an old-format profile: one global LocalhostViaProxy, IPs and domains in two keys, a domain typed in TargetHosts,
          and a stray line break inside the domains */
    write_file(p1, "{\"Version\":\"1.0\",\"LocalhostViaProxy\":true,\"ProxyRules\":["
        "{\"Name\":\"a\",\"ProcessName\":\"chrome.exe\",\"TargetHosts\":\"10.*.*.*\",\"TargetPorts\":\"*\",\"TargetDomains\":\"github.com;\\r\\n*.google.com\",\"Protocol\":\"TCP\",\"Action\":\"PROXY\",\"IsEnabled\":true,\"ProxyConfigId\":1},"
        "{\"Name\":\"b\",\"ProcessName\":\"x.exe\",\"TargetHosts\":\"example.org;192.168.*.*\",\"TargetPorts\":\"*\",\"TargetDomains\":\"*\",\"Protocol\":\"TCP\",\"Action\":\"DIRECT\",\"IsEnabled\":true,\"ProxyConfigId\":0},"
        "{\"Name\":\"c\",\"ProcessName\":\"y.exe\",\"TargetHosts\":\"*\",\"TargetPorts\":\"*\",\"TargetDomains\":\"*\",\"Protocol\":\"TCP\",\"Action\":\"DIRECT\",\"IsEnabled\":true,\"ProxyConfigId\":0}]}");
    PB_ProfileLoad(L"old", &g);
    CHECK(g.ruleCount == 3);
    CHECK(wcscmp(g.rule[0].hosts, L"10.*.*.*;github.com;*.google.com") == 0);        /* IPs + domains merged into one list */
    CHECK(wcsstr(g.rule[1].hosts, L"example.org") && wcsstr(g.rule[1].hosts, L"192.168.*.*"));
    CHECK(wcscmp(g.rule[2].hosts, L"*") == 0);
    CHECK(g.rule[0].localhost == 1 && g.rule[1].localhost == 1);                      /* the old global value became each rule's default */
    CHECK(g.logEveryConnection == 0);                                                /* a setting the old file does not have: off */

    /* 2. saving writes the two keys other ProxyBridge apps read; a domain typed with the IPs lands in TargetDomains */
    CHECK(PB_ProfileSave(L"new", &g));
    wchar_t p2[MAX_PATH]; _snwprintf_s(p2, MAX_PATH, _TRUNCATE, L"%s\\new.pbprofile", pdir);
    char* js = read_file(p2);
    CHECK(strstr(js, "\"TargetHosts\": \"10.*.*.*\"") != NULL);
    CHECK(strstr(js, "\"TargetDomains\": \"github.com;*.google.com\"") != NULL);
    CHECK(strstr(js, "\"TargetHosts\": \"192.168.*.*\"") != NULL);
    CHECK(strstr(js, "\"TargetDomains\": \"example.org\"") != NULL);
    CHECK(strstr(js, "\"LocalhostViaProxy\": true") != NULL);                         /* now per rule */
    free(js);
    PB_ProfileLoad(L"new", &h);
    CHECK(h.ruleCount == 3 && wcscmp(h.rule[0].hosts, g.rule[0].hosts) == 0);
    CHECK(wcscmp(h.rule[1].hosts, L"192.168.*.*;example.org") == 0);                  /* same entries, IPs first */

    /* 3. per-rule localhost and Log Every Connection round-trip */
    memset(&g, 0, sizeof g);
    g.ruleCount = 2; g.logEveryConnection = 1;
    for (int i = 0; i < 2; i++)
    {
        PBRule* r = &g.rule[i];
        wcscpy_s(r->name, 128, i ? L"b" : L"a"); wcscpy_s(r->proc, PB_APPS_MAX, L"*"); wcscpy_s(r->hosts, PB_HOSTS_MAX, L"*");
        wcscpy_s(r->ports, 128, L"*"); wcscpy_s(r->proto, 8, L"TCP"); wcscpy_s(r->action, 16, L"PROXY"); r->enabled = 1; r->localhost = i;   /* a: off, b: on */
    }
    CHECK(PB_ProfileSave(L"flags", &g));
    PB_ProfileLoad(L"flags", &h);
    CHECK(h.ruleCount == 2 && h.rule[0].localhost == 0 && h.rule[1].localhost == 1 && h.logEveryConnection == 1);

    /* 4. a long list (about 8000 characters) survives save + load without truncation */
    memset(&g, 0, sizeof g); g.ruleCount = 1;
    PBRule* r0 = &g.rule[0];
    wcscpy_s(r0->name, 128, L"big"); wcscpy_s(r0->proc, PB_APPS_MAX, L"*"); wcscpy_s(r0->ports, 128, L"*");
    wcscpy_s(r0->proto, 8, L"TCP"); wcscpy_s(r0->action, 16, L"DIRECT"); r0->enabled = 1;
    size_t o = 0; int n = 0;
    while (o + 30 < 8000) o += swprintf(r0->hosts + o, PB_HOSTS_MAX - o, L"%lshost%d.example.org", o ? L";" : L"", n++);
    size_t want = wcslen(r0->hosts);
    CHECK(want > 7900);
    CHECK(PB_ProfileSave(L"big", &g));
    PB_ProfileLoad(L"big", &h);
    CHECK(h.ruleCount == 1 && wcslen(h.rule[0].hosts) == want && wcscmp(h.rule[0].hosts, r0->hosts) == 0);

    /* 5. hostile file: 40,000-character TargetHosts and TargetDomains - cut cleanly, no crash, always terminated */
    char* huge = (char*)malloc(200000); size_t k = 0;
    k += sprintf(huge + k, "{\"ProxyRules\":[{\"Name\":\"h\",\"ProcessName\":\"*\",\"TargetHosts\":\"");
    for (int i = 0; k < 40000; i++) k += sprintf(huge + k, "a%d.org;", i);
    k += sprintf(huge + k, "\",\"TargetPorts\":\"*\",\"TargetDomains\":\"");
    for (int i = 0; k < 80000; i++) k += sprintf(huge + k, "b%d.net;", i);
    k += sprintf(huge + k, "\",\"Protocol\":\"TCP\",\"Action\":\"DIRECT\"}]}");
    wchar_t p3[MAX_PATH]; _snwprintf_s(p3, MAX_PATH, _TRUNCATE, L"%s\\huge.pbprofile", pdir); write_file(p3, huge); free(huge);
    memset(&h, 0x55, sizeof h);                                                       /* poison: nothing may be left unterminated */
    PB_ProfileLoad(L"huge", &h);
    CHECK(h.ruleCount == 1 && wcslen(h.rule[0].hosts) < PB_HOSTS_MAX);
    size_t hl = wcslen(h.rule[0].hosts); CHECK(hl > 0 && h.rule[0].hosts[hl - 1] != L';');
    CHECK(PB_ProfileSave(L"huge2", &h));

    /* 6. broken JSON does not crash and yields usable defaults */
    wchar_t p4[MAX_PATH]; _snwprintf_s(p4, MAX_PATH, _TRUNCATE, L"%s\\broken.pbprofile", pdir);
    write_file(p4, "{\"ProxyRules\": [ {\"Name\": \"x\", ");
    PB_ProfileLoad(L"broken", &h);
    CHECK(h.ruleCount >= 0 && h.ruleCount <= PB_MAX_RULE);

    rm_tree(root);
    return pbtest_done("test_profile");
}
