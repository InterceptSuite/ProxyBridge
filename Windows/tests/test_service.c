// test_service.c - the engine service (src\service\pb_service.c), included as source so its static functions can be
// called directly, with the engine API replaced by recording stubs:
//   - the request handler: every operation, argument decoding (NULL strings, flags), validation and malformed input
//   - the named-pipe permission list: SYSTEM and Administrators only (plus the optional per-user SIDs), no one else
//   - pipe-name squatting protection (FILE_FLAG_FIRST_PIPE_INSTANCE) and the SID sanity check used for the ACL
// No service is started and the real ProxyBridge pipes are never touched (the pipe tests use a private pipe name).
#define wmain pb_svc_wmain
#include "../src/service/pb_service.c"
#undef wmain
#include <aclapi.h>
#include "pbtest.h"

/* ---- engine stubs ---- */
static struct { PBProxyType type; char ip[64]; unsigned short port; char user[64], pass[64]; BOOL userNull, passNull, sd; UINT32 id; int calls; } P;
static struct { UINT32 id; char proc[128], hosts[128], ports[64], domains[128]; BOOL procNull, hostsNull, portsNull, domainsNull;
                PBRuleProtocol proto; PBRuleAction act; UINT32 cfg; BOOL localhost; int adds, edits; } R;
static UINT32 g_enabled, g_disabled, g_deleted, g_moveId, g_movePos, g_posQuery, g_delProxy;
static int g_trafficArg = -1, g_enableArg = -1, g_logAllArg = -1, g_cleared = 0, g_started = 0, g_stopped = 0;

static void cp(char* d, size_t n, const char* s) { if (s) strncpy_s(d, n, s, _TRUNCATE); else d[0] = 0; }   /* long fuzz strings are cut, not fatal */
static UINT32 SAddProxy(PBProxyType t, const char* ip, unsigned short port, const char* u, const char* p, BOOL sd) { P.type = t; cp(P.ip, 64, ip); P.port = port; cp(P.user, 64, u); cp(P.pass, 64, p); P.userNull = !u; P.passNull = !p; P.sd = sd; P.calls++; return 41; }
static BOOL   SEditProxy(UINT32 id, PBProxyType t, const char* ip, unsigned short port, const char* u, const char* p, BOOL sd) { P.id = id; SAddProxy(t, ip, port, u, p, sd); return TRUE; }
static BOOL   SDelProxy(UINT32 id) { g_delProxy = id; return TRUE; }
static UINT32 SAddRule(const char* a, const char* b, const char* c, const char* d, PBRuleProtocol pr, PBRuleAction ac, UINT32 cfg, BOOL lh)
{ cp(R.proc, 128, a); cp(R.hosts, 128, b); cp(R.ports, 64, c); cp(R.domains, 128, d); R.procNull = !a; R.hostsNull = !b; R.portsNull = !c; R.domainsNull = !d; R.proto = pr; R.act = ac; R.cfg = cfg; R.localhost = lh; R.adds++; return 77; }
static BOOL   SEditRule(UINT32 id, const char* a, const char* b, const char* c, const char* d, PBRuleProtocol pr, PBRuleAction ac, UINT32 cfg, BOOL lh) { R.id = id; SAddRule(a, b, c, d, pr, ac, cfg, lh); R.adds--; R.edits++; return TRUE; }
static BOOL   SEnable(UINT32 id)  { g_enabled = id; return TRUE; }
static BOOL   SDisable(UINT32 id) { g_disabled = id; return TRUE; }
static BOOL   SDelete(UINT32 id)  { g_deleted = id; return TRUE; }
static BOOL   SMove(UINT32 id, UINT32 pos) { g_moveId = id; g_movePos = pos; return TRUE; }
static UINT32 SGetPos(UINT32 id)  { g_posQuery = id; return 5; }
static void   STraffic(BOOL v) { g_trafficArg = v; }
static void   SEnabled(BOOL v) { g_enableArg = v; }
static void   SLogAll(BOOL v)  { g_logAllArg = v; }
static void   SClear(void)     { g_cleared++; }
static BOOL   SStart(void)     { g_started++; return TRUE; }
static BOOL   SStop(void)      { g_stopped++; return FALSE; }
static UINT32 g_flowsAsked = 0, g_flowsHave = 0;
static UINT32 SGetFlows(PBFlow* out, UINT32 max)
{
    g_flowsAsked = max;
    UINT32 n = g_flowsHave < max ? g_flowsHave : max;
    for (UINT32 i = 0; i < n; i++)
    {
        ZeroMemory(&out[i], sizeof out[i]);
        out[i].id = 0x100000002ull + i; out[i].pid = 4000 + i; out[i].proxy_config_id = 7; out[i].rule_id = 40 + i; out[i].age_ms = i ? 0xFFFFFFFFu : 1500;
        out[i].sent = 0x500000001ull; out[i].received = 99; out[i].port = 443; out[i].is_udp = (UINT8)(i & 1); out[i].is_ipv6 = (UINT8)((i >> 1) & 1);
        strcpy_s(out[i].name, sizeof out[i].name, "chrome.exe"); strcpy_s(out[i].host, sizeof out[i].host, "example.com");
    }
    if (n) memset(out[n - 1].name, 'x', sizeof out[n - 1].name);       /* an unterminated name must not run past the field */
    return n;
}

/* ---- request helpers ---- */
static BYTE  rq[PB_MSG_MAX], rs[PB_MSG_MAX];
static PbW   W;
static void  begin(UINT32 op) { PbW_Init(&W, rq, sizeof rq); PbW_U32(&W, op); }
static BOOL  run(UINT32* ret) { PbW resp; PbW_Init(&resp, rs, sizeof rs); BOOL ok = Dispatch(rq, W.len, &resp); if (ok && ret) { PbR r; PbR_Init(&r, rs, resp.len); *ret = PbR_U32(&r); } return ok; }

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    g_api.AddProxyConfig = SAddProxy; g_api.EditProxyConfig = SEditProxy; g_api.DeleteProxyConfig = SDelProxy;
    g_api.AddRule = SAddRule; g_api.EditRule = SEditRule; g_api.EnableRule = SEnable; g_api.DisableRule = SDisable; g_api.DeleteRule = SDelete;
    g_api.MoveRuleToPosition = SMove; g_api.GetRulePosition = SGetPos;
    g_api.SetTrafficLoggingEnabled = STraffic; g_api.SetEnabled = SEnabled; g_api.SetLogEveryConnection = SLogAll; g_api.ClearConnectionLogs = SClear;
    g_api.Start = SStart; g_api.Stop = SStop; g_api.TestProxyConfigEx = NULL; g_api.GetFlows = SGetFlows;
    UINT32 ret;

    /* ================= request handler ================= */
    begin(PBOP_HELLO);                                   CHECK(run(&ret) && ret == PB_PROTO_VERSION && PB_PROTO_VERSION >= 5);
    begin(PBOP_ADD_PROXY); PbW_U32(&W, 1); PbW_Str(&W, "127.0.0.1"); PbW_U32(&W, 1080); PbW_Str(&W, "alice"); PbW_Str(&W, "pw"); PbW_U32(&W, 1);
    CHECK(run(&ret) && ret == 41 && P.type == 1 && !strcmp(P.ip, "127.0.0.1") && P.port == 1080 && !strcmp(P.user, "alice") && !strcmp(P.pass, "pw") && P.sd);
    begin(PBOP_ADD_PROXY); PbW_U32(&W, 0); PbW_Str(&W, "10.0.0.1"); PbW_U32(&W, 8080); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_U32(&W, 0);
    CHECK(run(&ret) && P.type == 0 && P.userNull && P.passNull && !P.sd);                       /* NULL strings reach the engine as NULL */
    begin(PBOP_ADD_PROXY); PbW_U32(&W, 2); PbW_Str(&W, "x"); PbW_U32(&W, 1); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_U32(&W, 0); { int c = P.calls; CHECK(!run(&ret) && P.calls == c); }   /* unknown type */
    begin(PBOP_ADD_PROXY); PbW_U32(&W, 1); PbW_Str(&W, "x"); PbW_U32(&W, 70000); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_U32(&W, 0); { int c = P.calls; CHECK(!run(&ret) && P.calls == c); }   /* port > 65535 */
    begin(PBOP_ADD_PROXY); PbW_U32(&W, 1); { int c = P.calls; CHECK(!run(&ret) && P.calls == c); }                                       /* truncated */
    begin(PBOP_EDIT_PROXY); PbW_U32(&W, 9); PbW_U32(&W, 1); PbW_Str(&W, "h"); PbW_U32(&W, 5); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_U32(&W, 1);
    CHECK(run(&ret) && P.id == 9 && P.type == 1 && P.port == 5);
    begin(PBOP_DELETE_PROXY); PbW_U32(&W, 12);           CHECK(run(&ret) && ret == 1 && g_delProxy == 12);

    begin(PBOP_ADD_RULE); PbW_Str(&W, "chrome.exe"); PbW_Str(&W, "10.*.*.*"); PbW_Str(&W, "443"); PbW_Str(&W, "github.com"); PbW_U32(&W, 0); PbW_U32(&W, 0); PbW_U32(&W, 3); PbW_U32(&W, 1);
    CHECK(run(&ret) && ret == 77 && !strcmp(R.proc, "chrome.exe") && !strcmp(R.hosts, "10.*.*.*") && !strcmp(R.ports, "443") && !strcmp(R.domains, "github.com"));
    CHECK(R.proto == 0 && R.act == 0 && R.cfg == 3 && R.localhost == TRUE);                      /* the per-rule localhost flag arrives */
    begin(PBOP_ADD_RULE); PbW_Str(&W, "x.exe"); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_Str(&W, NULL); PbW_U32(&W, 2); PbW_U32(&W, 2); PbW_U32(&W, 0); PbW_U32(&W, 0);
    CHECK(run(&ret) && R.hostsNull && R.portsNull && R.domainsNull && !R.procNull && R.proto == 2 && R.act == 2 && R.localhost == FALSE);
    begin(PBOP_ADD_RULE); PbW_Str(&W, "x.exe"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_U32(&W, 3); PbW_U32(&W, 0); PbW_U32(&W, 0); PbW_U32(&W, 0);
    { int c = R.adds; CHECK(!run(&ret) && R.adds == c); }                                         /* protocol 3 is invalid */
    begin(PBOP_ADD_RULE); PbW_Str(&W, "x.exe"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_U32(&W, 0); PbW_U32(&W, 3); PbW_U32(&W, 0); PbW_U32(&W, 0);
    { int c = R.adds; CHECK(!run(&ret) && R.adds == c); }                                         /* action 3 is invalid */
    begin(PBOP_ADD_RULE); PbW_Str(&W, "x.exe"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_Str(&W, "*"); PbW_U32(&W, 0); PbW_U32(&W, 0); PbW_U32(&W, 0);
    { int c = R.adds; CHECK(!run(&ret) && R.adds == c); }                                         /* an old client without the localhost field */
    begin(PBOP_EDIT_RULE); PbW_U32(&W, 5); PbW_Str(&W, "e.exe"); PbW_Str(&W, "1.1.1.1"); PbW_Str(&W, "80"); PbW_Str(&W, "*"); PbW_U32(&W, 1); PbW_U32(&W, 1); PbW_U32(&W, 2); PbW_U32(&W, 1);
    CHECK(run(&ret) && R.id == 5 && !strcmp(R.proc, "e.exe") && R.localhost == TRUE && R.edits == 1);
    begin(PBOP_ENABLE_RULE);  PbW_U32(&W, 4); CHECK(run(&ret) && g_enabled == 4);
    begin(PBOP_DISABLE_RULE); PbW_U32(&W, 6); CHECK(run(&ret) && g_disabled == 6);
    begin(PBOP_DELETE_RULE);  PbW_U32(&W, 8); CHECK(run(&ret) && g_deleted == 8);
    begin(PBOP_MOVE_RULE);    PbW_U32(&W, 2); PbW_U32(&W, 9); CHECK(run(&ret) && g_moveId == 2 && g_movePos == 9);
    begin(PBOP_GET_RULE_POS); PbW_U32(&W, 3); CHECK(run(&ret) && ret == 5 && g_posQuery == 3);
    begin(PBOP_ENABLE_RULE);  CHECK(!run(&ret));                                                  /* missing id */

    begin(PBOP_SET_TRAFFIC_LOG); PbW_U32(&W, 1); CHECK(run(&ret) && g_trafficArg == 1);
    begin(PBOP_SET_TRAFFIC_LOG); PbW_U32(&W, 0); CHECK(run(&ret) && g_trafficArg == 0);
    begin(PBOP_SET_ENABLED);     PbW_U32(&W, 0); CHECK(run(&ret) && g_enableArg == 0);            /* main switch */
    begin(PBOP_SET_ENABLED);     PbW_U32(&W, 1); CHECK(run(&ret) && g_enableArg == 1);
    begin(PBOP_SET_ENABLED);     PbW_U32(&W, 7); CHECK(run(&ret) && g_enableArg == 1);            /* any non-zero value is "on" */
    begin(PBOP_SET_LOG_ALL);     PbW_U32(&W, 1); CHECK(run(&ret) && g_logAllArg == 1);
    begin(PBOP_SET_ENABLED);                     CHECK(!run(&ret));                               /* argument missing */
    begin(PBOP_CLEAR_CONN_LOGS);                 CHECK(run(&ret) && g_cleared == 1);
    begin(PBOP_START);                           CHECK(run(&ret) && ret == 1 && g_started == 1);
    begin(PBOP_STOP);                            CHECK(run(&ret) && ret == 0 && g_stopped == 1);

    /* live connections */
    g_flowsHave = 3;
    begin(PBOP_GET_FLOWS); PbW_U32(&W, 10);
    { PbW resp; PbW_Init(&resp, rs, sizeof rs); CHECK(Dispatch(rq, W.len, &resp) && resp.ok);
      PbR r; PbR_Init(&r, rs, resp.len);
      CHECK(PbR_U32(&r) == 3 && g_flowsAsked == 10);
      for (int i = 0; i < 3; i++)
      {
          UINT32 lo = PbR_U32(&r), hi = PbR_U32(&r); UINT32 pid = PbR_U32(&r), flags = PbR_U32(&r), port = PbR_U32(&r), cfg = PbR_U32(&r), rid = PbR_U32(&r), age = PbR_U32(&r);
          UINT32 sl = PbR_U32(&r), sh = PbR_U32(&r), rl = PbR_U32(&r), rh = PbR_U32(&r);
          char name[64], host[64]; PbR_Str(&r, name, sizeof name, NULL); PbR_Str(&r, host, sizeof host, NULL);
          CHECK(r.ok && lo == 2u + i && hi == 1 && pid == 4000u + i && port == 443 && cfg == 7 && rid == 40u + i && sl == 1 && sh == 5 && rl == 99 && rh == 0);
          CHECK(flags == (UINT32)(((i & 1) ? 1 : 0) | (((i >> 1) & 1) ? 2 : 0)) && age == (i ? 0xFFFFFFFFu : 1500u) && !strcmp(host, "example.com"));
          if (i == 2) CHECK(strlen(name) == 39);                                           /* the unterminated name was cut at the field size */
          else        CHECK(!strcmp(name, "chrome.exe"));
      }
      CHECK(r.pos == r.len); }                                                               /* nothing left over */
    begin(PBOP_GET_FLOWS); PbW_U32(&W, 0xFFFFFFFFu); CHECK(run(&ret) && ret == 3 && g_flowsAsked == PB_FLOWS_MAX_GUI);   /* a huge request is capped */
    g_flowsHave = 0; begin(PBOP_GET_FLOWS); PbW_U32(&W, 5); CHECK(run(&ret) && ret == 0);
    g_flowsHave = 1000; begin(PBOP_GET_FLOWS); PbW_U32(&W, 400);                              /* the biggest possible answer still fits one message */
    { PbW resp; PbW_Init(&resp, rs, sizeof rs); CHECK(Dispatch(rq, W.len, &resp) && resp.ok && resp.len <= PB_MSG_MAX); PbR r; PbR_Init(&r, rs, resp.len); CHECK(PbR_U32(&r) == 400); }
    begin(PBOP_GET_FLOWS); CHECK(!run(&ret));                                                 /* missing argument */
    g_flowsHave = 0;

    /* unknown operations and garbage are rejected without touching the engine */
    begin(0);        CHECK(!run(&ret));
    begin(9999);     CHECK(!run(&ret));
    PbW_Init(&W, rq, sizeof rq); CHECK(!run(&ret));                                               /* empty request */
    { int a = R.adds + P.calls; srand(99);
      for (int it = 0; it < 30000; it++)                                                          /* random requests: no crash, no overrun (guard page) */
      {
          int n = rand() % 120; BYTE tmp[160];
          for (int i = 0; i < n; i++) tmp[i] = (BYTE)(rand() % 4 ? rand() % 40 : rand());
          if (n >= 4 && it % 2) { UINT32 op = 1 + rand() % (PBOP_GET_FLOWS + 1); memcpy(tmp, &op, 4); }
          void* base; BYTE* g = pb_guarded(tmp, (size_t)n, &base);
          PbW resp; PbW_Init(&resp, rs, sizeof rs); Dispatch(g, (DWORD)n, &resp);
          pb_guard_release(base);
      }
      g_checks += 30000; (void)a; }

    /* ================= pipe permission list ================= */
    wchar_t sddl[1024]; BuildPipeSddl(sddl, ARRAYSIZE(sddl));
    CHECK(wcsncmp(sddl, L"D:(A;;GA;;;SY)(A;;GA;;;BA)", 25) == 0);                                  /* SYSTEM + Administrators always */
    const wchar_t* bad[] = { L";;;WD)", L";;;IU)", L";;;AU)", L";;;BU)", L";;;NU)", L";;;AN)", L";;;S-1-1-0)", L";;;S-1-5-4)", L";;;S-1-5-11)", L";;;S-1-5-32-545)" };
    for (int i = 0; i < ARRAYSIZE(bad); i++) CHECK(wcsstr(sddl, bad[i]) == NULL);                  /* never Everyone / interactive / authenticated / users / anonymous */
    { PSECURITY_DESCRIPTOR psd = NULL; CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &psd, NULL)); if (psd) LocalFree(psd); }   /* well formed */

    CHECK(LooksLikeSid(L"S-1-5-21-1004336348-1177238915-682003330-1001") && LooksLikeSid(L"S-1-5-18"));
    CHECK(!LooksLikeSid(L"") && !LooksLikeSid(L"S") && !LooksLikeSid(L"X-1-5-18") && !LooksLikeSid(L"S-1-5-18)(A;;GA;;;WD") && !LooksLikeSid(L"S-1-5-18 ") && !LooksLikeSid(L"s-1-5-18"));
    { wchar_t longsid[200]; wcscpy_s(longsid, 200, L"S-1"); for (int i = 0; i < 20; i++) wcscat_s(longsid, 200, L"-12345"); CHECK(!LooksLikeSid(longsid)); }   /* 123 characters: too long */

    /* the pipe created by MakePipe really carries that list, and a second owner of the same name is refused */
    { wchar_t name[80]; _snwprintf_s(name, 80, _TRUNCATE, L"\\\\.\\pipe\\pbtest_%lu", GetCurrentProcessId());
      HANDLE h1 = MakePipe(name, TRUE, PIPE_ACCESS_DUPLEX);
      CHECK(h1 != INVALID_HANDLE_VALUE);
      if (h1 != INVALID_HANDLE_VALUE)
      {
          PSECURITY_DESCRIPTOR sd = NULL; PACL dacl = NULL;
          if (GetSecurityInfo(h1, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS)
          {
              LPWSTR s = NULL; ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &s, NULL);
              CHECK(s && wcsstr(s, L";;;SY)") && wcsstr(s, L";;;BA)") && !wcsstr(s, L";;;WD)") && !wcsstr(s, L";;;IU)") && !wcsstr(s, L";;;AU)") && !wcsstr(s, L";;;BU)"));
              if (s) LocalFree(s);
              LocalFree(sd);
          }
          else CHECK(FALSE);
          HANDLE h2 = MakePipe(name, TRUE, PIPE_ACCESS_DUPLEX);                                    /* someone else squatting on the name */
          CHECK(h2 == INVALID_HANDLE_VALUE);
          if (h2 != INVALID_HANDLE_VALUE) CloseHandle(h2);
          CloseHandle(h1);
      } }

    return pbtest_done("test_service");
}
