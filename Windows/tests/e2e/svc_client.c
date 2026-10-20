// svc_client.c - test helper for run_e2e_service.ps1.
//
// Talks to the installed ProxyBridge Service exactly like the app does (it includes the app's own pipe client,
// gui\api\pb_ipc.h), but is driven by text commands on stdin instead of menus, and answers on stdout. This lets the
// end-to-end test add proxies and rules, start the engine, read the Live Connections data and watch the connection events
// of the real service while real traffic flows.
//
//   svc_client.exe            interactive: one command per line (fields separated by TAB), see the list below
//   svc_client.exe --probe    connect, print CONNECTED (or why not) and exit - used to test who may use the service
//
// Answers: OK[\t..] | ERR[\t..] | FLOW lines followed by END\t<count> | EVT\t... (asynchronous log and connection events)
//   proxy  <socks5|http> <host> <port> <user|-> <pass|-> <sendDomain 0|1>      OK <id>
//   rule   <process> <hosts> <ports> <domains> <tcp|udp|both> <proxy|direct|block> <proxyId> <localhost 0|1>   OK <id>
//   enable_rule|disable_rule|delete_rule <id>        move_rule <id> <position>        rulepos <id>
//   start | stop | enabled <0|1> | logall <0|1> | traffic <0|1> | clearlogs | flows | sleep <ms> | quit
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "../../gui/api/pb_ipc.h"

static CRITICAL_SECTION g_out;

static void out(const char* fmt, ...)
{
    EnterCriticalSection(&g_out);
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    fflush(stdout);
    LeaveCriticalSection(&g_out);
}
static void oneline(char* s) { for (; *s; s++) if (*s == '\n' || *s == '\r' || *s == '\t') *s = ' '; }

static void on_log(const char* m)
{
    char b[1024]; strncpy(b, m ? m : "", sizeof(b) - 1); b[sizeof(b) - 1] = 0; oneline(b);
    out("EVT\tLOG\t%s\n", b);
}
static void on_conn(const char* proc, DWORD pid, const char* ip, unsigned short port, const char* info)
{
    char p[300], i[300], f[400];
    strncpy(p, proc ? proc : "", sizeof(p) - 1); p[sizeof(p) - 1] = 0; oneline(p);
    strncpy(i, ip ? ip : "", sizeof(i) - 1); i[sizeof(i) - 1] = 0; oneline(i);
    strncpy(f, info ? info : "", sizeof(f) - 1); f[sizeof(f) - 1] = 0; oneline(f);
    out("EVT\tCONN\t%s\t%lu\t%s\t%u\t%s\n", p, (unsigned long)pid, i, (unsigned)port, f);
}

static const char* why(int rc)
{
    switch (rc) { case PB_IPC_NO_SERVICE: return "NO_SERVICE"; case PB_IPC_BUSY: return "BUSY"; case PB_IPC_BAD_VERSION: return "BAD_VERSION"; case PB_IPC_DENIED: return "DENIED"; }
    return "UNKNOWN";
}

static int split(char* line, char** f, int max)
{
    int n = 0;
    while (n < max) { f[n++] = line; char* t = strchr(line, '\t'); if (!t) break; *t = 0; line = t + 1; }
    return n;
}

int main(int argc, char** argv)
{
    InitializeCriticalSection(&g_out);
    PBApi api;
    int rc = PB_LoadService(&api);
    if (rc != PB_IPC_OK) { out("CONNECT_FAILED\t%s\n", why(rc)); return 3; }
    out("CONNECTED\n");
    if (argc > 1 && strcmp(argv[1], "--probe") == 0) return 0;

    api.SetLogCallback(on_log);
    api.SetConnectionCallback(on_conn);

    static PBFlow flows[PB_FLOWS_MAX_GUI];
    char line[8192];
    while (fgets(line, sizeof(line), stdin))
    {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (!l) continue;
        char* f[16] = { 0 };
        int n = split(line, f, 16);
        const char* c = f[0];

        if (!strcmp(c, "proxy") && n >= 7)
        {
            PBProxyType t = _stricmp(f[1], "http") == 0 ? PB_PROXY_HTTP : PB_PROXY_SOCKS5;
            UINT32 id = api.AddProxyConfig(t, f[2], (unsigned short)atoi(f[3]), strcmp(f[4], "-") ? f[4] : NULL, strcmp(f[5], "-") ? f[5] : NULL, atoi(f[6]) != 0);
            if (id) out("OK\t%u\n", id); else out("ERR\tproxy\n");
        }
        else if (!strcmp(c, "rule") && n >= 9)
        {
            PBRuleProtocol p = !_stricmp(f[5], "udp") ? PB_PROTO_UDP : !_stricmp(f[5], "both") ? PB_PROTO_BOTH : PB_PROTO_TCP;
            PBRuleAction a = !_stricmp(f[6], "direct") ? PB_ACTION_DIRECT : !_stricmp(f[6], "block") ? PB_ACTION_BLOCK : PB_ACTION_PROXY;
            UINT32 id = api.AddRule(f[1], f[2], f[3], f[4], p, a, (UINT32)atoi(f[7]), atoi(f[8]) != 0);
            if (id) out("OK\t%u\n", id); else out("ERR\trule\n");
        }
        else if (!strcmp(c, "enable_rule") && n >= 2)  out(api.EnableRule((UINT32)atoi(f[1])) ? "OK\n" : "ERR\tenable_rule\n");
        else if (!strcmp(c, "disable_rule") && n >= 2) out(api.DisableRule((UINT32)atoi(f[1])) ? "OK\n" : "ERR\tdisable_rule\n");
        else if (!strcmp(c, "delete_rule") && n >= 2)  out(api.DeleteRule((UINT32)atoi(f[1])) ? "OK\n" : "ERR\tdelete_rule\n");
        else if (!strcmp(c, "move_rule") && n >= 3)    out(api.MoveRuleToPosition((UINT32)atoi(f[1]), (UINT32)atoi(f[2])) ? "OK\n" : "ERR\tmove_rule\n");
        else if (!strcmp(c, "rulepos") && n >= 2)      out("OK\t%u\n", api.GetRulePosition((UINT32)atoi(f[1])));
        else if (!strcmp(c, "start"))                  out(api.Start() ? "OK\n" : "ERR\tstart\n");
        else if (!strcmp(c, "stop"))                   out(api.Stop() ? "OK\n" : "ERR\tstop\n");
        else if (!strcmp(c, "enabled") && n >= 2)      { api.SetEnabled(atoi(f[1]) != 0); out("OK\n"); }
        else if (!strcmp(c, "logall") && n >= 2)       { api.SetLogEveryConnection(atoi(f[1]) != 0); out("OK\n"); }
        else if (!strcmp(c, "traffic") && n >= 2)      { api.SetTrafficLoggingEnabled(atoi(f[1]) != 0); out("OK\n"); }
        else if (!strcmp(c, "clearlogs"))              { api.ClearConnectionLogs(); out("OK\n"); }
        else if (!strcmp(c, "sleep") && n >= 2)        { Sleep((DWORD)atoi(f[1])); out("OK\n"); }
        else if (!strcmp(c, "flows"))
        {
            UINT32 cnt = api.GetFlows(flows, PB_FLOWS_MAX_GUI);
            for (UINT32 i = 0; i < cnt; i++)
            {
                const PBFlow* x = &flows[i];
                char nm[64], hs[96]; strncpy(nm, x->name, sizeof(nm) - 1); nm[sizeof(nm) - 1] = 0; oneline(nm);
                strncpy(hs, x->host, sizeof(hs) - 1); hs[sizeof(hs) - 1] = 0; oneline(hs);
                out("FLOW\t%llu\t%lu\t%u\t%u\t%s\t%u\t%llu\t%llu\t%s\t%u\t%u\t%u\n", (unsigned long long)x->id, (unsigned long)x->pid, (unsigned)x->is_udp,
                    (unsigned)x->is_ipv6, hs, (unsigned)x->port, (unsigned long long)x->sent, (unsigned long long)x->received, nm,
                    (unsigned)x->rule_id, (unsigned)x->proxy_config_id, (unsigned)x->age_ms);
            }
            out("END\t%u\n", cnt);
        }
        else if (!strcmp(c, "quit")) { api.Stop(); out("OK\n"); return 0; }
        else out("ERR\tunknown command or missing arguments\n");
    }
    api.Stop();       // stdin closed: leave the engine stopped
    return 0;
}
