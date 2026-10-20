// Library API test against the live eBPF datapath: every rule/proxy mutation must take effect immediately on new connections.
// Needs root and the fake proxies running (tests/api_live.sh starts them).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/ProxyBridge.h"

static int pass, fail;
static int events;
static void on_conn(const char *p, uint32_t pid, const char *ip, uint16_t port, const char *info) { (void)p; (void)pid; (void)ip; (void)port; (void)info; events++; }
static void on_log(const char *m) { if (getenv("PB_VERBOSE")) fprintf(stderr, "[log] %s\n", m); }

static void fetch(const char *ip, char *out, size_t n)
{
    char cmd[256]; snprintf(cmd, sizeof cmd, "curl -s -m 2 http://%s/ 2>&1; echo \"rc=$?\"", ip);
    FILE *f = popen(cmd, "r"); size_t l = 0;
    while (f && l + 1 < n && fgets(out + l, (int)(n - l), f)) l = strlen(out);
    if (f) pclose(f);
}
static void expect(const char *what, const char *ip, const char *want)
{
    char out[512] = ""; fetch(ip, out, sizeof out);
    int ok = want ? strstr(out, want) != NULL : (strstr(out, "hello-from") == NULL && strstr(out, "rc=0") == NULL);
    if (want && !strcmp(want, "BLOCKED")) ok = strstr(out, "rc=7") != NULL;
    printf("  %s  %s\n", ok ? "PASS" : "FAIL", what); if (!ok) printf("        got: %.120s\n", out);
    ok ? pass++ : fail++;
}
static void check(const char *what, int cond) { printf("  %s  %s\n", cond ? "PASS" : "FAIL", what); cond ? pass++ : fail++; }

int main(void)
{
    char err[256] = "";
    ProxyBridge_SetLogCallback(on_log); ProxyBridge_SetConnectionCallback(on_conn); ProxyBridge_SetTrafficLoggingEnabled(true);

    printf("== validation\n");
    check("invalid host rejected with a reason", !ProxyBridge_ValidateRule("curl", "999.1.1.1", "80", err, sizeof err) && err[0]);
    check("invalid port rejected", !ProxyBridge_ValidateRule("curl", "*", "99999", err, sizeof err));
    check("domain accepted", ProxyBridge_ValidateRule("curl", "*.example.org", "443", err, sizeof err));
    check("AddRule with bad pattern returns 0 + message", ProxyBridge_AddRule("curl", "1.2.3", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 0, err, sizeof err) == 0 && err[0]);
    check("SetProxySendDomain/SetRuleLocalhost refuse unknown ids", !ProxyBridge_SetProxySendDomain(9999, false) && !ProxyBridge_SetRuleLocalhost(9999, true));
    check("AddProxy with empty host rejected", ProxyBridge_AddProxy("x", PROXY_TYPE_SOCKS5, "", 1080, "", "", err, sizeof err) == 0);
    check("AddProxy with port 0 rejected", ProxyBridge_AddProxy("x", PROXY_TYPE_SOCKS5, "h", 0, "", "", err, sizeof err) == 0);

    uint32_t pa = ProxyBridge_AddProxy("a", PROXY_TYPE_SOCKS5, "127.0.0.1", 19080, "", "", err, sizeof err);
    uint32_t pb = ProxyBridge_AddProxy("b", PROXY_TYPE_SOCKS5, "127.0.0.1", 19081, "bob", "pw", err, sizeof err);
    uint32_t pc = ProxyBridge_AddProxy("c", PROXY_TYPE_HTTP, "127.0.0.1", 19082, "", "", err, sizeof err);
    check("three proxies added with distinct ids", pa && pb && pc && pa != pb && pb != pc);
    uint32_t r1 = ProxyBridge_AddRule("curl", "192.0.2.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, pa, err, sizeof err);
    check("rule added", r1 != 0);
    check("Start", ProxyBridge_Start());
    sleep(1);

    printf("== live edits take effect on the next connection\n");
    expect("initial: rule -> proxy a", "192.0.2.5", "hello-from-A dst=192.0.2.5:80");
    check("EditRule -> proxy b", ProxyBridge_EditRule(r1, "curl", "192.0.2.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, pb, err, sizeof err));
    expect("after edit: proxy b", "192.0.2.5", "hello-from-B dst=192.0.2.5:80");
    check("EditRule with a bad pattern fails and keeps the old rule", !ProxyBridge_EditRule(r1, "curl", "bad host", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, pb, err, sizeof err));
    expect("old rule still active", "192.0.2.5", "hello-from-B");
    check("DisableRule", ProxyBridge_DisableRule(r1));
    expect("disabled: traffic is direct", "192.0.2.5", NULL);
    check("EnableRule", ProxyBridge_EnableRule(r1));
    expect("enabled again", "192.0.2.5", "hello-from-B");

    printf("== ordering\n");
    uint32_t r2 = ProxyBridge_AddRule("curl", "192.0.2.5", "*", RULE_PROTOCOL_TCP, RULE_ACTION_BLOCK, 0, err, sizeof err);
    expect("BLOCK rule added after the PROXY rule loses (first match wins)", "192.0.2.5", "hello-from-B");
    check("MoveRule to the top", ProxyBridge_MoveRule(r2, 0));
    expect("after move: BLOCK wins", "192.0.2.5", "BLOCKED");
    expect("other addresses still proxied", "192.0.2.6", "hello-from-B dst=192.0.2.6:80");
    check("MoveRule back to the end", ProxyBridge_MoveRule(r2, 99));
    expect("PROXY wins again", "192.0.2.5", "hello-from-B");
    check("DeleteRule (the BLOCK rule)", ProxyBridge_DeleteRule(r2));
    check("DeleteRule on an unknown id fails", !ProxyBridge_DeleteRule(424242));

    printf("== proxy lifecycle\n");
    check("DeleteProxy(b)", ProxyBridge_DeleteProxy(pb));
    expect("rule that used a deleted proxy falls back to the default proxy (a)", "192.0.2.5", "hello-from-A dst=192.0.2.5:80");
    ProxyBridge_ClearProxies();
    expect("no proxies at all: PROXY rule fails CLOSED (blocked, never direct)", "192.0.2.5", "BLOCKED");
    uint32_t pb2 = ProxyBridge_AddProxy("b2", PROXY_TYPE_SOCKS5, "127.0.0.1", 19081, "bob", "pw", err, sizeof err);
    uint32_t pa2 = ProxyBridge_AddProxy("a2", PROXY_TYPE_SOCKS5, "127.0.0.1", 19080, "", "", err, sizeof err);
    check("proxies re-added", pa2 && pb2);
    check("EditRule to proxy_id 0 (= default)", ProxyBridge_EditRule(r1, "curl", "192.0.2.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 0, err, sizeof err));
    expect("default = first proxy added (b2)", "192.0.2.5", "hello-from-B");
    ProxyBridge_SetDefaultProxy(pa2);
    expect("SetDefaultProxy(a2) retargets proxy_id 0 rules", "192.0.2.5", "hello-from-A");
    check("EditProxy changes the endpoint live (a2 -> HTTP proxy c's port)", ProxyBridge_EditProxy(pa2, "a2", PROXY_TYPE_HTTP, "127.0.0.1", 19082, "", "", err, sizeof err));
    expect("now served through the HTTP proxy", "192.0.2.5", "hello-from-C dst=192.0.2.5:80");

    printf("== stop/start keeps configuration\n");
    check("Stop", ProxyBridge_Stop());
    expect("while stopped: nothing redirected", "192.0.2.5", NULL);
    check("Start again", ProxyBridge_Start());
    sleep(1);
    expect("rules and proxies survived Stop/Start", "192.0.2.5", "hello-from-C");

    printf("== proxy test helper\n");
    char buf[512] = "";
    check("TestProxy through a SOCKS5 proxy works", ProxyBridge_TestProxy(pb2, "192.0.2.77", 80, buf, sizeof buf) == 0);
    printf("        (%s)\n", buf);
    uint32_t dead = ProxyBridge_AddProxy("dead", PROXY_TYPE_SOCKS5, "127.0.0.1", 19999, "", "", err, sizeof err);
    buf[0] = 0; check("TestProxy against a dead proxy fails with a readable message", ProxyBridge_TestProxy(dead, "192.0.2.77", 80, buf, sizeof buf) != 0 && strlen(buf) > 5);
    printf("        (%s)\n", buf);

    printf("== cleanup\n");
    ProxyBridge_ClearRules();
    expect("ClearRules: direct again", "192.0.2.5", NULL);
    check("connection events were reported to the callback", events > 0);
    ProxyBridge_Stop();
    printf("\npassed=%d failed=%d\n", pass, fail);
    return fail != 0;
}
