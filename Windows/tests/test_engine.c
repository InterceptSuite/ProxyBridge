// test_engine.c - the rule engine, linked from the real core sources (no driver is opened, no packet is captured):
//   - a rule's host part: IP entries OR domain entries (names come from the DNS snoop cache), IPv4 and IPv6
//   - ports still AND with hosts, wildcard-process rules, EditRule
//   - the per-rule "also proxy localhost" flag
//   - the main switch: paused = nothing is proxied or blocked for new connections
#include "pb_internal.h"
#include "pbtest.h"

static UINT32 ip4(const char* s) { struct in_addr a; inet_pton(AF_INET, s, &a); return a.S_un.S_addr; }
static RuleAction m4(const char* proc, const char* ip, int port) { UINT32 id = 0; return match_rule(proc, ip4(ip), (UINT16)port, FALSE, &id); }
static RuleAction m6(const char* proc, const char* ip, int port) { UINT8 a[16]; inet_pton(AF_INET6, ip, a); UINT32 id = 0; return match_rule_v6(proc, a, (UINT16)port, FALSE, &id); }

int main(void)
{
    dns_cache_init();
    /* names the DNS tap "learned" */
    dns_cache_store(ip4("140.82.112.3"), "github.com");
    dns_cache_store(ip4("142.250.1.1"), "www.google.com");
    dns_cache_store(ip4("10.9.9.9"), "intranet.corp");
    { UINT8 a6[16]; inet_pton(AF_INET6, "2606:4700::1111", a6); dns_cache_store_v6(a6, "github.com"); }

    /* 1. IP list AND domain list set on one rule: either is enough (it used to need both) */
    UINT32 a = ProxyBridge_AddRule("chrome.exe", "10.*.*.*", "*", "github.com;*.google.com", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(a != 0);
    CHECK(m4("chrome.exe", "10.1.2.3", 443)      == RULE_ACTION_PROXY);    /* IP entry only (name unknown)             */
    CHECK(m4("chrome.exe", "10.9.9.9", 443)      == RULE_ACTION_PROXY);    /* IP entry; name intranet.corp not listed  */
    CHECK(m4("chrome.exe", "140.82.112.3", 443)  == RULE_ACTION_PROXY);    /* domain entry only (public IP)            */
    CHECK(m4("chrome.exe", "142.250.1.1", 80)    == RULE_ACTION_PROXY);    /* wildcard domain entry                    */
    CHECK(m4("chrome.exe", "8.8.8.8", 443)       == RULE_ACTION_DIRECT);   /* neither                                  */
    CHECK(m4("chrome.exe", "93.184.216.34", 443) == RULE_ACTION_DIRECT);   /* unknown name, not in the IP list         */
    CHECK(m4("firefox.exe", "10.1.2.3", 443)     == RULE_ACTION_DIRECT);   /* another process is unaffected            */
    ProxyBridge_DeleteRule(a);

    /* 2. domains only (IP side "*"): an IP-only match must not leak in */
    UINT32 b = ProxyBridge_AddRule("chrome.exe", "*", "*", "github.com", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m4("chrome.exe", "140.82.112.3", 443) == RULE_ACTION_PROXY);
    CHECK(m4("chrome.exe", "142.250.1.1", 443)  == RULE_ACTION_DIRECT);
    CHECK(m4("chrome.exe", "10.1.2.3", 443)     == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(b);

    /* 3. IPs only (domain side "*") */
    UINT32 c = ProxyBridge_AddRule("chrome.exe", "192.168.*.*;10.0.0.1", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m4("chrome.exe", "192.168.4.4", 1)  == RULE_ACTION_PROXY);
    CHECK(m4("chrome.exe", "10.0.0.1", 1)     == RULE_ACTION_PROXY);
    CHECK(m4("chrome.exe", "140.82.112.3", 1) == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(c);

    /* 4. everything wildcard matches every host; ports still AND with hosts */
    UINT32 d = ProxyBridge_AddRule("chrome.exe", "*", "443", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    CHECK(m4("chrome.exe", "8.8.8.8", 443) == RULE_ACTION_BLOCK);
    CHECK(m4("chrome.exe", "8.8.8.8", 80)  == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(d);
    UINT32 e = ProxyBridge_AddRule("chrome.exe", "10.*.*.*", "443", "github.com", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m4("chrome.exe", "140.82.112.3", 443) == RULE_ACTION_PROXY && m4("chrome.exe", "140.82.112.3", 80) == RULE_ACTION_DIRECT);
    CHECK(m4("chrome.exe", "10.5.5.5", 443)     == RULE_ACTION_PROXY && m4("chrome.exe", "10.5.5.5", 80)      == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(e);

    /* 5. a wildcard-process rule with filters uses the same either-or logic */
    UINT32 f = ProxyBridge_AddRule("*", "10.*.*.*", "*", "github.com", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    CHECK(m4("anything.exe", "140.82.112.3", 443) == RULE_ACTION_BLOCK);
    CHECK(m4("anything.exe", "10.2.3.4", 443)     == RULE_ACTION_BLOCK);
    CHECK(m4("anything.exe", "8.8.8.8", 443)      == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(f);

    /* 6. IPv6: address entry OR domain entry */
    UINT32 g6 = ProxyBridge_AddRule("chrome.exe", "2001:db8::/32", "*", "github.com", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m6("chrome.exe", "2001:db8::1", 443)     == RULE_ACTION_PROXY);    /* address entry */
    CHECK(m6("chrome.exe", "2606:4700::1111", 443) == RULE_ACTION_PROXY);    /* domain entry (learned AAAA) */
    CHECK(m6("chrome.exe", "2a00:1450::1", 443)    == RULE_ACTION_DIRECT);
    ProxyBridge_DeleteRule(g6);

    /* 7. EditRule works with the new matching */
    UINT32 h = ProxyBridge_AddRule("chrome.exe", "10.*.*.*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m4("chrome.exe", "140.82.112.3", 1) == RULE_ACTION_DIRECT);
    CHECK(ProxyBridge_EditRule(h, "chrome.exe", "10.*.*.*", "*", "github.com", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE));
    CHECK(m4("chrome.exe", "140.82.112.3", 1) == RULE_ACTION_PROXY && m4("chrome.exe", "10.1.1.1", 1) == RULE_ACTION_PROXY);
    ProxyBridge_DeleteRule(h);

    /* 8. per-rule "also proxy localhost": match_rule reports the matched rule's flag */
    UINT32 l1 = ProxyBridge_AddRule("browser.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, TRUE);
    UINT32 l2 = ProxyBridge_AddRule("curl.exe",    "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    CHECK(m4("browser.exe", "127.0.0.1", 8080) == RULE_ACTION_PROXY && g_tl_rule_localhost == TRUE);
    CHECK(m4("curl.exe",    "127.0.0.1", 8080) == RULE_ACTION_PROXY && g_tl_rule_localhost == FALSE);
    CHECK(ProxyBridge_EditRule(l2, "curl.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, TRUE));
    CHECK(m4("curl.exe", "127.0.0.1", 8080) == RULE_ACTION_PROXY && g_tl_rule_localhost == TRUE);
    CHECK(m4("other.exe", "127.0.0.1", 8080) == RULE_ACTION_DIRECT && g_tl_rule_localhost == FALSE);   /* no rule: no flag */
    ProxyBridge_DeleteRule(l1); ProxyBridge_DeleteRule(l2);

    /* 9. main switch: paused = no rule applies to new connections; enabling restores them */
    UINT32 p1 = ProxyBridge_AddRule("chrome.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
    UINT32 p2 = ProxyBridge_AddRule("curl.exe",   "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    CHECK(g_proxy_enabled == TRUE);                                            /* on by default */
    CHECK(m4("chrome.exe", "8.8.8.8", 443) == RULE_ACTION_PROXY && m4("curl.exe", "8.8.8.8", 443) == RULE_ACTION_BLOCK);
    ProxyBridge_SetEnabled(FALSE);
    CHECK(m4("chrome.exe", "8.8.8.8", 443) == RULE_ACTION_DIRECT);             /* proxy rule paused */
    CHECK(m4("curl.exe",   "8.8.8.8", 443) == RULE_ACTION_DIRECT);             /* block rule paused too */
    { UINT8 a6[16] = {0x20, 0x01, 0x0d, 0xb8}; UINT32 idv = 77; CHECK(match_rule_v6("chrome.exe", a6, 443, FALSE, &idv) == RULE_ACTION_DIRECT && idv == 0); }
    ProxyBridge_SetEnabled(FALSE);                                              /* idempotent */
    CHECK(m4("chrome.exe", "8.8.8.8", 443) == RULE_ACTION_DIRECT);
    ProxyBridge_SetEnabled(TRUE);
    CHECK(m4("chrome.exe", "8.8.8.8", 443) == RULE_ACTION_PROXY && m4("curl.exe", "8.8.8.8", 443) == RULE_ACTION_BLOCK);
    ProxyBridge_DeleteRule(p1); ProxyBridge_DeleteRule(p2);

    /* 10. rule list housekeeping: disabled rules are skipped; deleted rules are gone */
    UINT32 x = ProxyBridge_AddRule("zzz.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    CHECK(m4("zzz.exe", "8.8.8.8", 1) == RULE_ACTION_BLOCK);
    ProxyBridge_DisableRule(x); CHECK(m4("zzz.exe", "8.8.8.8", 1) == RULE_ACTION_DIRECT);
    ProxyBridge_EnableRule(x);  CHECK(m4("zzz.exe", "8.8.8.8", 1) == RULE_ACTION_BLOCK);
    ProxyBridge_DeleteRule(x);  CHECK(m4("zzz.exe", "8.8.8.8", 1) == RULE_ACTION_DIRECT);

    /* the GUI offers 32 proxy servers, so the engine must accept 32 (and refuse a 33rd, not overflow) */
    { UINT32 ids[40]; int got = 0;
      for (int i = 0; i < 40; i++) { ids[i] = ProxyBridge_AddProxyConfig(PROXY_TYPE_SOCKS5, "127.0.0.1", (UINT16)(2000 + i), NULL, NULL, TRUE); if (ids[i]) got++; }
      CHECK(MAX_PROXY_CONFIGS == 32 && got == 32 && ids[31] != 0 && ids[32] == 0);
      for (int i = 0; i < 40; i++) if (ids[i]) ProxyBridge_DeleteProxyConfig(ids[i]);
      CHECK(ProxyBridge_AddProxyConfig(PROXY_TYPE_HTTP, "127.0.0.1", 3000, NULL, NULL, FALSE) != 0);   /* room again after deleting */
    }

    return pbtest_done("test_engine");
}
