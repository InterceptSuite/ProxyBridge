// test_rules_match.c - the individual matchers of the rule engine (src\pb_rules.c) and the rule list API:
//   IPv4 / IPv6 patterns, port lists, process patterns (names, paths, wildcards), domain patterns and lists,
//   rule ordering (first match wins, fully wildcard process rules last), Add/Edit/Delete/Move validation.
#include "pb_internal.h"
#include "pbtest.h"

static UINT32 ip4(const char* s) { struct in_addr a; inet_pton(AF_INET, s, &a); return a.S_un.S_addr; }
static BOOL v6(const char* pat, const char* addr) { UINT8 a[16]; inet_pton(AF_INET6, addr, a); return match_ip_pattern_v6(pat, a); }
static RuleAction m4(const char* proc, const char* ip, int port) { UINT32 id = 0; return match_rule(proc, ip4(ip), (UINT16)port, FALSE, &id); }

int main(void)
{
    /* ================= IPv4 patterns ================= */
    CHECK(match_ip_pattern("192.168.1.1", ip4("192.168.1.1")) && !match_ip_pattern("192.168.1.1", ip4("192.168.1.2")));
    CHECK(match_ip_pattern("192.168.*.*", ip4("192.168.77.8")) && !match_ip_pattern("192.168.*.*", ip4("192.169.1.1")));
    CHECK(match_ip_pattern("*.*.*.*", ip4("8.8.4.4")) && match_ip_pattern("*", ip4("8.8.4.4")) && match_ip_pattern(NULL, ip4("8.8.4.4")));
    CHECK(match_ip_pattern("10.*.*.7", ip4("10.1.2.7")) && !match_ip_pattern("10.*.*.7", ip4("10.1.2.8")));
    CHECK(!match_ip_pattern("10.0.0.5-10.0.0.9", ip4("10.0.0.4")) && match_ip_pattern("10.0.0.5-10.0.0.9", ip4("10.0.0.5")) &&
          match_ip_pattern("10.0.0.5-10.0.0.9", ip4("10.0.0.9")) && !match_ip_pattern("10.0.0.5-10.0.0.9", ip4("10.0.0.10")));      /* inclusive */
    CHECK(match_ip_pattern("10.1.0.0-10.5.255.255", ip4("10.3.9.9")) && !match_ip_pattern("10.1.0.0-10.5.255.255", ip4("10.6.0.0")));   /* crosses octets */
    CHECK(!match_ip_pattern("10.0.0.9-10.0.0.5", ip4("10.0.0.7")));                                                                    /* reversed range */
    CHECK(!match_ip_pattern("10.0.0", ip4("10.0.0.1")) && !match_ip_pattern("", ip4("10.0.0.1")) && !match_ip_pattern("abc", ip4("1.1.1.1")));
    { char longp[400]; memset(longp, '1', 399); longp[399] = 0; CHECK(!match_ip_pattern(longp, ip4("1.1.1.1"))); }                      /* oversize: no crash */
    CHECK(match_ip_list("192.168.1.1;10.0.0.1", ip4("10.0.0.1")) && !match_ip_list("192.168.1.1;10.0.0.1", ip4("11.0.0.1")));
    CHECK(match_ip_list("192.168.1.1; 10.0.0.1", ip4("10.0.0.1")));                                                                   /* a blank after ';' is fine */
    CHECK(match_ip_list("", ip4("1.1.1.1")) && match_ip_list("*", ip4("1.1.1.1")));
    CHECK(!match_ip_list(";", ip4("1.1.1.1")));                                                                                       /* only separators: matches nothing (the GUI turns this into "*") */

    /* IPv4 CIDR */
    CHECK(match_ip_pattern("10.0.0.0/8", ip4("10.1.2.3")) && match_ip_pattern("10.0.0.0/8", ip4("10.255.255.255")) && match_ip_pattern("10.0.0.0/8", ip4("10.0.0.0")));
    CHECK(!match_ip_pattern("10.0.0.0/8", ip4("11.0.0.1")) && !match_ip_pattern("10.0.0.0/8", ip4("9.255.255.255")));
    CHECK(match_ip_pattern("192.168.1.128/25", ip4("192.168.1.200")) && match_ip_pattern("192.168.1.128/25", ip4("192.168.1.255")) &&
          !match_ip_pattern("192.168.1.128/25", ip4("192.168.1.127")) && !match_ip_pattern("192.168.1.128/25", ip4("192.168.2.200")));    /* not on an octet boundary */
    CHECK(match_ip_pattern("172.16.0.0/12", ip4("172.31.255.255")) && !match_ip_pattern("172.16.0.0/12", ip4("172.32.0.0")));
    CHECK(match_ip_pattern("1.2.3.4/32", ip4("1.2.3.4")) && !match_ip_pattern("1.2.3.4/32", ip4("1.2.3.5")));                       /* /32 = one address */
    CHECK(match_ip_pattern("0.0.0.0/0", ip4("8.8.8.8")) && match_ip_pattern("0.0.0.0/0", ip4("255.255.255.255")));                    /* /0 = everything */
    CHECK(match_ip_pattern("10.1.2.3/8", ip4("10.99.0.1")));                                                                         /* host bits in the address are ignored */
    CHECK(!match_ip_pattern("10.0.0.0/33", ip4("10.0.0.1")) && !match_ip_pattern("10.0.0.0/-1", ip4("10.0.0.1")) && !match_ip_pattern("10.0.0.0/", ip4("10.0.0.1")) &&
          !match_ip_pattern("10.0.0.0/8x", ip4("10.0.0.1")) && !match_ip_pattern("10.0.0/8", ip4("10.0.0.1")) && !match_ip_pattern("300.0.0.0/8", ip4("10.0.0.1")) &&
          !match_ip_pattern("10.*.*.*/8", ip4("10.0.0.1")) && !match_ip_pattern("/8", ip4("10.0.0.1")));                             /* malformed: matches nothing */
    CHECK(match_ip_list("10.0.0.0/8;192.168.0.0/16;172.16.0.0-172.31.255.255", ip4("192.168.44.1")) &&
          match_ip_list("10.0.0.0/8;192.168.0.0/16;172.16.0.0-172.31.255.255", ip4("172.20.0.1")) &&
          !match_ip_list("10.0.0.0/8;192.168.0.0/16;172.16.0.0-172.31.255.255", ip4("8.8.8.8")));                                    /* CIDR, range and list together */
    { UINT32 c = ProxyBridge_AddRule("cidr.exe", "10.0.0.0/8", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
      CHECK(c != 0 && m4("cidr.exe", "10.200.1.1", 443) == RULE_ACTION_BLOCK && m4("cidr.exe", "11.0.0.1", 443) == RULE_ACTION_DIRECT);   /* through a real rule */
      ProxyBridge_DeleteRule(c); }

    /* ================= IPv6 patterns ================= */
    CHECK(v6("::1", "::1") && !v6("::1", "::2") && v6("*", "2001:db8::5"));
    CHECK(v6("2001:db8::/32", "2001:db8:ffff::1") && !v6("2001:db8::/32", "2001:db9::1"));
    CHECK(v6("fe80::/10", "fe80::1") && v6("fe80::/10", "febf::1") && !v6("fe80::/10", "fec0::1"));
    CHECK(v6("::/0", "2a00::1") && v6("::1/128", "::1") && !v6("::1/128", "::2") && !v6("::/129", "::1"));
    CHECK(v6("2001:db8::1-2001:db8::ff", "2001:db8::80") && !v6("2001:db8::1-2001:db8::ff", "2001:db8::100"));
    CHECK(!v6("10.0.0.0", "::1") && !v6("garbage:::", "::1"));                                                                       /* IPv4 patterns never match IPv6 */
    { char longp[300]; memset(longp, 'a', 299); longp[299] = 0; longp[3] = ':'; CHECK(!v6(longp, "::1")); }                           /* oversize: no crash */

    /* ================= ports ================= */
    CHECK(match_port_pattern("80", 80) && !match_port_pattern("80", 81) && match_port_pattern("*", 5));
    CHECK(match_port_pattern("8000-9000", 8000) && match_port_pattern("8000-9000", 9000) && match_port_pattern("8000-9000", 8500) &&
          !match_port_pattern("8000-9000", 7999) && !match_port_pattern("8000-9000", 9001));
    CHECK(match_port_list("80;443;8000-9000", 443) && match_port_list("80,443", 443) && match_port_list("80; 443", 443) && !match_port_list("80;443", 8080));
    CHECK(match_port_list("", 1) && match_port_list("*", 65535));

    /* ================= process patterns ================= */
    CHECK(wildcard_match("*steam*", "mysteamclient.exe") && wildcard_match("fire*.exe", "FireFox.EXE") && wildcard_match("*.bin", "a.bin"));
    CHECK(!wildcard_match("fire*.exe", "chrome.exe") && wildcard_match("**", "x") && wildcard_match("*", "") && !wildcard_match("a", "") && wildcard_match("a*b*c", "aXXbYYc"));
    CHECK(match_process_pattern("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"));                         /* name matches the file name of a path */
    CHECK(match_process_pattern("CHROME.EXE", "chrome.exe") && !match_process_pattern("chrome.exe", "chromedriver.exe"));
    CHECK(match_process_pattern("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "c:\\program files\\google\\chrome\\application\\chrome.exe"));
    CHECK(!match_process_pattern("C:\\Other\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"));              /* a path pattern must match the whole path */
    CHECK(match_process_pattern("C:\\Program Files\\*\\chrome.exe", "C:\\Program Files\\Google\\chrome.exe"));
    CHECK(match_process_pattern("*", "anything.exe") && match_process_pattern(NULL, "anything.exe"));
    CHECK(match_process_list("firefox.exe;chrome.exe", "chrome.exe") && match_process_list("firefox.exe, chrome.exe", "chrome.exe") && !match_process_list("firefox.exe;edge.exe", "chrome.exe"));
    CHECK(match_process_list("\"C:\\Program Files\\App\\my app.exe\"", "C:\\Program Files\\App\\my app.exe"));                         /* quoted path with a space */
    CHECK(match_process_list("  chrome.exe  ", "chrome.exe") && match_process_list("", "x.exe") && match_process_list("*", "x.exe") && match_process_list(NULL, "x.exe"));
    { char many[8192]; size_t o = 0; for (int i = 0; i < 700; i++) o += sprintf_s(many + o, sizeof many - o, "app%d.exe;", i); strcat_s(many, sizeof many, "target.exe");
      CHECK(match_process_list(many, "target.exe") && match_process_list(many, "app5.exe") && !match_process_list(many, "nope.exe")); }   /* list longer than the stack buffer */

    /* ================= domain patterns ================= */
    CHECK(match_domain_pattern("github.com", "GitHub.com") && !match_domain_pattern("github.com", "api.github.com"));
    CHECK(match_domain_pattern("*.github.com", "api.github.com") && match_domain_pattern("*.github.com", "github.com"));              /* the apex matches too */
    CHECK(!match_domain_pattern("*.github.com", "evilgithub.com") && !match_domain_pattern("*.github.com", "github.com.evil.org"));
    CHECK(match_domain_pattern("*google*", "www.google.co.uk") && match_domain_pattern("*", "x") && match_domain_pattern("", "x"));
    CHECK(!match_domain_pattern("github.com", "") && !match_domain_pattern("github.com", NULL));                                      /* unknown name: only "*" matches */
    CHECK(match_domain_list("a.com;*.b.org;c.net", "x.b.org") && match_domain_list("a.com, c.net", "c.net") && !match_domain_list("a.com;c.net", "d.net"));
    CHECK(match_domain_list("", NULL) && match_domain_list("*", NULL) && !match_domain_list("a.com", NULL));
    { static char many[16384]; size_t o = 0; for (int i = 0; i < 600; i++) o += sprintf_s(many + o, sizeof many - o, "host%d.example.org;", i); strcat_s(many, sizeof many, "*.last.example");
      CHECK(match_domain_list(many, "x.last.example") && match_domain_list(many, "host42.example.org") && !match_domain_list(many, "host9999.example.org")); }

    /* ================= rule list API ================= */
    CHECK(ProxyBridge_AddRule(NULL, "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE) == 0);                            /* a rule needs a process */
    CHECK(ProxyBridge_AddRule("", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE) == 0);
    CHECK(!ProxyBridge_EditRule(0, "a.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE));
    CHECK(!ProxyBridge_EditRule(99999, "a.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE));
    CHECK(!ProxyBridge_EditRule(1, NULL, "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE));
    CHECK(!ProxyBridge_DeleteRule(99999) && !ProxyBridge_EnableRule(99999) && !ProxyBridge_DisableRule(99999));
    CHECK(ProxyBridge_GetRulePosition(99999) == 0);

    /* a rule with NULL/empty target lists is a wildcard rule (stored as "*") */
    { UINT32 w = ProxyBridge_AddRule("wild.exe", NULL, NULL, NULL, RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
      CHECK(w != 0 && m4("wild.exe", "8.8.8.8", 443) == RULE_ACTION_BLOCK); ProxyBridge_DeleteRule(w); }

    /* protocol filter: a TCP-only rule ignores UDP flows and vice versa */
    { UINT32 t = ProxyBridge_AddRule("p.exe", "*", "*", "*", RULE_PROTOCOL_TCP, RULE_ACTION_BLOCK, 0, FALSE);
      UINT32 id = 0;
      CHECK(match_rule("p.exe", ip4("1.1.1.1"), 53, FALSE, &id) == RULE_ACTION_BLOCK && match_rule("p.exe", ip4("1.1.1.1"), 53, TRUE, &id) == RULE_ACTION_DIRECT);
      ProxyBridge_DeleteRule(t); }

    /* ordering: first matching rule in the list wins; a fully wildcard "*" process rule is only used last */
    { UINT32 a = ProxyBridge_AddRule("chrome.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0, FALSE);
      UINT32 b = ProxyBridge_AddRule("chrome.exe", "10.*.*.*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE);
      CHECK(ProxyBridge_GetRulePosition(a) == 1 && ProxyBridge_GetRulePosition(b) == 2);
      CHECK(m4("chrome.exe", "10.1.1.1", 80) == RULE_ACTION_PROXY);                                  /* A first: it covers everything */
      CHECK(ProxyBridge_MoveRuleToPosition(b, 1) == TRUE);
      CHECK(ProxyBridge_GetRulePosition(b) == 1 && ProxyBridge_GetRulePosition(a) == 2);
      CHECK(m4("chrome.exe", "10.1.1.1", 80) == RULE_ACTION_DIRECT && m4("chrome.exe", "8.8.8.8", 80) == RULE_ACTION_PROXY);
      UINT32 wcard = ProxyBridge_AddRule("*", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);   /* added last, matches every program */
      CHECK(m4("chrome.exe", "8.8.8.8", 80) == RULE_ACTION_PROXY);                                  /* specific rules still win */
      CHECK(m4("other.exe", "8.8.8.8", 80) == RULE_ACTION_BLOCK);                                   /* everything else falls to it */
      ProxyBridge_MoveRuleToPosition(wcard, 1);
      CHECK(m4("chrome.exe", "8.8.8.8", 80) == RULE_ACTION_PROXY);                                  /* ... even when it is listed first */
      ProxyBridge_MoveRuleToPosition(a, 99);                                                         /* an out-of-range position must not corrupt the list */
      UINT32 pa = ProxyBridge_GetRulePosition(a), pb = ProxyBridge_GetRulePosition(b), pw = ProxyBridge_GetRulePosition(wcard);
      CHECK(pa >= 1 && pa <= 3 && pb >= 1 && pb <= 3 && pw >= 1 && pw <= 3 && pa != pb && pb != pw && pa != pw);
      ProxyBridge_DeleteRule(a); ProxyBridge_DeleteRule(b); ProxyBridge_DeleteRule(wcard);
      CHECK(m4("chrome.exe", "8.8.8.8", 80) == RULE_ACTION_DIRECT); }

    /* very long target lists are accepted and stored without truncation */
    { char hosts[20000]; size_t o = 0; for (int i = 0; i < 1500; i++) o += sprintf_s(hosts + o, sizeof hosts - o, "10.%d.%d.1;", i / 250, i % 250);
      UINT32 big = ProxyBridge_AddRule("longlist.exe", hosts, "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
      CHECK(big != 0 && m4("longlist.exe", "10.5.249.1", 1) == RULE_ACTION_BLOCK && m4("longlist.exe", "10.5.249.2", 1) == RULE_ACTION_DIRECT);
      ProxyBridge_DeleteRule(big); }

    /* a long Applications list (many programs, ~7000 characters) is kept whole and still matches its last entry */
    { char procs[8192]; size_t o = 0; for (int i = 0; i < 600; i++) o += sprintf_s(procs + o, sizeof procs - o, "prog%03d.exe;", i);
      sprintf_s(procs + o, sizeof procs - o, "lastone.exe");
      UINT32 id = ProxyBridge_AddRule(procs, "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
      CHECK(id != 0 && m4("lastone.exe", "8.8.8.8", 80) == RULE_ACTION_BLOCK && m4("prog300.exe", "8.8.8.8", 80) == RULE_ACTION_BLOCK && m4("lastone2.exe", "8.8.8.8", 80) == RULE_ACTION_DIRECT);
      ProxyBridge_DeleteRule(id); }

    /* a list that cannot fit is refused, never cut in the middle of a program name */
    { static char huge[MAX_RULE_PROCESS_LIST + 16]; memset(huge, 'a', sizeof huge - 1); huge[sizeof huge - 1] = 0;
      CHECK(ProxyBridge_AddRule(huge, "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE) == 0);
      UINT32 ok = ProxyBridge_AddRule("ok.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
      CHECK(ok != 0 && !ProxyBridge_EditRule(ok, huge, "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE) && m4("ok.exe", "8.8.8.8", 80) == RULE_ACTION_BLOCK);
      ProxyBridge_DeleteRule(ok); }

    return pbtest_done("test_rules_match");
}
