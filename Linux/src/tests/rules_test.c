#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../pb_rules.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void a4(uint8_t o[16], const char *s) { memset(o, 0, 16); o[10] = o[11] = 0xff; inet_pton(AF_INET, s, o + 12); }
static void a6(uint8_t o[16], const char *s) { inet_pton(AF_INET6, s, o); }

static struct pb_rule R(const char *p, const char *h, const char *pt)
{
    struct pb_rule r; char err[128];
    bool ok = pb_rule_parse(&r, p, h, pt, err, sizeof err);
    if (!ok) printf("parse error: %s\n", err);
    CHECK(ok);
    return r;
}
static bool bad(const char *p, const char *h, const char *pt)
{
    struct pb_rule r; char err[128];
    bool ok = pb_rule_parse(&r, p, h, pt, err, sizeof err);
    if (ok) pb_rule_free(&r); else printf("  (rejected as expected: %s)\n", err);
    return !ok;
}

int main(void)
{
    uint8_t a[16];
    struct pb_rule r;

    r = R("firefox;chrome*", "", ""); CHECK(!r.any_proc && r.nprocs == 2);
    CHECK(pb_rule_match_process(&r, "/usr/lib/firefox/firefox")); CHECK(pb_rule_match_process(&r, "/opt/google/chrome/chrome"));
    CHECK(pb_rule_match_process(&r, "/opt/chromium/chromedriver")); CHECK(!pb_rule_match_process(&r, "/usr/bin/curl")); pb_rule_free(&r);
    r = R("*chrome*", "", ""); CHECK(pb_rule_match_process(&r, "/opt/google/chrome/chrome")); CHECK(pb_rule_match_process(&r, "/usr/bin/mychromex")); pb_rule_free(&r);
    r = R("/usr/bin/*", "", ""); CHECK(pb_rule_match_process(&r, "/usr/bin/curl")); CHECK(!pb_rule_match_process(&r, "/opt/x/curl")); pb_rule_free(&r);
    r = R("", "", ""); CHECK(r.any_proc && r.any_host && r.any_port); pb_rule_free(&r);
    r = R("*", "*", "*"); CHECK(r.any_proc && r.any_host && r.any_port); pb_rule_free(&r);

    r = R("", "192.168.*.*;10.0.0.0/8", "80;443;8000-9000");
    a4(a, "192.168.4.5"); CHECK(pb_rule_match_dest(&r, AF_INET, a, 443, NULL, 0));
    a4(a, "10.200.1.1");  CHECK(pb_rule_match_dest(&r, AF_INET, a, 8500, NULL, 0));
    a4(a, "10.200.1.1");  CHECK(!pb_rule_match_dest(&r, AF_INET, a, 22, NULL, 0));
    a4(a, "172.16.0.1");  CHECK(!pb_rule_match_dest(&r, AF_INET, a, 80, NULL, 0));
    CHECK(r.hosts[0].kind == PB_HOST_V4_RANGE);   // 192.168.*.* collapses to a range
    pb_rule_free(&r);

    r = R("", "10.1-5.*.7", ""); CHECK(r.hosts[0].kind == PB_HOST_V4_BOX);
    a4(a, "10.3.99.7"); CHECK(pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0)); a4(a, "10.6.99.7"); CHECK(!pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0));
    a4(a, "10.3.99.8"); CHECK(!pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0)); pb_rule_free(&r);

    r = R("", "1.2.3.4-1.2.3.9", ""); a4(a, "1.2.3.9"); CHECK(pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0)); a4(a, "1.2.3.10"); CHECK(!pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0)); pb_rule_free(&r);
    r = R("", "2001:db8::/32;fd00::1", ""); a6(a, "2001:db8:ffff::1"); CHECK(pb_rule_match_dest(&r, AF_INET6, a, 1, NULL, 0));
    a6(a, "2001:db9::1"); CHECK(!pb_rule_match_dest(&r, AF_INET6, a, 1, NULL, 0)); a6(a, "fd00::1"); CHECK(pb_rule_match_dest(&r, AF_INET6, a, 1, NULL, 0));
    a4(a, "1.1.1.1"); CHECK(!pb_rule_match_dest(&r, AF_INET, a, 1, NULL, 0)); pb_rule_free(&r);

    CHECK(bad("", "999.1.1.1", "")); CHECK(bad("", "1.2.3", "")); CHECK(bad("", "1.2.3.4.5", "")); CHECK(bad("", "10.0.0.0/33", ""));
    CHECK(bad("", "exa$mple.com", "")); CHECK(bad("", ".example.com", "")); CHECK(bad("", "a..b.com", "")); CHECK(bad("", "5.5.5.5-1.1.1.1", "")); CHECK(bad("", "", "abc"));
    CHECK(bad("", "", "0")); CHECK(bad("", "", "70000")); CHECK(bad("", "", "90-80")); CHECK(bad("", "::g", "")); CHECK(bad("", "1::/129", ""));

    struct pb_rule rules[3]; memset(rules, 0, sizeof rules);
    rules[0] = R("curl", "", "443"); rules[0].enabled = true;  rules[0].action = RULE_ACTION_BLOCK;
    rules[1] = R("curl", "", ""); rules[1].enabled = true; rules[1].action = RULE_ACTION_PROXY;
    rules[2] = R("", "", ""); rules[2].enabled = true; rules[2].action = RULE_ACTION_DIRECT; rules[2].protocol = RULE_PROTOCOL_UDP;
    a4(a, "9.9.9.9");
    CHECK(pb_rules_eval(rules, 3, "/usr/bin/curl", AF_INET, a, 443, IPPROTO_TCP, NULL, 0) == 0);
    CHECK(pb_rules_eval(rules, 3, "/usr/bin/curl", AF_INET, a, 80, IPPROTO_TCP, NULL, 0) == 1);
    CHECK(pb_rules_eval(rules, 3, "/usr/bin/wget", AF_INET, a, 80, IPPROTO_TCP, NULL, 0) == -1);
    CHECK(pb_rules_eval(rules, 3, "/usr/bin/wget", AF_INET, a, 80, IPPROTO_UDP, NULL, 0) == 2);
    rules[0].enabled = false; CHECK(pb_rules_eval(rules, 3, "/usr/bin/curl", AF_INET, a, 443, IPPROTO_TCP, NULL, 0) == 1);
    for (int i = 0; i < 3; i++) pb_rule_free(&rules[i]);

    CHECK(pb_implicit_direct(AF_INET, (a4(a, "127.0.0.53"), a), 53, IPPROTO_UDP, true));
    CHECK(pb_implicit_direct(AF_INET, (a4(a, "224.0.0.251"), a), 5353, IPPROTO_UDP, true));
    CHECK(!pb_implicit_direct(AF_INET, (a4(a, "8.8.8.8"), a), 53, IPPROTO_UDP, true));
    CHECK(pb_implicit_direct(AF_INET, (a4(a, "8.8.8.8"), a), 53, IPPROTO_UDP, false));
    CHECK(pb_implicit_direct(AF_INET6, (a6(a, "::1"), a), 80, IPPROTO_TCP, true));
    CHECK(!pb_implicit_direct(AF_INET6, (a6(a, "2001:db8::1"), a), 80, IPPROTO_TCP, true));
    // ---- domain rules
    r = R("", "*.github.com;example.org;10.0.0.0/8", "443");
    CHECK(r.ndomains == 2 && r.nhosts == 1 && !r.any_host);
    const char *gh[] = { "api.github.com" }, *ex[] = { "EXAMPLE.org." }, *no[] = { "github.com", "notgithub.com", "example.org.evil.com" };
    a4(a, "140.82.1.1");
    CHECK(pb_rule_match_dest(&r, AF_INET, a, 443, gh, 1));
    CHECK(pb_rule_match_dest(&r, AF_INET, a, 443, ex, 1));            // case-insensitive, trailing root dot tolerated
    CHECK(!pb_rule_match_dest(&r, AF_INET, a, 443, no, 3));           // "*.github.com" does not match the bare apex; exact stays exact
    CHECK(!pb_rule_match_dest(&r, AF_INET, a, 80, gh, 1));            // port still has to match
    a4(a, "10.1.2.3"); CHECK(pb_rule_match_dest(&r, AF_INET, a, 443, NULL, 0));   // IP pattern in the same list still works
    pb_rule_free(&r);
    r = R("", "github.com;*.github.com", ""); CHECK(r.ndomains == 2); pb_rule_free(&r);
    CHECK(pb_domain_match("a?c.com", "abc.com")); CHECK(!pb_domain_match("a?c.com", "abbc.com")); CHECK(pb_domain_match("*", "x.y"));
    CHECK(bad("", "bad name.com", ""));

    {   // long Target Host lists: hundreds of domains, up to PB_HOSTS_MAX - 1 characters, and the limits themselves
        static char big[PB_HOSTS_MAX + 64];
        size_t o = 0; int n = 0;
        while (o + 24 < 7000) { o += (size_t)snprintf(big + o, sizeof big - o, "host%d.example.org;", n++); }
        r = R("", big, ""); CHECK(r.ndomains == n); CHECK(r.hosts_src[0] == 'h');
        CHECK(pb_rule_match_dest(&r, AF_INET, (a4(a, "1.2.3.4"), a), 443, (const char *[]){ "host77.example.org" }, 1));
        CHECK(!pb_rule_match_dest(&r, AF_INET, (a4(a, "1.2.3.4"), a), 443, (const char *[]){ "other.example.org" }, 1));
        pb_rule_free(&r);

        struct pb_rule t; char e[128];
        memset(big, 'a', PB_HOSTS_MAX); big[PB_HOSTS_MAX] = 0;                  // 8192 characters: rejected by the length limit
        CHECK(!pb_rule_parse(&t, "", big, "", e, sizeof e)); CHECK(strstr(e, "too long") != NULL);

        for (int k = 0; k < 2; k++) {                                            // exactly PB_MAX_HOST_PATTERNS entries parse, one more is rejected
            o = 0;
            for (int i = 0; i < PB_MAX_HOST_PATTERNS + k; i++) o += (size_t)snprintf(big + o, sizeof big - o, "x.y;");
            if (k == 0) { CHECK(pb_rule_parse(&t, "", big, "", e, sizeof e)); pb_rule_free(&t); }
            else        { CHECK(!pb_rule_parse(&t, "", big, "", e, sizeof e)); CHECK(strstr(e, "too many") != NULL); }
        }
        CHECK(bad("a1;a2;a3;a4;a5;a6;a7;a8;a9;a10;a11;a12;a13;a14;a15;a16;a17;a18;a19;a20;a21;a22;a23;a24;a25;a26;a27;a28;a29;a30;a31;a32;a33;a34;a35;a36;a37;a38;a39;a40;a41;a42;a43;a44;a45;a46;a47;a48;a49;a50;a51;a52;a53;a54;a55;a56;a57;a58;a59;a60;a61;a62;a63;a64;a65", "", ""));   // process list limit unchanged
    }
    printf(fails ? "RULES TESTS FAILED (%d)\n" : "rules tests passed\n", fails);
    return fails != 0;
}
