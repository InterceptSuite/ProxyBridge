// test_cli.c - the helpers of the command-line client (cli\main.c): it applies the same host-list cleanup and
// IP/domain sorting as the GUI to profile files, so a profile written by hand or by another platform still works.
// cli\main.c is included as source so its static functions can be called directly.
#define main pb_cli_main
#include "../cli/main.c"
#undef main
#include "pbtest.h"

static void norm(const char* in, const char* want)
{
    char buf[256]; strcpy_s(buf, sizeof buf, in); normalize_list(buf);
    if (strcmp(buf, want)) { g_fails++; printf("  FAIL normalize [%s] -> [%s], wanted [%s]\n", in, buf, want); }
    g_checks++;
}

static void sort(const char* hosts0, const char* doms0, const char* wantHosts, const char* wantDoms)
{
    char h[512], d[8192]; strcpy_s(h, sizeof h, hosts0); strcpy_s(d, sizeof d, doms0);
    sort_hosts(h, sizeof h, d, sizeof d);
    if (strcmp(h, wantHosts) || strcmp(d, wantDoms))
    { g_fails++; printf("  FAIL sort [%s]+[%s] -> [%s] [%s], wanted [%s] [%s]\n", hosts0, doms0, h, d, wantHosts, wantDoms); }
    g_checks++;
}

int main(void)
{
    norm("google.com;\r\n *.google.com ;\n,github.com;", "google.com;*.google.com;github.com");
    norm("", ""); norm(";;", ""); norm("a\nb", "ab"); norm("*", "*");

    CHECK(is_ip_token("10.0.0.0/8", 10) && is_ip_token("192.168.*.*", 11) && is_ip_token("1.2.3.4-1.2.3.9", 15));
    CHECK(is_ip_token("::1", 3) && is_ip_token("fe80::1-fe80::ff", 16) && is_ip_token("2001:db8::/32", 13));
    CHECK(!is_ip_token("github.com", 10) && !is_ip_token("*.github.com", 12) && !is_ip_token("abc.def", 7) && !is_ip_token("123.com", 7));

    sort("10.*.*.*", "github.com;*.google.com", "10.*.*.*", "github.com;*.google.com");
    sort("example.org;192.168.*.*", "*", "192.168.*.*", "example.org");              /* a domain typed with the IPs moves to the domains */
    sort("*", "*", "*", "*");  sort("", "", "*", "*");
    sort("10.0.0.1", "*", "10.0.0.1", "*");                                          /* "*" alone on a side means no restriction from it */
    sort("*", "github.com", "*", "github.com");
    sort("a.com;*", "b.com", "*", "*");                                              /* "*" next to other entries = any host */
    sort("1.2.3.4-1.2.3.9;fe80::1-fe80::ff;::1", "x.org", "1.2.3.4-1.2.3.9;fe80::1-fe80::ff;::1", "x.org");
    {   /* addresses hiding in a huge domain list must not overflow the 512-byte hosts buffer */
        char h[512] = "*", d[8192]; size_t k = 0;
        for (int i = 0; i < 600; i++) k += sprintf_s(d + k, sizeof d - k, "10.%d.%d.1;", i % 250, i / 250);
        strcpy_s(d + k, sizeof d - k, "x.org");
        sort_hosts(h, sizeof h, d, sizeof d);
        CHECK(strlen(h) < sizeof h && h[0] != 0 && h[strlen(h) - 1] != ';');
    }

    return pbtest_done("test_cli");
}
