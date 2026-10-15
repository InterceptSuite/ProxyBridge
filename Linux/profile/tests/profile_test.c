// Unit tests for the .pbprofile reader/writer (build with sanitizers via run_tests.sh).
#define _GNU_SOURCE
#include "../pb_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

// The sample from the Windows README, plus the optional fields the Windows GUI writes.
static const char *WINDOWS_SAMPLE =
    "{ \"Version\": \"1.0\", \"LocalhostViaProxy\": false, \"IsTrafficLoggingEnabled\": true,\n"
    "  \"ProxyConfigs\": [\n"
    "    { \"Id\": 1, \"Type\": \"socks5\", \"Host\": \"127.0.0.1\", \"Port\": \"1080\", \"Username\": \"\", \"Password\": \"\" },\n"
    "    { \"Id\": 2, \"Name\": \"corp\", \"Type\": \"http\", \"Host\": \"10.0.0.2\", \"Port\": \"8080\", \"Username\": \"bob\", \"Password\": \"p\\\"w\", \"SendDomainToProxy\": true }\n"
    "  ],\n"
    "  \"ProxyRules\": [\n"
    "    { \"ProcessName\": \"chrome.exe\", \"TargetHosts\": \"*\", \"TargetPorts\": \"*\", \"Protocol\": \"TCP\", \"Action\": \"PROXY\", \"IsEnabled\": true, \"ProxyConfigId\": 1 },\n"
    "    { \"ProcessName\": \"firefox.exe\", \"TargetHosts\": \"192.168.*.*\", \"TargetPorts\": \"80;443\", \"TargetDomains\": \"*.github.com\","
    "      \"Protocol\": \"BOTH\", \"Action\": \"PROXY\", \"IsEnabled\": false, \"ProxyConfigId\": 2 },\n"
    "    { \"ProcessName\": \"x\", \"Protocol\": \"UDP\", \"Action\": \"BLOCK\" }\n"
    "  ],\n"
    "  \"LogFilters\": [ { \"Mode\": \"Hide\", \"ProcessName\": \"x\" } ] }\n";

static int parse(const char *s, struct pbp_profile *p, char *err)
{
    return pbp_parse(s, strlen(s), p, err, 256);
}

static void test_windows_sample(void)
{
    struct pbp_profile p;
    char err[256];
    CHECK(parse(WINDOWS_SAMPLE, &p, err) == 0);
    CHECK(p.nproxies == 2 && p.nrules == 3 && p.logging);
    CHECK(p.proxies[0].type == 1 && !strcmp(p.proxies[0].host, "127.0.0.1") && p.proxies[0].port == 1080);
    CHECK(!strcmp(p.proxies[0].name, "proxy1"));
    CHECK(p.proxies[1].type == 0 && !strcmp(p.proxies[1].name, "corp") && !strcmp(p.proxies[1].pass, "p\"w"));
    CHECK(!strcmp(p.rules[0].process, "chrome.exe") && p.rules[0].proxy_id == 1 && p.rules[0].enabled);
    CHECK(!strcmp(p.rules[1].hosts, "192.168.*.*;*.github.com"));      // domains join the host list
    CHECK(!strcmp(p.rules[1].ports, "80;443") && p.rules[1].protocol == 2 && !p.rules[1].enabled);
    CHECK(p.rules[2].protocol == 1 && p.rules[2].action == 2 && p.rules[2].proxy_id == 0 && p.rules[2].enabled);
    CHECK(!strcmp(p.rules[2].hosts, "*") && !strcmp(p.rules[2].ports, "*"));
    pbp_free(&p);
}

static void test_roundtrip(void)
{
    struct pbp_profile a, b;
    char err[256];
    CHECK(parse(WINDOWS_SAMPLE, &a, err) == 0);
    a.name = strdup("Work \"é\"");
    a.default_proxy_id = 2;
    a.dns_via_proxy = false;
    char *json = pbp_serialize(&a);
    CHECK(json && strstr(json, "\"TargetDomains\": \"*.github.com\"") && strstr(json, "\"TargetHosts\": \"192.168.*.*\""));
    CHECK(pbp_parse(json, strlen(json), &b, err, sizeof err) == 0);
    CHECK(b.nproxies == a.nproxies && b.nrules == a.nrules && b.default_proxy_id == 2 && !b.dns_via_proxy);
    CHECK(b.name && !strcmp(b.name, a.name));
    for (size_t i = 0; i < a.nrules && i < b.nrules; i++) {
        CHECK(!strcmp(a.rules[i].hosts, b.rules[i].hosts) && !strcmp(a.rules[i].process, b.rules[i].process));
        CHECK(a.rules[i].protocol == b.rules[i].protocol && a.rules[i].action == b.rules[i].action);
        CHECK(a.rules[i].enabled == b.rules[i].enabled && a.rules[i].proxy_id == b.rules[i].proxy_id);
    }
    for (size_t i = 0; i < a.nproxies && i < b.nproxies; i++)
        CHECK(!strcmp(a.proxies[i].pass, b.proxies[i].pass) && a.proxies[i].port == b.proxies[i].port && a.proxies[i].id == b.proxies[i].id);
    free(json);
    pbp_free(&a);
    pbp_free(&b);
}

static void expect_error(const char *json, const char *needle)
{
    struct pbp_profile p;
    char err[256] = "";
    int rc = parse(json, &p, err);
    CHECK(rc == -1 && p.nproxies == 0 && p.nrules == 0 && !p.proxies && !p.rules);
    if (needle && !strstr(err, needle)) { fails++; printf("FAIL error '%s' lacks '%s'\n", err, needle); }
}

static void test_errors(void)
{
    expect_error("", NULL);
    expect_error("[]", "JSON object");
    expect_error("{", NULL);
    expect_error("{\"ProxyRules\": 5}", "arrays");
    expect_error("{} trailing", "after the profile");
    expect_error("{\"Name\": \"abc}", "unterminated");
    expect_error("{\"Name\": \"\\q\"}", "escape");
    expect_error("{\"Name\": \"\\ud800\"}", "surrogate");
    expect_error("{\"Name\": \"\\u0000\"}", "NUL");
    expect_error("{\"ProxyConfigs\":[{\"Type\":\"socks5\",\"Host\":\"h\",\"Port\":\"0\"}]}", "Port");
    expect_error("{\"ProxyConfigs\":[{\"Type\":\"socks5\",\"Host\":\"\",\"Port\":\"1\"}]}", "Host");
    expect_error("{\"ProxyConfigs\":[{\"Type\":\"ftp\",\"Host\":\"h\",\"Port\":\"1\"}]}", "Type");
    expect_error("{\"ProxyConfigs\":[5]}", "not an object");
    expect_error("{\"ProxyRules\":[{\"Protocol\":\"ICMP\"}]}", "Protocol");
    expect_error("{\"ProxyRules\":[{\"Action\":\"ALLOW\"}]}", "Action");
    expect_error("{\"ProxyRules\":[{\"ProxyConfigId\":7}]}", "does not match");
    expect_error("{\"ProxyRules\":[{\"ProxyConfigId\":-1}]}", "does not match");
    expect_error("{\"DefaultProxyId\":9}", "DefaultProxyId");

    char deep[400];                                        // nesting beyond the limit must not recurse without bound
    memset(deep, '[', 300);
    deep[300] = 0;
    expect_error(deep, "deeply");
}

static void test_leniency(void)
{
    struct pbp_profile p;
    char err[256];
    CHECK(parse("\xEF\xBB\xBF{\"Name\":\"bom\"}", &p, err) == 0 && !strcmp(p.name, "bom"));
    pbp_free(&p);
    CHECK(parse("{\"Name\":\"\\u00e9\\ud83d\\ude00\"}", &p, err) == 0 && !strcmp(p.name, "\xC3\xA9\xF0\x9F\x98\x80"));
    pbp_free(&p);
    // numbers where strings are expected, mixed key case, duplicate ids and names
    CHECK(parse("{\"proxyconfigs\":[{\"Id\":3,\"Name\":\"a\",\"Type\":\"SOCKS5\",\"Host\":\"h\",\"Port\":1080},"
                "{\"Id\":3,\"Name\":\"a\",\"Type\":\"HTTP\",\"Host\":\"h2\",\"Port\":\"8080\"}],"
                "\"ProxyRules\":[{\"ProxyConfigId\":\"3\"}]}", &p, err) == 0);
    CHECK(p.nproxies == 2 && p.proxies[0].port == 1080 && p.proxies[0].id == 3 && p.proxies[1].id == 4);
    CHECK(strcmp(p.proxies[0].name, p.proxies[1].name) != 0);
    CHECK(p.nrules == 1 && p.rules[0].proxy_id == 3);
    pbp_free(&p);
    CHECK(parse("{}", &p, err) == 0 && p.nproxies == 0 && p.nrules == 0 && p.logging && p.dns_via_proxy);
    pbp_free(&p);
}

static void check_split(const char *in, const char *ips, const char *doms)
{
    char *a, *d;
    pbp_split_hosts(in, &a, &d);
    CHECK(!strcmp(a, ips) && !strcmp(d, doms));
    if (strcmp(a, ips) || strcmp(d, doms)) printf("  split(%s) = [%s] [%s], wanted [%s] [%s]\n", in, a, d, ips, doms);
    free(a);
    free(d);
}

static void test_hosts(void)
{
    check_split("*", "*", "");
    check_split("", "", "");
    check_split("10.0.0.0/8; 192.168.*.*", "10.0.0.0/8;192.168.*.*", "");
    check_split("1.2.3.4-1.2.3.9,10.1-5.*.*", "1.2.3.4-1.2.3.9;10.1-5.*.*", "");
    check_split("github.com;*.github.com", "", "github.com;*.github.com");
    check_split("fe80::1;2001:db8::/32", "fe80::1;2001:db8::/32", "");
    check_split("10.0.0.1;example.org;::1;bad.cafe", "10.0.0.1;::1", "example.org;bad.cafe");
    check_split("a?.example.com", "", "a?.example.com");

    char *m = pbp_merge_hosts("*", "x.com");
    CHECK(!strcmp(m, "x.com")); free(m);
    m = pbp_merge_hosts("", "");
    CHECK(!strcmp(m, "*")); free(m);
    m = pbp_merge_hosts("10.0.0.0/8", "x.com;y.org");
    CHECK(!strcmp(m, "10.0.0.0/8;x.com;y.org")); free(m);
    m = pbp_merge_hosts(NULL, NULL);
    CHECK(!strcmp(m, "*")); free(m);
}

static void test_names(void)
{
    const char *names[] = { "Default", "My Work", "a/b", "..", ".hidden", "100%", "tab\tname", "日本語", "x.y.z", "a:b*c?" };
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        char *f = pbp_filename_for(names[i]);
        CHECK(f && !strchr(f, '/') && f[0] != '.');
        char *back = f ? pbp_name_from_filename(f) : NULL;
        CHECK(back && !strcmp(back, names[i]));
        free(f);
        free(back);
    }
    CHECK(pbp_filename_for("") == NULL && pbp_filename_for(NULL) == NULL);
    char longname[300];
    memset(longname, 'a', 299);
    longname[299] = 0;
    CHECK(pbp_filename_for(longname) == NULL);
    CHECK(pbp_name_from_filename("x.txt") == NULL && pbp_name_from_filename(".pbprofile") == NULL);
    CHECK(pbp_name_from_filename("bad%zz.pbprofile") == NULL && pbp_name_from_filename("trunc%4.pbprofile") == NULL);
    CHECK(pbp_name_from_filename("nul%00.pbprofile") == NULL);
}

static void test_files(void)
{
    char dir[] = "/tmp/pbp_test_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[300], err[256];
    snprintf(path, sizeof path, "%s/a.pbprofile", dir);

    struct pbp_profile p, q;
    CHECK(parse(WINDOWS_SAMPLE, &p, err) == 0);
    CHECK(pbp_save_file(path, &p, err, sizeof err) == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);        // the file holds credentials
    CHECK(pbp_load_file(path, &q, err, sizeof err) == 0 && q.nrules == p.nrules);
    pbp_free(&q);
    CHECK(pbp_save_file(path, &p, err, sizeof err) == 0);               // overwrite
    char leftovers[400];
    snprintf(leftovers, sizeof leftovers, "ls %s | grep -c tmp > /dev/null", dir);
    CHECK(system(leftovers) != 0);                                      // no temporary files remain
    pbp_free(&p);

    CHECK(pbp_load_file("/nonexistent/x.pbprofile", &q, err, sizeof err) == -1 && strstr(err, "cannot open"));
    CHECK(pbp_load_file(dir, &q, err, sizeof err) == -1 && strstr(err, "regular"));
    snprintf(path, sizeof path, "%s/empty.pbprofile", dir);
    FILE *f = fopen(path, "w");
    fclose(f);
    CHECK(pbp_load_file(path, &q, err, sizeof err) == -1 && strstr(err, "empty"));
    snprintf(path, sizeof path, "%s/huge.pbprofile", dir);
    f = fopen(path, "w");
    CHECK(fseek(f, (long)PBP_MAX_FILE + 10, SEEK_SET) == 0 && fputc('x', f) != EOF);
    fclose(f);
    CHECK(pbp_load_file(path, &q, err, sizeof err) == -1 && strstr(err, "too large"));

    char *r = pbp_resolve("/etc/proxybridge", "Work");
    CHECK(r && !strcmp(r, "/etc/proxybridge/profiles/Work.pbprofile")); free(r);
    r = pbp_resolve("/etc/proxybridge", "/tmp/x.pbprofile");
    CHECK(r && !strcmp(r, "/tmp/x.pbprofile")); free(r);
    r = pbp_resolve("/etc/proxybridge", "Work.pbprofile");              // no such file in the cwd: treated as the name
    CHECK(r && !strcmp(r, "/etc/proxybridge/profiles/Work.pbprofile")); free(r);
    r = pbp_resolve("/etc/proxybridge", "..");
    CHECK(r && strstr(r, "..") == NULL ? 1 : r && !strstr(r, "/../")); free(r);

    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

// Mutated and truncated inputs must be rejected or accepted, never crash or leak (run under ASan/UBSan).
static void test_fuzz(void)
{
    size_t n = strlen(WINDOWS_SAMPLE);
    unsigned seed = 12345;
    int accepted = 0;
    for (int it = 0; it < 40000; it++) {
        char *buf = malloc(n + 1);
        memcpy(buf, WINDOWS_SAMPLE, n + 1);
        size_t len = n;
        seed = seed * 1103515245u + 12345u;
        int flips = 1 + (int)((seed >> 16) % 4);
        for (int k = 0; k < flips; k++) {
            seed = seed * 1103515245u + 12345u;
            size_t pos = (seed >> 8) % n;
            seed = seed * 1103515245u + 12345u;
            buf[pos] = (char)(seed >> 16);
        }
        seed = seed * 1103515245u + 12345u;
        if ((seed >> 20) % 4 == 0) len = (seed >> 8) % n;
        struct pbp_profile p;
        char err[256];
        if (pbp_parse(buf, len, &p, err, sizeof err) == 0) {
            accepted++;
            char *out = pbp_serialize(&p);
            struct pbp_profile q;
            CHECK(out && pbp_parse(out, strlen(out), &q, err, sizeof err) == 0);   // anything accepted must survive a round trip
            if (out) pbp_free(&q);
            free(out);
            pbp_free(&p);
        }
        free(buf);
    }
    CHECK(accepted > 0);
}

int main(void)
{
    test_windows_sample();
    test_roundtrip();
    test_errors();
    test_leniency();
    test_hosts();
    test_names();
    test_files();
    test_fuzz();
    printf("profile_test: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
