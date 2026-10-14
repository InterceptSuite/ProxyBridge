// Rule/proxy churn while traffic flows: memory, descriptors and threads must stay flat.
#define _GNU_SOURCE
#include <dirent.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/ProxyBridge.h"

static long status_kb(const char *key)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    size_t n = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, key, n)) { v = strtol(line + n, NULL, 10); break; }
    if (f) fclose(f);
    return v;
}

static int count_dir(const char *path)
{
    DIR *d = opendir(path);
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d))) n += e->d_name[0] != '.';
    if (d) closedir(d);
    return n;
}

struct sample { long rss_kb, heap_kb; long threads; int fds; };

static struct sample sample(void)
{
    struct mallinfo2 mi = mallinfo2();
    return (struct sample){ status_kb("VmRSS:"), (long)((mi.uordblks + mi.hblkhd) / 1024), status_kb("Threads:"), count_dir("/proc/self/fd") };
}

int main(int argc, char **argv)
{
    int iterations = argc > 1 ? atoi(argv[1]) : 5000;
    char err[256];
    uint32_t pa = ProxyBridge_AddProxy("a", PROXY_TYPE_SOCKS5, "127.0.0.1", 19080, "", "", err, sizeof err);
    uint32_t pb = ProxyBridge_AddProxy("b", PROXY_TYPE_SOCKS5, "127.0.0.1", 19081, "bob", "pw", err, sizeof err);
    ProxyBridge_AddRule("curl", "192.0.2.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, pa, err, sizeof err);
    ProxyBridge_AddRule("python3*", "192.0.2.0/24", "5300", RULE_PROTOCOL_UDP, RULE_ACTION_PROXY, pb, err, sizeof err);
    ProxyBridge_AddRule("*", "*.example.test", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, pa, err, sizeof err);
    if (!ProxyBridge_Start()) { fprintf(stderr, "start failed\n"); return 2; }
    sleep(1);

    struct sample warm = { 0 };
    int warm_at = iterations / 10;
    for (int i = 0; i < iterations; i++) {
        char hosts[64];
        snprintf(hosts, sizeof hosts, "10.%d.%d.0/24;*.churn%d.test", i % 200, (i / 200) % 200, i % 7);
        uint32_t r1 = ProxyBridge_AddRule("wget;curl", hosts, "80;443;8000-9000", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, i % 2 ? pa : pb, err, sizeof err);
        uint32_t r2 = ProxyBridge_AddRule("*chrome*", "198.51.100.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_BLOCK, 0, err, sizeof err);
        ProxyBridge_EditRule(r1, "wget", "203.0.113.0/24", "*", RULE_PROTOCOL_TCP, RULE_ACTION_DIRECT, 0, err, sizeof err);
        ProxyBridge_MoveRule(r2, 0);
        ProxyBridge_DisableRule(r1);
        ProxyBridge_EnableRule(r1);
        uint32_t p = ProxyBridge_AddProxy("tmp", i % 2 ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5, "127.0.0.1", 19082, "", "", err, sizeof err);
        ProxyBridge_EditProxy(p, "tmp2", PROXY_TYPE_SOCKS5, "localhost", 19083, "u", "p", err, sizeof err);
        ProxyBridge_DeleteRule(r1);
        ProxyBridge_DeleteRule(r2);
        ProxyBridge_DeleteProxy(p);
        if (i % 500 == 499) { ProxyBridge_Stop(); ProxyBridge_Start(); }      /* full restart cycles */
        if (i == warm_at) warm = sample();
        if (i % 1000 == 999) { struct sample s = sample(); printf("iteration %d: rss=%ld KB heap in use=%ld KB threads=%ld fds=%d\n", i + 1, s.rss_kb, s.heap_kb, s.threads, s.fds); fflush(stdout); }
    }
    struct sample end = sample();
    ProxyBridge_Stop();
    long rss_growth = end.rss_kb - warm.rss_kb, heap_growth = end.heap_kb - warm.heap_kb;
    printf("warm-up: rss=%ld heap=%ld KB threads=%ld fds=%d | end: rss=%ld heap=%ld KB threads=%ld fds=%d | growth: rss %ld KB, heap in use %ld KB\n",
           warm.rss_kb, warm.heap_kb, warm.threads, warm.fds, end.rss_kb, end.heap_kb, end.threads, end.fds, rss_growth, heap_growth);
    int sanitized = getenv("PB_SANITIZED") != NULL;          /* sanitizer quarantines distort both numbers */
    int ok = (sanitized || heap_growth < 256) && end.fds <= warm.fds + 2 && end.threads <= warm.threads + 1;
    printf("%s\n", ok ? "PASS  heap, descriptors and threads stay flat under churn" : "FAIL  growth under churn");
    return !ok;
}
