/* Test helper: runs the library's multi-step proxy check (what the GUI's "Test connection" shows).
 *   check_probe <name> <socks5|http> <host> <port> <user|-> <pass|-> <target host> <target port>  [more proxies: 6 args each]
 * Exit status: 0 all passed, 1 some failed, 2 bad arguments. No root needed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/ProxyBridge.h"

static void line(const char* s, void* u) { (void)u; printf("%s\n", s); fflush(stdout); }

int main(int argc, char** argv)
{
    if (argc < 9 || (argc - 3) % 6) { fprintf(stderr, "usage: see source\n"); return 2; }
    const char* th = argv[argc - 2]; long tp = strtol(argv[argc - 1], NULL, 10);
    if (!th[0] || tp < 1 || tp > 65535) { fprintf(stderr, "ERROR: Invalid target\n"); return 2; }
    int failed = 0;
    for (int i = 1; i + 5 < argc - 1; i += 6) {
        char err[256];
        ProxyType t = strcmp(argv[i + 1], "http") ? PROXY_TYPE_SOCKS5 : PROXY_TYPE_HTTP;
        const char* u = strcmp(argv[i + 4], "-") ? argv[i + 4] : "";
        const char* p = strcmp(argv[i + 5], "-") ? argv[i + 5] : "";
        uint32_t id = ProxyBridge_AddProxy(argv[i], t, argv[i + 2], (uint16_t)atoi(argv[i + 3]), u, p, err, sizeof err);
        if (!id) { fprintf(stderr, "ERROR: %s\n", err); return 2; }
        if (ProxyBridge_TestProxyEx(id, th, (uint16_t)tp, line, NULL) != 0) failed++;
    }
    return failed ? 1 : 0;
}
