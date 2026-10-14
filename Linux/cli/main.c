#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>
#include "../src/ProxyBridge.h"

#define MAX_RULES 100
#define MAX_PROXIES 32
#define MAX_RULE_STR 1024

typedef struct {
    char process_name[256];
    char target_hosts[256];
    char target_ports[256];
    RuleProtocol protocol;
    RuleAction action;
    char proxy_ref[64];     /* name or 1-based index of a --proxy; empty = first proxy */
} ProxyRule;

typedef struct {
    char name[64];
    ProxyType type;
    char host[256];
    uint16_t port;
    char username[256];
    char password[256];
    uint32_t id;
} ProxyEntry;

static volatile bool keep_running = false;
static int verbose_level = 0;

static void log_callback(const char* message)
{
    if (verbose_level == 1 || verbose_level == 3)
    {
        printf("[LOG] %s\n", message);
    }
}

static void connection_callback(const char* process_name, uint32_t pid, const char* dest_ip, uint16_t dest_port, const char* proxy_info)
{
    if (verbose_level == 2 || verbose_level == 3)
    {
        printf("[CONN] %s (PID:%u) -> %s:%u via %s\n",
               process_name, pid, dest_ip, dest_port, proxy_info);
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    keep_running = false;   /* async-signal-safe: the main loop does the shutdown */
}

static void show_banner(void)
{
    printf("\n");
    printf("  ____                        ____       _     _            \n");
    printf(" |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ \n");
    printf(" | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\\n");
    printf(" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/\n");
    printf(" |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|\n");
    printf("                      |___/                      |___/  V4.0\n");
    printf("\n");
    printf("  Universal proxy client for Linux applications\n");
    printf("\n");
    printf("\tAuthor: Sourav Kalal/InterceptSuite\n");
    printf("\tGitHub: https://github.com/InterceptSuite/ProxyBridge\n");
    printf("\n");
}

static void show_help(const char* prog)
{
    show_banner();
    printf("USAGE:\n");
    printf("  %s [OPTIONS]\n\n", prog);

    printf("OPTIONS:\n");
    printf("  --proxy <spec>         Add a proxy (repeatable). The first one is the default.\n");
    printf("                         Format: [name=]type://[user:pass@]host:port\n");
    printf("                         Examples: socks5://127.0.0.1:1080\n");
    printf("                                   work=http://alice:secret@proxy.corp:8080\n");
    printf("                                   tor=socks5://[::1]:9050\n");
    printf("                         Legacy form type://host:port:user:pass is still accepted.\n");
    printf("                         Default: socks5://127.0.0.1:4444\n\n");

    printf("  --rule <rule>          Traffic routing rule (repeatable, first match wins)\n");
    printf("                         Format: process:hosts:ports:protocol:action[=proxy]\n");
    printf("                           process  - name or path glob(s): curl, chrom*, *, or several separated by ; or ,\n");
    printf("                           hosts    - IPv4/IPv6, CIDR (10.0.0.0/8), ranges (1.2.3.4-1.2.3.9),\n");
    printf("                                      octet patterns (192.168.*.*), domain names (github.com, *.github.com)\n");
    printf("                                      or *; several separated by ; or ,\n");
    printf("                                      (domains are matched via the DNS answers the application received)\n");
    printf("                           ports    - *, 443, 80;8080, 8000-9000\n");
    printf("                           protocol - TCP, UDP, or BOTH\n");
    printf("                           action   - PROXY, DIRECT, or BLOCK; PROXY=name (or PROXY=2) picks a specific proxy\n");
    printf("                         Examples:\n");
    printf("                           curl:*:*:TCP:PROXY\n");
    printf("                           firefox:*:*:BOTH:PROXY=work\n");
    printf("                           curl;wget:10.0.0.0/8:*:TCP:DIRECT\n");
    printf("                           *:*:53:UDP:PROXY=tor\n");
    printf("                           firefox:*.github.com;github.com:443:TCP:PROXY=work\n\n");

    printf("  --dns-via-proxy <bool> Route DNS queries through the proxy (true/false/1/0, default true)\n\n");

    printf("  --verbose <level>      0 none (default), 1 logs, 2 connections, 3 both\n\n");

    printf("  --cleanup              No-op, kept for compatibility: the eBPF programs detach automatically\n\n");

    printf("  --help, -h             Show this help message\n\n");

    printf("EXAMPLES:\n");
    printf("  sudo %s --rule curl:*:*:TCP:PROXY\n\n", prog);
    printf("  sudo %s --proxy socks5://192.168.1.10:1080 --proxy work=http://proxy.corp:8080 \\\n", prog);
    printf("       --rule firefox:*:*:BOTH:PROXY --rule curl:*:*:TCP:PROXY=work --verbose 2\n\n");

    printf("NOTE:\n");
    printf("  ProxyBridge needs root and a Linux kernel >= 5.8 with BTF and cgroup v2 (eBPF datapath).\n");
    printf("  Credentials given on the command line are visible to other users via ps.\n\n");
}

static void upper_copy(char* dst, const char* src, size_t n)
{
    size_t i = 0;
    for (; src[i] && i + 1 < n; i++)
        dst[i] = (char)toupper((unsigned char)src[i]);
    dst[i] = '\0';
}

static RuleProtocol parse_protocol(const char* str)
{
    char upper[16];
    upper_copy(upper, str, sizeof(upper));
    if (strcmp(upper, "TCP") == 0) return RULE_PROTOCOL_TCP;
    if (strcmp(upper, "UDP") == 0) return RULE_PROTOCOL_UDP;
    if (strcmp(upper, "BOTH") == 0) return RULE_PROTOCOL_BOTH;
    fprintf(stderr, "ERROR: Invalid protocol '%s'. Use TCP, UDP, or BOTH\n", str);
    exit(1);
}

/* action[=proxy] */
static RuleAction parse_action(const char* str, char* proxy_ref, size_t ref_size)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", str);
    proxy_ref[0] = '\0';
    char* eq = strchr(buf, '=');
    if (eq)
    {
        *eq = '\0';
        snprintf(proxy_ref, ref_size, "%s", eq + 1);
    }
    char upper[16];
    upper_copy(upper, buf, sizeof(upper));
    if (strcmp(upper, "PROXY") == 0) return RULE_ACTION_PROXY;
    if (eq && proxy_ref[0]) { fprintf(stderr, "ERROR: '=proxy' is only valid with PROXY\n"); exit(1); }
    if (strcmp(upper, "DIRECT") == 0) return RULE_ACTION_DIRECT;
    if (strcmp(upper, "BLOCK") == 0) return RULE_ACTION_BLOCK;
    fprintf(stderr, "ERROR: Invalid action '%s'. Use PROXY, DIRECT, or BLOCK\n", buf);
    exit(1);
}

static void default_if_empty(char* dest, const char* src, const char* default_val, size_t dest_size)
{
    if (src == NULL || src[0] == '\0' || strcmp(src, " ") == 0)
        snprintf(dest, dest_size, "%s", default_val);
    else
        snprintf(dest, dest_size, "%.*s", (int)dest_size - 1, src);
}

/* process:hosts:ports:protocol:action[=proxy] -- hosts may itself contain ':' (IPv6), so parse from both ends */
static bool parse_rule(const char* rule_str, ProxyRule* rule)
{
    char buffer[MAX_RULE_STR];
    snprintf(buffer, sizeof(buffer), "%s", rule_str);

    char* first = strchr(buffer, ':');
    char* last = strrchr(buffer, ':');
    char* second_last = NULL;
    char* third_last = NULL;
    if (last && last != first)
    {
        *last = '\0';
        second_last = strrchr(buffer, ':');
        if (second_last && second_last != first)
        {
            *second_last = '\0';
            third_last = strrchr(buffer, ':');
        }
    }
    if (!first || !last || !second_last || !third_last || third_last == first)
    {
        fprintf(stderr, "ERROR: Invalid rule format '%s'\n", rule_str);
        fprintf(stderr, "Expected format: process:hosts:ports:protocol:action[=proxy]\n");
        return false;
    }
    /* after trimming: buffer = process ':' hosts ':' ports ; protocol = second_last+1 ; action = last+1 */
    *third_last = '\0';
    const char* ports = third_last + 1;
    const char* protocol = second_last + 1;
    const char* action = last + 1;

    /* process = up to the first ':' ; hosts = between first ':' and third_last */
    char* sep = strchr(buffer, ':');
    if (!sep)
    {
        fprintf(stderr, "ERROR: Invalid rule format '%s'\n", rule_str);
        return false;
    }
    *sep = '\0';
    const char* hosts = sep + 1;

    default_if_empty(rule->process_name, buffer, "*", sizeof(rule->process_name));
    default_if_empty(rule->target_hosts, hosts, "*", sizeof(rule->target_hosts));
    default_if_empty(rule->target_ports, ports, "*", sizeof(rule->target_ports));
    rule->protocol = parse_protocol(protocol);
    rule->action = parse_action(action, rule->proxy_ref, sizeof(rule->proxy_ref));
    return true;
}

/* [name=]type://[user:pass@]host:port  or legacy type://host:port[:user:pass] ; host may be [v6] */
static bool parse_proxy_spec(const char* spec, ProxyEntry* p)
{
    char buffer[768];
    snprintf(buffer, sizeof(buffer), "%s", spec);
    memset(p, 0, sizeof(*p));

    char* scheme_end = strstr(buffer, "://");
    if (scheme_end == NULL)
    {
        fprintf(stderr, "ERROR: Invalid proxy '%s'. Expected [name=]type://host:port\n", spec);
        return false;
    }
    *scheme_end = '\0';
    char* scheme = buffer;
    char* rest = scheme_end + 3;
    char* eq = strchr(scheme, '=');
    if (eq)
    {
        *eq = '\0';
        snprintf(p->name, sizeof(p->name), "%.*s", (int)sizeof(p->name) - 1, scheme);
        scheme = eq + 1;
    }

    char upper_scheme[16];
    upper_copy(upper_scheme, scheme, sizeof(upper_scheme));
    if (strcmp(upper_scheme, "SOCKS5") == 0) p->type = PROXY_TYPE_SOCKS5;
    else if (strcmp(upper_scheme, "HTTP") == 0) p->type = PROXY_TYPE_HTTP;
    else
    {
        fprintf(stderr, "ERROR: Invalid proxy type '%s'. Use 'socks5' or 'http'\n", scheme);
        return false;
    }

    char* at = strrchr(rest, '@');
    if (at)
    {
        *at = '\0';
        char* colon = strchr(rest, ':');
        if (colon) { *colon = '\0'; snprintf(p->password, sizeof(p->password), "%s", colon + 1); }
        snprintf(p->username, sizeof(p->username), "%s", rest);
        rest = at + 1;
    }

    char* port_str = NULL;
    char* legacy = NULL;
    if (rest[0] == '[')
    {
        char* close = strchr(rest, ']');
        if (!close || close[1] != ':') { fprintf(stderr, "ERROR: Invalid IPv6 proxy host in '%s'\n", spec); return false; }
        *close = '\0';
        snprintf(p->host, sizeof(p->host), "%s", rest + 1);
        port_str = close + 2;
    }
    else
    {
        char* colon = strchr(rest, ':');
        if (!colon) { fprintf(stderr, "ERROR: Invalid proxy '%s': missing port\n", spec); return false; }
        *colon = '\0';
        snprintf(p->host, sizeof(p->host), "%s", rest);
        port_str = colon + 1;
    }
    legacy = strchr(port_str, ':');          /* type://host:port:user:pass */
    if (legacy && !at)
    {
        *legacy++ = '\0';
        char* colon = strchr(legacy, ':');
        if (colon) { *colon = '\0'; snprintf(p->password, sizeof(p->password), "%s", colon + 1); }
        snprintf(p->username, sizeof(p->username), "%s", legacy);
    }
    char* endp = NULL;
    long port = strtol(port_str, &endp, 10);
    if (!*port_str || *endp || port < 1 || port > 65535)
    {
        fprintf(stderr, "ERROR: Invalid proxy port '%s'\n", port_str);
        return false;
    }
    p->port = (uint16_t)port;
    if (!p->host[0]) { fprintf(stderr, "ERROR: Proxy host is empty in '%s'\n", spec); return false; }
    return true;
}

static uint32_t find_proxy(const ProxyEntry* proxies, int n, const char* ref)
{
    if (!ref[0])
        return 0;                            /* default proxy */
    char* endp = NULL;
    long idx = strtol(ref, &endp, 10);
    if (!*endp && idx >= 1 && idx <= n)
        return proxies[idx - 1].id;
    for (int i = 0; i < n; i++)
        if (strcmp(proxies[i].name, ref) == 0)
            return proxies[i].id;
    return UINT32_MAX;
}

static bool is_root(void)
{
    return getuid() == 0;
}

int main(int argc, char *argv[])
{
    ProxyEntry proxies[MAX_PROXIES];
    int num_proxies = 0;
    ProxyRule rules[MAX_RULES];
    int num_rules = 0;
    bool dns_via_proxy = true;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--cleanup") == 0)
        {
            printf("Nothing to clean up: the eBPF programs detach automatically when ProxyBridge exits.\n");
            return 0;
        }
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            show_help(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc)
        {
            if (num_proxies >= MAX_PROXIES)
            {
                fprintf(stderr, "ERROR: Maximum %d proxies supported\n", MAX_PROXIES);
                return 1;
            }
            if (!parse_proxy_spec(argv[++i], &proxies[num_proxies]))
                return 1;
            num_proxies++;
        }
        else if (strcmp(argv[i], "--rule") == 0 && i + 1 < argc)
        {
            if (num_rules >= MAX_RULES)
            {
                fprintf(stderr, "ERROR: Maximum %d rules supported\n", MAX_RULES);
                return 1;
            }
            if (!parse_rule(argv[++i], &rules[num_rules]))
                return 1;
            num_rules++;
        }
        else if (strcmp(argv[i], "--dns-via-proxy") == 0 && i + 1 < argc)
        {
            char* value = argv[++i];
            if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0)
                dns_via_proxy = true;
            else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0)
                dns_via_proxy = false;
            else
            {
                fprintf(stderr, "ERROR: Invalid value for --dns-via-proxy. Use: true, false, 1, or 0\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--verbose") == 0 && i + 1 < argc)
        {
            verbose_level = atoi(argv[++i]);
            if (verbose_level < 0 || verbose_level > 3)
            {
                fprintf(stderr, "ERROR: Verbose level must be 0-3\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Unknown option '%s'\n", argv[i]);
            fprintf(stderr, "Use --help for usage information\n");
            return 1;
        }
    }

    if (num_proxies == 0)
    {
        if (!parse_proxy_spec("socks5://127.0.0.1:4444", &proxies[0]))
            return 1;
        num_proxies = 1;
    }

    show_banner();

    if (!is_root())
    {
        printf("\033[31m\nERROR: ProxyBridge requires root privileges!\033[0m\n");
        printf("Please run this application with sudo or as root.\n\n");
        return 1;
    }

    if (verbose_level == 1 || verbose_level == 3)
        ProxyBridge_SetLogCallback(log_callback);
    else
        ProxyBridge_SetLogCallback(NULL);

    if (verbose_level == 2 || verbose_level == 3)
        ProxyBridge_SetConnectionCallback(connection_callback);
    else
        ProxyBridge_SetConnectionCallback(NULL);

    ProxyBridge_SetTrafficLoggingEnabled(verbose_level > 0);
    ProxyBridge_SetDnsViaProxy(dns_via_proxy);

    char err[256];
    printf("Proxies: %d\n", num_proxies);
    for (int i = 0; i < num_proxies; i++)
    {
        ProxyEntry* p = &proxies[i];
        p->id = ProxyBridge_AddProxy(p->name, p->type, p->host, p->port, p->username, p->password, err, sizeof(err));
        if (!p->id)
        {
            fprintf(stderr, "ERROR: Proxy %d (%s:%u): %s\n", i + 1, p->host, p->port, err);
            return 1;
        }
        printf("  [%d]%s%s%s %s://%s:%u%s\n", i + 1, p->name[0] ? " " : "", p->name, i == 0 ? " (default)" : "",
               p->type == PROXY_TYPE_HTTP ? "http" : "socks5", p->host, p->port, p->username[0] ? " (auth)" : "");
    }
    printf("DNS via Proxy: %s\n", dns_via_proxy ? "Enabled" : "Disabled");

    if (num_rules > 0)
    {
        printf("Rules: %d\n", num_rules);
        for (int i = 0; i < num_rules; i++)
        {
            const char* protocol_str = rules[i].protocol == RULE_PROTOCOL_TCP ? "TCP" :
                                      rules[i].protocol == RULE_PROTOCOL_UDP ? "UDP" : "BOTH";
            const char* action_str = rules[i].action == RULE_ACTION_PROXY ? "PROXY" :
                                    rules[i].action == RULE_ACTION_DIRECT ? "DIRECT" : "BLOCK";
            uint32_t proxy_id = 0;
            if (rules[i].action == RULE_ACTION_PROXY)
            {
                proxy_id = find_proxy(proxies, num_proxies, rules[i].proxy_ref);
                if (proxy_id == UINT32_MAX)
                {
                    fprintf(stderr, "ERROR: Rule %d refers to unknown proxy '%s'\n", i + 1, rules[i].proxy_ref);
                    return 1;
                }
            }

            uint32_t rule_id = ProxyBridge_AddRule(rules[i].process_name, rules[i].target_hosts, rules[i].target_ports,
                                                   rules[i].protocol, rules[i].action, proxy_id, err, sizeof(err));
            if (rule_id == 0)
            {
                fprintf(stderr, "  ERROR: Rule %d (%s:%s:%s): %s\n", i + 1, rules[i].process_name,
                        rules[i].target_hosts, rules[i].target_ports, err);
                return 1;
            }
            printf("  [%u] %s:%s:%s:%s -> %s%s%s\n", rule_id, rules[i].process_name, rules[i].target_hosts,
                   rules[i].target_ports, protocol_str, action_str,
                   rules[i].proxy_ref[0] ? " via " : "", rules[i].proxy_ref);
        }
    }
    else
    {
        printf("\033[33mWARNING: No rules specified. No traffic will be proxied.\033[0m\n");
        printf("Use --rule to add proxy rules. See --help for examples.\n");
    }

    if (!ProxyBridge_Start())
    {
        fprintf(stderr, "ERROR: Failed to start ProxyBridge (run with --verbose 1 for details)\n");
        return 1;
    }

    keep_running = true;
    printf("\nProxyBridge started. Press Ctrl+C to stop...\n\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (keep_running)
        sleep(1);

    ProxyBridge_Stop();
    printf("ProxyBridge stopped.\n");
    return 0;
}
