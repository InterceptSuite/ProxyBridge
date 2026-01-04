
#include "ProxyBridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

static volatile bool g_running = false;
static int g_verbose = 0;

static void signal_handler(int sig) {
    (void)sig;
    printf("\n\nStopping ProxyBridge...\n");
    if (g_running) {
        ProxyBridge_Stop();
        g_running = false;
    }
    printf("ProxyBridge stopped.\n");
    exit(0);
}

static void print_banner(void) {
    printf("\n");
    printf("  ____                        ____       _     _\n");
    printf(" |  _ \\ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___\n");
    printf(" | |_) | '__/ _ \\ \\/ / | | | |  _ \\| '__| |/ _` |/ _` |/ _ \\\n");
    printf(" |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/\n");
    printf(" |_|   |_|  \\___/_/\\_\\\\__, | |____/|_|  |_|\\__,_|\\__, |\\___|\n");
    printf("                      |___/                      |___/  V%s\n", ProxyBridge_GetVersion());
    printf("\n");
    printf("  Universal proxy client for Linux applications\n");
    printf("\n");
    printf("        Author: Sourav Kalal/InterceptSuite\n");
    printf("        GitHub: https://github.com/InterceptSuite/ProxyBridge\n");
    printf("\n");
}

static void print_help(void) {
    print_banner();
    printf("Description:\n");
    printf("  ProxyBridge - Universal proxy client for Linux applications\n\n");
    printf("Usage:\n");
    printf("  proxybridge [options]\n\n");
    printf("Options:\n");
    printf("  --proxy <proxy>      Proxy server URL with optional authentication\n");
    printf("                       Format: type://ip:port or type://ip:port:username:password\n");
    printf("                       Examples: socks5://127.0.0.1:1080\n");
    printf("                                 http://proxy.com:8080:myuser:mypass [default: socks5://127.0.0.1:4444]\n");
    printf("  --rule <rule>        Traffic routing rule (multiple values supported, can repeat)\n");
    printf("                       Format: process:hosts:ports:protocol:action\n");
    printf("                         process  - Process name(s): curl, chr*, *, or * (use ; for multiple: curl;firefox)\n");
    printf("                         hosts    - IP/host(s): *, google.com, 192.168.*.*, or multiple separated by ; or ,\n");
    printf("                         ports    - Port(s): *, 443, 80;8080, 80-100, or multiple separated by ; or ,\n");
    printf("                         protocol - TCP, UDP, or BOTH\n");
    printf("                         action   - PROXY, DIRECT, or BLOCK\n");
    printf("                       Examples:\n");
    printf("                         curl:*:*:TCP:PROXY\n");
    printf("                         curl;firefox:*:*:TCP:PROXY\n");
    printf("                         *:*:53:UDP:PROXY\n");
    printf("                         firefox:*:80;443:TCP:DIRECT\n");
    printf("  --dns-via-proxy      Route DNS queries through proxy (default: true) [default: True]\n");
    printf("  --verbose <level>    Logging verbosity level\n");
    printf("                         0 - No logs (default)\n");
    printf("                         1 - Show log messages only\n");
    printf("                         2 - Show connection events only\n");
    printf("                         3 - Show both logs and connections [default: 0]\n");
    printf("  --version            Show version information\n");
    printf("  -h, --help           Show help and usage information\n");
    printf("\n");
}

// Parse proxy URL: socks5://host:port or socks5://host:port:user:pass
static int parse_proxy_url(const char *url, ProxySettings *settings) {
    char *str = strdup(url);
    char *orig = str;
    
    // Parse type
    char *scheme_end = strstr(str, "://");
    if (!scheme_end) {
        free(orig);
        return 0;
    }
    *scheme_end = '\0';
    if (strcmp(str, "socks5") == 0) settings->proxy_type = PROXY_TYPE_SOCKS5;
    else if (strcmp(str, "http") == 0) settings->proxy_type = PROXY_TYPE_HTTP;
    else { free(orig); return 0; }
    
    str = scheme_end + 3;
    
    // Parse host:port:user:pass
    char *parts[4] = {NULL};
    int part_count = 0;
    char *token = strtok(str, ":");
    while (token && part_count < 4) {
        parts[part_count++] = token;
        token = strtok(NULL, ":");
    }
    
    if (part_count < 2) { free(orig); return 0; }
    
    strncpy(settings->proxy_host, parts[0], sizeof(settings->proxy_host)-1);
    settings->proxy_port = atoi(parts[1]);
    
    if (part_count >= 3) strncpy(settings->username, parts[2], sizeof(settings->username)-1);
    if (part_count >= 4) strncpy(settings->password, parts[3], sizeof(settings->password)-1);
    
    free(orig);
    return 1;
}

// Parse rule: process:hosts:ports:protocol:action (colon delimiter like Windows)
static int parse_rule(const char *rule_str, ProxyRule *rule) {
    char *str = strdup(rule_str);
    char *orig = str;
    char *parts[5] = {NULL};
    int part_count = 0;
    
    char *token = strtok(str, ":");
    while (token && part_count < 5) {
        parts[part_count++] = token;
        token = strtok(NULL, ":");
    }
    
    if (part_count != 5) { free(orig); return 0; }
    
    strncpy(rule->process_name, parts[0], sizeof(rule->process_name)-1);
    strncpy(rule->target_hosts, parts[1], sizeof(rule->target_hosts)-1);
    strncpy(rule->target_ports, parts[2], sizeof(rule->target_ports)-1);
    
    // Parse protocol (case-insensitive)
    char proto_upper[10];
    for (int i = 0; parts[3][i] && i < 9; i++) proto_upper[i] = toupper(parts[3][i]);
    proto_upper[strlen(parts[3])] = '\0';
    if (strcmp(proto_upper, "TCP") == 0) rule->proto = PROTO_TCP;
    else if (strcmp(proto_upper, "UDP") == 0) rule->proto = PROTO_UDP;
    else if (strcmp(proto_upper, "BOTH") == 0) rule->proto = PROTO_BOTH;
    else { free(orig); return 0; }
    
    // Parse action (case-insensitive)
    char action_upper[10];
    for (int i = 0; parts[4][i] && i < 9; i++) action_upper[i] = toupper(parts[4][i]);
    action_upper[strlen(parts[4])] = '\0';
    if (strcmp(action_upper, "PROXY") == 0) rule->action = ACTION_PROXY;
    else if (strcmp(action_upper, "DIRECT") == 0) rule->action = ACTION_DIRECT;
    else if (strcmp(action_upper, "BLOCK") == 0) rule->action = ACTION_BLOCK;
    else { free(orig); return 0; }
    
    rule->enabled = true;
    free(orig);
    return 1;
}

static void on_connection(const char *processName, uint32_t pid, const char *destIp, uint16_t destPort, const char *proxyInfo) {
    // Verbose 2 = connections only, Verbose 3 = both
    if (g_verbose == 2 || g_verbose == 3) {
        printf("[CONN] %s (PID:%u) -> %s:%u via %s\n", processName, pid, destIp, destPort, proxyInfo);
    }
}


int main(int argc, char **argv) {
    ProxySettings settings = {0};
    ProxyRule rules[100] = {0};
    int rule_count = 0;
    bool dns_via_proxy = true;
    
    // Defaults
    settings.proxy_type = PROXY_TYPE_SOCKS5;
    strcpy(settings.proxy_host, "127.0.0.1");
    settings.proxy_port = 4444;
    settings.dns_via_proxy = true;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("ProxyBridge v%s\n", ProxyBridge_GetVersion());
            return 0;
        } else if (strcmp(argv[i], "--proxy") == 0 && i+1 < argc) {
            i++;
            if (!parse_proxy_url(argv[i], &settings)) {
                fprintf(stderr, "ERROR: Invalid proxy URL format\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--rule") == 0 && i+1 < argc) {
            i++;
            if (rule_count >= 100) {
                fprintf(stderr, "ERROR: Too many rules (max 100)\n");
                continue;
            }
            if (!parse_rule(argv[i], &rules[rule_count])) {
                fprintf(stderr, "ERROR: Invalid rule format: %s\n", argv[i]);
                continue;
            }
            rule_count++;
        } else if (strcmp(argv[i], "--dns-via-proxy") == 0) {
            dns_via_proxy = true;
        } else if (strcmp(argv[i], "--verbose") == 0 && i+1 < argc) {
            i++;
            g_verbose = atoi(argv[i]);
            if (g_verbose < 0 || g_verbose > 3) g_verbose = 0;
        }
    }
    
    print_banner();
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Set connection callback only if verbose mode requires it
    if (g_verbose == 2 || g_verbose == 3) {
        ProxyBridge_SetConnectionCallback(on_connection);
    }
    
    printf("Proxy: %s://%s:%d\n",
           settings.proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5",
           settings.proxy_host, settings.proxy_port);
    if (settings.username[0] != '\0') {
        printf("Proxy Auth: %s:***\n", settings.username);
    }
    printf("DNS via Proxy: %s\n", dns_via_proxy ? "Enabled" : "Disabled");
    
    settings.dns_via_proxy = dns_via_proxy;
    ProxyBridge_SetProxySettings(&settings);
    
    if (rule_count > 0) {
        printf("Rules: %d\n", rule_count);
    }
    
    if (!ProxyBridge_Start()) {
        fprintf(stderr, "ERROR: Failed to start ProxyBridge\n");
        return 1;
    }
    
    // Add rules AFTER start (when BPF is loaded)
    for (int i = 0; i < rule_count; i++) {
        uint32_t rule_id = ProxyBridge_AddRule(&rules[i]);
        if (rule_id > 0) {
            const char *proto_str = (rules[i].proto == PROTO_TCP) ? "TCP" : 
                                   (rules[i].proto == PROTO_UDP) ? "UDP" : "BOTH";
            const char *action_str = (rules[i].action == ACTION_PROXY) ? "PROXY" :
                                    (rules[i].action == ACTION_BLOCK) ? "BLOCK" : "DIRECT";
            printf("  [%u] %s:%s:%s:%s -> %s\n", rule_id,
                   rules[i].process_name, rules[i].target_hosts, rules[i].target_ports,
                   proto_str, action_str);
        } else {
            fprintf(stderr, "  ERROR: Failed to add rule for %s\n", rules[i].process_name);
        }
    }
    
    g_running = true;
    printf("\nProxyBridge started. Press Ctrl+C to stop...\n\n");
    
    while (g_running) {
        sleep(1);
    }
    
    return 0;
}


