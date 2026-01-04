
#include "ProxyBridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile bool keep_running = true;

static void signal_handler(int sig) {
    (void)sig;
    printf("\n[SIGNAL] Shutting down...\n");
    keep_running = false;
}

static void print_usage(void) {
    printf("ProxyBridge v%s - Linux eBPF Edition\n", ProxyBridge_GetVersion());
    printf("Usage: proxybridge [OPTIONS]\n");
    printf("  --proxy-host <host>         Proxy server hostname/IP (required)\n");
    printf("  --proxy-port <port>         Proxy server port (required)\n");
    printf("  --proxy-type <http|socks5>  Proxy type (default: socks5)\n");
    printf("  --username <user>           Proxy username (optional)\n");
    printf("  --password <pass>           Proxy password (optional)\n");
    printf("  --rule <process;hosts;ports;proto;action>\n");
    printf("                              Add rule (can use multiple times)\n");
    printf("                              process: * or process name\n");
    printf("                              hosts: * or IP/pattern (e.g., 192.168.*.*)\n");
    printf("                              ports: * or port/range (e.g., 80;443 or 80-8000)\n");
    printf("                              proto: tcp, udp, both\n");
    printf("                              action: proxy, direct, block\n");
    printf("  --help                      Show this help\n");
    printf("\nExample:\n");
    printf("  sudo ./proxybridge --proxy-host 127.0.0.1 --proxy-port 1080 --proxy-type socks5 \\\n");
    printf("    --rule \"curl;*;*;tcp;proxy\" --rule \"firefox;*;80;443;tcp;proxy\"\n");
}

int main(int argc, char **argv) {
    ProxySettings settings = {0};
    ProxyRule rules[64] = {0};
    int rule_count = 0;
    
    settings.proxy_type = PROXY_TYPE_SOCKS5;
    settings.dns_via_proxy = true;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "--proxy-host") == 0 && i+1 < argc) {
            strncpy(settings.proxy_host, argv[++i], sizeof(settings.proxy_host)-1);
        } else if (strcmp(argv[i], "--proxy-port") == 0 && i+1 < argc) {
            settings.proxy_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--proxy-type") == 0 && i+1 < argc) {
            i++;
            if (strcmp(argv[i], "http") == 0) settings.proxy_type = PROXY_TYPE_HTTP;
            else if (strcmp(argv[i], "socks5") == 0) settings.proxy_type = PROXY_TYPE_SOCKS5;
        } else if (strcmp(argv[i], "--username") == 0 && i+1 < argc) {
            strncpy(settings.username, argv[++i], sizeof(settings.username)-1);
        } else if (strcmp(argv[i], "--password") == 0 && i+1 < argc) {
            strncpy(settings.password, argv[++i], sizeof(settings.password)-1);
        } else if (strcmp(argv[i], "--rule") == 0 && i+1 < argc) {
            i++;
            if (rule_count >= 64) {
                fprintf(stderr, "Too many rules (max 64)\n");
                continue;
            }
            char *rule_str = strdup(argv[i]);
            char *parts[5];
            int part_count = 0;
            char *token = strtok(rule_str, ";");
            while (token && part_count < 5) {
                parts[part_count++] = token;
                token = strtok(NULL, ";");
            }
            if (part_count == 5) {
                strncpy(rules[rule_count].process_name, parts[0], sizeof(rules[rule_count].process_name)-1);
                strncpy(rules[rule_count].target_hosts, parts[1], sizeof(rules[rule_count].target_hosts)-1);
                strncpy(rules[rule_count].target_ports, parts[2], sizeof(rules[rule_count].target_ports)-1);
                if (strcmp(parts[3], "tcp") == 0) rules[rule_count].proto = PROTO_TCP;
                else if (strcmp(parts[3], "udp") == 0) rules[rule_count].proto = PROTO_UDP;
                else rules[rule_count].proto = PROTO_BOTH;
                if (strcmp(parts[4], "proxy") == 0) rules[rule_count].action = ACTION_PROXY;
                else if (strcmp(parts[4], "block") == 0) rules[rule_count].action = ACTION_BLOCK;
                else rules[rule_count].action = ACTION_DIRECT;
                rules[rule_count].enabled = true;
                rule_count++;
            }
            free(rule_str);
        }
    }
    
    if (settings.proxy_host[0] == '\0' || settings.proxy_port == 0) {
        fprintf(stderr, "ERROR: --proxy-host and --proxy-port are required\n");
        print_usage();
        return 1;
    }
    

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    
    ProxyBridge_SetProxySettings(&settings);
    
    printf("Starting ProxyBridge...\n");
    printf("Proxy: %s://%s:%d\n",
           settings.proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5",
           settings.proxy_host, settings.proxy_port);
    
    if (!ProxyBridge_Start()) {
        fprintf(stderr, "Failed to start ProxyBridge\n");
        return 1;
    }
    
    for (int i = 0; i < rule_count; i++) {
        ProxyBridge_AddRule(&rules[i]);
    }
    
    printf("ProxyBridge running. Press Ctrl+C to stop.\n");
    
    while (keep_running) {
        sleep(1);
    }
    
    ProxyBridge_Stop();
    printf("ProxyBridge stopped.\n");
    
    return 0;
}

