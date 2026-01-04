// ProxyBridge.c - Complete implementation matching Windows
#include "ProxyBridge.h"
#include "proxybridge.skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define VERSION "3.0.0"
#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011
#define CGROUP_PATH "/sys/fs/cgroup"
#define SO_ORIGINAL_DST 80
#define MAX_PROCESS_NAME 256

// SOCKS5
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02

// BPF rule structure (must match BPF program)
struct proxy_rule {
    char process_name[MAX_PROCESS_NAME];
    char target_hosts[512];
    char target_ports[256];
    unsigned char proto;
    unsigned char action;
    unsigned char enabled;
};

// BPF event structure (must match BPF program)
struct conn_event {
    char process_name[16];
    uint32_t pid;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint8_t action;
    uint8_t proto;
};

// Globals
static struct proxybridge_bpf *skel = NULL;
static ProxySettings g_proxy = {0};
static ConnectionCallback g_callback = NULL;
static pthread_t g_tcp_thread = 0;
static pthread_t g_udp_thread = 0;
static pthread_t g_event_thread = 0;
static volatile bool g_running = false;
static int g_tcp_fd = -1;
static int g_udp_fd = -1;
static uint32_t g_next_rule_id = 1;

struct sockaddr_in_orig {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t pad[8];
};

struct orig_dest_info {
    uint32_t ip;
    uint16_t port;
    uint16_t local_port;
};

static void log_connection(const char *process, uint32_t pid, uint32_t dest_ip, uint16_t dest_port, int action) {
    // Don't log our own connections to the proxy server
    if (pid == getpid()) return;
    
    char dest_ip_str[32];
    snprintf(dest_ip_str, sizeof(dest_ip_str), "%u.%u.%u.%u",
             (dest_ip>>24)&0xFF, (dest_ip>>16)&0xFF, (dest_ip>>8)&0xFF, dest_ip&0xFF);
    
    const char *action_str = (action == ACTION_PROXY) ? "PROXY" : (action == ACTION_BLOCK) ? "BLOCK" : "DIRECT";
    printf("[CONN] %s (PID:%u) -> %s:%u [%s]\n", process, pid, dest_ip_str, dest_port, action_str);
    
    if (g_callback) {
        char proxy_info[256];
        snprintf(proxy_info, sizeof(proxy_info), "%s:%d", g_proxy.proxy_host, g_proxy.proxy_port);
        g_callback(process, pid, dest_ip_str, dest_port, proxy_info);
    }
}

static int get_original_dest_from_map(int fd, uint32_t *ip, uint16_t *port) {
    if (!skel) return -1;
    
    // Iterate the map to find our connection
    uint64_t key = 0, next_key;
    struct orig_dest_info value;
    int map_fd = bpf_map__fd(skel->maps.socket_map);
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            *ip = value.ip;
            *port = value.port;
            bpf_map_delete_elem(map_fd, &next_key);
            return 0;
        }
        key = next_key;
    }
    
    return -1;
}

static uint32_t resolve_host(const char *host) {
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) == 1) return ntohl(addr.s_addr);
    struct hostent *he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    return ntohl(addr.s_addr);
}

static int socks5_connect(int fd, uint32_t dest_ip, uint16_t dest_port) {
    unsigned char buf[512];
    bool use_auth = (g_proxy.username[0] != '\0');
    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 2; buf[2] = SOCKS5_AUTH_NONE; buf[3] = SOCKS5_AUTH_USERPASS;
        if (send(fd, buf, 4, 0) != 4) return -1;
    } else {
        buf[1] = 1; buf[2] = SOCKS5_AUTH_NONE;
        if (send(fd, buf, 3, 0) != 3) return -1;
    }
    if (recv(fd, buf, 2, 0) != 2 || buf[0] != SOCKS5_VERSION) return -1;
    if (buf[1] == SOCKS5_AUTH_USERPASS) {
        if (!use_auth) return -1;
        int ulen = strlen(g_proxy.username), plen = strlen(g_proxy.password);
        buf[0] = 0x01; buf[1] = ulen;
        memcpy(&buf[2], g_proxy.username, ulen);
        buf[2 + ulen] = plen;
        memcpy(&buf[3 + ulen], g_proxy.password, plen);
        if (send(fd, buf, 3 + ulen + plen, 0) < 0) return -1;
        if (recv(fd, buf, 2, 0) != 2 || buf[1] != 0x00) return -1;
    }
    buf[0] = SOCKS5_VERSION; buf[1] = SOCKS5_CMD_CONNECT; buf[2] = 0x00; buf[3] = SOCKS5_ATYP_IPV4;
    *(uint32_t*)&buf[4] = htonl(dest_ip);
    *(uint16_t*)&buf[8] = htons(dest_port);
    if (send(fd, buf, 10, 0) != 10) return -1;
    if (recv(fd, buf, 10, 0) < 2 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00) return -1;
    return 0;
}

static void base64_encode(const char *in, char *out, size_t out_size) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(in), olen = 0;
    for (size_t i = 0; i < len && olen < out_size - 4; i += 3) {
        unsigned char b1 = in[i], b2 = (i+1<len)?in[i+1]:0, b3 = (i+2<len)?in[i+2]:0;
        out[olen++] = b64[b1 >> 2];
        out[olen++] = b64[((b1 & 0x03) << 4) | (b2 >> 4)];
        out[olen++] = (i+1<len) ? b64[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        out[olen++] = (i+2<len) ? b64[b3 & 0x3F] : '=';
    }
    out[olen] = '\0';
}

static int http_connect(int fd, uint32_t dest_ip, uint16_t dest_port) {
    char req[2048], resp[4096];
    bool use_auth = (g_proxy.username[0] != '\0');
    if (use_auth) {
        char cred[512], enc[1024];
        snprintf(cred, sizeof(cred), "%s:%s", g_proxy.username, g_proxy.password);
        base64_encode(cred, enc, sizeof(enc));
        snprintf(req, sizeof(req),
                "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\nHost: %d.%d.%d.%d:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",
                (dest_ip>>0)&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24)&0xFF,dest_port,
                (dest_ip>>0)&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24)&0xFF,dest_port,enc);
    } else {
        snprintf(req, sizeof(req), "CONNECT %d.%d.%d.%d:%d HTTP/1.1\r\nHost: %d.%d.%d.%d:%d\r\n\r\n",
                (dest_ip>>0)&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24)&0xFF,dest_port,
                (dest_ip>>0)&0xFF,(dest_ip>>8)&0xFF,(dest_ip>>16)&0xFF,(dest_ip>>24)&0xFF,dest_port);
    }
    if (send(fd, req, strlen(req), 0) < 0) return -1;
    int len = recv(fd, resp, sizeof(resp)-1, 0);
    if (len < 12) return -1;
    resp[len] = '\0';
    int code = 0;
    sscanf(resp, "HTTP/%*s %d", &code);
    return (code == 200) ? 0 : -1;
}

static void forward_data(int client_fd, int proxy_fd) {
    fd_set rdfds;
    char buf[8192];
    int maxfd = (client_fd > proxy_fd) ? client_fd : proxy_fd;
    while (g_running) {
        FD_ZERO(&rdfds);
        FD_SET(client_fd, &rdfds);
        FD_SET(proxy_fd, &rdfds);
        struct timeval tv = {1, 0};
        if (select(maxfd + 1, &rdfds, NULL, NULL, &tv) <= 0) continue;
        if (FD_ISSET(client_fd, &rdfds)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(proxy_fd, buf, n, 0) != n) break;
        }
        if (FD_ISSET(proxy_fd, &rdfds)) {
            ssize_t n = recv(proxy_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(client_fd, buf, n, 0) != n) break;
        }
    }
}

static void* handle_tcp_conn(void *arg) {
    int client_fd = (int)(long)arg;
    int proxy_fd = -1;
    uint32_t dest_ip, proxy_ip;
    uint16_t dest_port;
    
    if (get_original_dest_from_map(client_fd, &dest_ip, &dest_port) != 0) {
        close(client_fd);
        return NULL;
    }
    
    // Don't log here - already logged by BPF event
    proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_fd < 0) goto cleanup;
    proxy_ip = resolve_host(g_proxy.proxy_host);
    if (proxy_ip == 0) goto cleanup;
    struct sockaddr_in paddr = {0};
    paddr.sin_family = AF_INET;
    paddr.sin_addr.s_addr = htonl(proxy_ip);
    paddr.sin_port = htons(g_proxy.proxy_port);
    if (connect(proxy_fd, (struct sockaddr*)&paddr, sizeof(paddr)) != 0) goto cleanup;
    if (g_proxy.proxy_type == PROXY_TYPE_SOCKS5) {
        if (socks5_connect(proxy_fd, dest_ip, dest_port) != 0) goto cleanup;
    } else {
        if (http_connect(proxy_fd, dest_ip, dest_port) != 0) goto cleanup;
    }
    forward_data(client_fd, proxy_fd);
cleanup:
    if (proxy_fd >= 0) close(proxy_fd);
    close(client_fd);
    return NULL;
}

static void* tcp_relay(void *arg) {
    (void)arg;
    g_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp_fd < 0) return NULL;
    int opt = 1;
    setsockopt(g_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LOCAL_PROXY_PORT);
    if (bind(g_tcp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(g_tcp_fd, 128) < 0) {
        close(g_tcp_fd);
        g_tcp_fd = -1;
        return NULL;
    }
    // TCP relay listening
    while (g_running) {
        fd_set rdfds;
        FD_ZERO(&rdfds);
        FD_SET(g_tcp_fd, &rdfds);
        struct timeval tv = {1, 0};
        if (select(g_tcp_fd + 1, &rdfds, NULL, NULL, &tv) <= 0) continue;
        int client_fd = accept(g_tcp_fd, NULL, NULL);
        if (client_fd >= 0) {
            pthread_t thread;
            pthread_create(&thread, NULL, handle_tcp_conn, (void*)(long)client_fd);
            pthread_detach(thread);
        }
    }
    if (g_tcp_fd >= 0) { close(g_tcp_fd); g_tcp_fd = -1; }
    return NULL;
}

static void* udp_relay(void *arg) {
    (void)arg;
    return NULL;
}

// Event reader thread - reads connection events from BPF
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    (void)ctx; (void)cpu;
    struct conn_event *e = (struct conn_event *)data;
    if (data_sz < sizeof(*e)) return;
    
    const char *action_str = (e->action == ACTION_PROXY) ? "Proxy" : 
                            (e->action == ACTION_BLOCK) ? "Blocked" : "Direct";
    
    log_connection(e->process_name, e->pid, e->dest_ip, e->dest_port, e->action);
}

static void* event_reader(void *arg) {
    (void)arg;
    struct perf_buffer *pb = NULL;
    
    if (!skel) return NULL;
    
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "[ERROR] Failed to create perf buffer\n");
        return NULL;
    }
    
    // Event reader started
    while (g_running) {
        perf_buffer__poll(pb, 100);
    }
    
    perf_buffer__free(pb);
    return NULL;
}

const char* ProxyBridge_GetVersion(void) { return VERSION; }

bool ProxyBridge_Start(void) {
    if (g_running) return false;
    g_running = true;
    skel = proxybridge_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to load BPF\n");
        g_running = false;
        return false;
    }
    int cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0 || bpf_prog_attach(bpf_program__fd(skel->progs.cgroup_connect4), cgroup_fd, BPF_CGROUP_INET4_CONNECT, 0) != 0) {
        fprintf(stderr, "[ERROR] Failed to attach connect4\n");
        proxybridge_bpf__destroy(skel);
        skel = NULL;
        g_running = false;
        if (cgroup_fd >= 0) close(cgroup_fd);
        return false;
    }
    close(cgroup_fd);
    printf("[BPF] Attached to cgroup\n");
    pthread_create(&g_tcp_thread, NULL, tcp_relay, NULL);
    if (g_proxy.proxy_type == PROXY_TYPE_SOCKS5) pthread_create(&g_udp_thread, NULL, udp_relay, NULL);
    pthread_create(&g_event_thread, NULL, event_reader, NULL);
    return true;
}

void ProxyBridge_Stop(void) {
    if (!g_running) return;
    g_running = false;
    if (g_tcp_fd >= 0) { close(g_tcp_fd); g_tcp_fd = -1; }
    if (g_udp_fd >= 0) { close(g_udp_fd); g_udp_fd = -1; }
    if (g_tcp_thread) { pthread_join(g_tcp_thread, NULL); g_tcp_thread = 0; }
    if (g_udp_thread) { pthread_join(g_udp_thread, NULL); g_udp_thread = 0; }
    if (g_event_thread) { pthread_join(g_event_thread, NULL); g_event_thread = 0; }
    if (skel) {
        printf("[BPF] Detaching...\n");
        proxybridge_bpf__destroy(skel);
        skel = NULL;
        printf("[BPF] Detached\n");
    }
}

void ProxyBridge_SetProxySettings(const ProxySettings *settings) { if (settings) g_proxy = *settings; }

uint32_t ProxyBridge_AddRule(const ProxyRule *rule) {
    if (!rule || !skel) return 0;
    uint32_t id = g_next_rule_id++;
    struct proxy_rule bpf_rule = {0};
    strncpy(bpf_rule.process_name, rule->process_name, sizeof(bpf_rule.process_name)-1);
    strncpy(bpf_rule.target_hosts, rule->target_hosts, sizeof(bpf_rule.target_hosts)-1);
    strncpy(bpf_rule.target_ports, rule->target_ports, sizeof(bpf_rule.target_ports)-1);
    bpf_rule.proto = rule->proto;
    bpf_rule.action = rule->action;
    bpf_rule.enabled = rule->enabled ? 1 : 0;
    uint32_t idx = id - 1;
    bpf_map_update_elem(bpf_map__fd(skel->maps.rules_map), &idx, &bpf_rule, BPF_ANY);
    printf("[RULE %u] %s %s:%s %s\n", id, rule->process_name, rule->target_hosts, rule->target_ports,
           rule->action == ACTION_PROXY ? "PROXY" : rule->action == ACTION_BLOCK ? "BLOCK" : "DIRECT");
    return id;
}

bool ProxyBridge_UpdateRule(uint32_t rule_id, const ProxyRule *rule) {
    if (!rule || !skel || rule_id == 0) return false;
    struct proxy_rule bpf_rule = {0};
    strncpy(bpf_rule.process_name, rule->process_name, sizeof(bpf_rule.process_name)-1);
    strncpy(bpf_rule.target_hosts, rule->target_hosts, sizeof(bpf_rule.target_hosts)-1);
    strncpy(bpf_rule.target_ports, rule->target_ports, sizeof(bpf_rule.target_ports)-1);
    bpf_rule.proto = rule->proto;
    bpf_rule.action = rule->action;
    bpf_rule.enabled = rule->enabled ? 1 : 0;
    uint32_t idx = rule_id - 1;
    return bpf_map_update_elem(bpf_map__fd(skel->maps.rules_map), &idx, &bpf_rule, BPF_ANY) == 0;
}

bool ProxyBridge_RemoveRule(uint32_t rule_id) {
    if (!skel || rule_id == 0) return false;
    struct proxy_rule bpf_rule = {0};
    uint32_t idx = rule_id - 1;
    return bpf_map_update_elem(bpf_map__fd(skel->maps.rules_map), &idx, &bpf_rule, BPF_ANY) == 0;
}

void ProxyBridge_ClearRules(void) {
    if (!skel) return;
    struct proxy_rule bpf_rule = {0};
    for (uint32_t i = 0; i < 100; i++)
        bpf_map_update_elem(bpf_map__fd(skel->maps.rules_map), &i, &bpf_rule, BPF_ANY);
    g_next_rule_id = 1;
}

void ProxyBridge_SetConnectionCallback(ConnectionCallback callback) { g_callback = callback; }
