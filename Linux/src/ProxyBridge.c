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
#include <netinet/tcp.h>
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
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
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
static int g_cgroup_fd = -1;

static ProxyRule g_rules[100];
static int g_rule_count = 0;
static pthread_mutex_t g_rules_mutex = PTHREAD_MUTEX_INITIALIZER;

static int socks5_udp_socket = -1;
static int socks5_udp_send_socket = -1;
static struct sockaddr_in socks5_udp_relay_addr;
static bool udp_associate_connected = false;
static time_t last_udp_connect_attempt = 0;

// Store process names from BPF events (keyed by dest_ip:dest_port)
struct conn_info {
    char process[16];
    uint32_t pid;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint8_t proto;
    time_t timestamp;
};
static struct conn_info g_conn_map[1000];
static int g_conn_map_count = 0;
static pthread_mutex_t g_conn_map_mutex = PTHREAD_MUTEX_INITIALIZER;

struct sockaddr_in_orig {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t pad[8];
};

struct orig_dest_info {
    uint32_t ip;
    uint16_t port;
    char process[16];
    uint32_t pid;
};

// Complex pattern matching (userspace only)
static bool match_wildcard(const char *str, const char *pattern) {
    if (!str || !pattern) return false;
    if (strcmp(pattern, "*") == 0) return true;
    const char *s = str, *p = pattern;
    int iterations = 0;
    const int MAX_ITERS = 10000; // Prevent DoS
    while (*s && *p && iterations++ < MAX_ITERS) {
        if (*p == '*') {
            p++;
            if (!*p) return true;
            while (*s && *s != *p) s++;
            if (!*s) return false;
        } else if (*p == *s) {
            p++; s++;
        } else {
            return false;
        }
    }
    return !*p && !*s;
}

static bool match_list(const char *item, const char *list) {
    if (strcmp(list, "*") == 0) return true;
    char buf[512];
    strncpy(buf, list, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    char *token = strtok(buf, ";");
    while (token) {
        while (*token == ' ') token++;
        if (strcmp(token, item) == 0) return true;
        token = strtok(NULL, ";");
    }
    return false;
}

static bool match_port(uint16_t port, const char *pattern) {
    if (strcmp(pattern, "*") == 0) return true;
    char buf[256];
    strncpy(buf, pattern, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    char *token = strtok(buf, ";");
    while (token) {
        while (*token == ' ') token++;
        if (strchr(token, '-')) {
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                if (port >= start && port <= end) return true;
            }
        } else {
            if (port == atoi(token)) return true;
        }
        token = strtok(NULL, ";");
    }
    return false;
}

static bool match_ip(uint32_t ip, const char *pattern) {
    if (strcmp(pattern, "*") == 0) return true;
    char ip_str[32];
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
    return match_wildcard(ip_str, pattern);
}

static uint8_t check_proxy_rules(const char *process, uint32_t dest_ip, uint16_t dest_port, uint8_t proto) {
    pthread_mutex_lock(&g_rules_mutex);
    for (int i = 0; i < g_rule_count; i++) {
        ProxyRule *rule = &g_rules[i];
        if (!rule->enabled || !(rule->proto & proto)) continue;
        if (!match_list(process, rule->process_name)) continue;
        if (!match_ip(dest_ip, rule->target_hosts)) continue;
        if (!match_port(dest_port, rule->target_ports)) continue;
        uint8_t action = rule->action;
        pthread_mutex_unlock(&g_rules_mutex);
        return action;
    }
    pthread_mutex_unlock(&g_rules_mutex);
    return ACTION_DIRECT;
}

static void log_connection(const char *process, uint32_t pid, uint32_t dest_ip, uint16_t dest_port, int action, int proto) {
    if (pid == getpid() || dest_port == 0) return;
    
    char dest_ip_str[32];
    snprintf(dest_ip_str, sizeof(dest_ip_str), "%u.%u.%u.%u",
             (dest_ip>>24)&0xFF, (dest_ip>>16)&0xFF, (dest_ip>>8)&0xFF, dest_ip&0xFF);
    
    const char *proto_str = (proto == PROTO_UDP) ? " (UDP)" : "";
    
    if (action == ACTION_PROXY) {
        printf("[CONN] %s (PID:%u) -> %s:%u via %s:%d%s\n", 
               process, pid, dest_ip_str, dest_port, g_proxy.proxy_host, g_proxy.proxy_port, proto_str);
    } else {
        const char *action_str = (action == ACTION_BLOCK) ? "BLOCK" : "DIRECT";
        printf("[CONN] %s (PID:%u) -> %s:%u [%s]%s\n", process, pid, dest_ip_str, dest_port, action_str, proto_str);
    }
}

static int get_original_dest_from_map(int fd, uint32_t *ip, uint16_t *port, char *process, uint32_t *pid) {
    if (!skel || !ip || !port || !process || !pid) return -1;
    
    // Iterate the map to find our connection
    uint64_t key = 0, next_key;
    struct orig_dest_info value;
    int map_fd = bpf_map__fd(skel->maps.socket_map);
    if (map_fd < 0) return -1;
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            *ip = value.ip;
            *port = value.port;
            // Secure copy with explicit bounds
            memcpy(process, value.process, 15);
            process[15] = '\0';
            *pid = value.pid;
            bpf_map_delete_elem(map_fd, &next_key);
            return 0;
        }
        key = next_key;
    }
    
    return -1;
}

static uint32_t resolve_host(const char *host) {
    if (!host || strlen(host) == 0 || strlen(host) > 255) return 0;
    
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

static int socks5_udp_associate(int s, struct sockaddr_in *relay_addr) {
    unsigned char buf[512];
    bool use_auth = (g_proxy.username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 2; buf[2] = SOCKS5_AUTH_NONE; buf[3] = SOCKS5_AUTH_USERPASS;
        if (send(s, buf, 4, 0) != 4) return -1;
    } else {
        buf[1] = 1; buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, buf, 3, 0) != 3) return -1;
    }

    if (recv(s, buf, 2, 0) != 2 || buf[0] != SOCKS5_VERSION) return -1;

    if (buf[1] == SOCKS5_AUTH_USERPASS) {
        if (!use_auth) return -1;
        int ulen = strlen(g_proxy.username), plen = strlen(g_proxy.password);
        if (ulen > 255 || plen > 255 || ulen + plen + 3 > sizeof(buf)) return -1;
        buf[0] = 0x01; buf[1] = ulen;
        memcpy(&buf[2], g_proxy.username, ulen);
        buf[2 + ulen] = plen;
        memcpy(&buf[3 + ulen], g_proxy.password, plen);
        if (send(s, buf, 3 + ulen + plen, 0) < 0) return -1;
        if (recv(s, buf, 2, 0) != 2 || buf[1] != 0x00) return -1;
    } else if (buf[1] != SOCKS5_AUTH_NONE) return -1;

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = buf[5] = buf[6] = buf[7] = 0;
    buf[8] = buf[9] = 0;

    if (send(s, buf, 10, 0) != 10) return -1;
    if (recv(s, buf, 10, 0) < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00) return -1;

    relay_addr->sin_family = AF_INET;
    memcpy(&relay_addr->sin_addr.s_addr, &buf[4], 4);
    memcpy(&relay_addr->sin_port, &buf[8], 2);

    return 0;
}

static bool establish_udp_associate(void) {
    time_t now = time(NULL);
    if (now - last_udp_connect_attempt < 5) return false;
    last_udp_connect_attempt = now;

    if (socks5_udp_socket >= 0) {
        close(socks5_udp_socket);
        socks5_udp_socket = -1;
    }
    if (socks5_udp_send_socket >= 0) {
        close(socks5_udp_send_socket);
        socks5_udp_send_socket = -1;
    }

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) return false;

    struct timeval timeout = {3, 0};
    setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    uint32_t socks5_ip = resolve_host(g_proxy.proxy_host);
    if (socks5_ip == 0) {
        close(tcp_sock);
        return false;
    }

    struct sockaddr_in socks_addr = {0};
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = htonl(socks5_ip);
    socks_addr.sin_port = htons(g_proxy.proxy_port);

    if (connect(tcp_sock, (struct sockaddr*)&socks_addr, sizeof(socks_addr)) != 0) {
        close(tcp_sock);
        return false;
    }

    if (socks5_udp_associate(tcp_sock, &socks5_udp_relay_addr) != 0) {
        close(tcp_sock);
        return false;
    }

    socks5_udp_socket = tcp_sock;

    socks5_udp_send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socks5_udp_send_socket < 0) {
        close(socks5_udp_socket);
        socks5_udp_socket = -1;
        return false;
    }

    printf("[UDP] SOCKS5 UDP ASSOCIATE established\n");
    return true;
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
    if (client_fd < 0 || proxy_fd < 0) return;
    
    fd_set rdfds;
    char buf[32768];
    int maxfd = (client_fd > proxy_fd) ? client_fd : proxy_fd;
    int idle_count = 0;
    const int IDLE_TIMEOUT = 3000;
    
    while (g_running && idle_count < IDLE_TIMEOUT) {
        FD_ZERO(&rdfds);
        FD_SET(client_fd, &rdfds);
        FD_SET(proxy_fd, &rdfds);
        struct timeval tv = {0, 100000};
        int ret = select(maxfd + 1, &rdfds, NULL, NULL, &tv);
        
        if (ret < 0) break;
        if (ret == 0) { idle_count++; continue; }
        idle_count = 0;
        
        if (FD_ISSET(client_fd, &rdfds)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(proxy_fd, buf, n, MSG_NOSIGNAL) != n) break;
        }
        if (FD_ISSET(proxy_fd, &rdfds)) {
            ssize_t n = recv(proxy_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(client_fd, buf, n, MSG_NOSIGNAL) != n) break;
        }
    }
}

static void* handle_tcp_conn(void *arg) {
    int client_fd = (int)(long)arg;
    int dest_fd = -1;
    uint32_t dest_ip;
    uint16_t dest_port;
    char process[16] = "unknown";
    uint32_t pid = 0;
    
    int opt = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    if (get_original_dest_from_map(client_fd, &dest_ip, &dest_port, process, &pid) != 0) {
        close(client_fd);
        return NULL;
    }
    
    uint8_t action = check_proxy_rules(process, dest_ip, dest_port, PROTO_TCP);
    log_connection(process, pid, dest_ip, dest_port, action, PROTO_TCP);
    
    if (action == ACTION_BLOCK) {
        close(client_fd);
        return NULL;
    }
    
    if (action == ACTION_DIRECT) {
        dest_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (dest_fd < 0) goto cleanup;
        int opt = 1;
        setsockopt(dest_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        struct sockaddr_in daddr = {0};
        daddr.sin_family = AF_INET;
        daddr.sin_addr.s_addr = htonl(dest_ip);
        daddr.sin_port = htons(dest_port);
        if (connect(dest_fd, (struct sockaddr*)&daddr, sizeof(daddr)) != 0) goto cleanup;
        forward_data(client_fd, dest_fd);
    } else {
        dest_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (dest_fd < 0) goto cleanup;
        int opt = 1;
        setsockopt(dest_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        uint32_t proxy_ip = resolve_host(g_proxy.proxy_host);
        if (proxy_ip == 0) goto cleanup;
        struct sockaddr_in paddr = {0};
        paddr.sin_family = AF_INET;
        paddr.sin_addr.s_addr = htonl(proxy_ip);
        paddr.sin_port = htons(g_proxy.proxy_port);
        if (connect(dest_fd, (struct sockaddr*)&paddr, sizeof(paddr)) != 0) goto cleanup;
        if (g_proxy.proxy_type == PROXY_TYPE_SOCKS5) {
            if (socks5_connect(dest_fd, dest_ip, dest_port) != 0) goto cleanup;
        } else {
            if (http_connect(dest_fd, dest_ip, dest_port) != 0) goto cleanup;
        }
        forward_data(client_fd, dest_fd);
    }
cleanup:
    if (dest_fd >= 0) close(dest_fd);
    close(client_fd);
    return NULL;
}

static void* tcp_relay(void *arg) {
    (void)arg;
    g_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp_fd < 0) return NULL;
    int opt = 1;
    setsockopt(g_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(g_tcp_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    int bufsize = 262144;
    setsockopt(g_tcp_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(g_tcp_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LOCAL_PROXY_PORT);
    if (bind(g_tcp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(g_tcp_fd, 512) < 0) {
        close(g_tcp_fd);
        g_tcp_fd = -1;
        return NULL;
    }
    
    while (g_running) {
        fd_set rdfds;
        FD_ZERO(&rdfds);
        FD_SET(g_tcp_fd, &rdfds);
        struct timeval tv = {0, 100000};
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
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NULL;
    }
    
    g_udp_fd = fd;
    static unsigned char recv_buf[65536];
    static unsigned char send_buf[65536];
    
    if (g_proxy.proxy_type == PROXY_TYPE_SOCKS5) {
        udp_associate_connected = establish_udp_associate();
    }
    
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int maxfd = fd;
        
        if (udp_associate_connected && socks5_udp_send_socket >= 0) {
            FD_SET(socks5_udp_send_socket, &rfds);
            if (socks5_udp_send_socket > maxfd) maxfd = socks5_udp_send_socket;
        }
        
        struct timeval tv = {0, 50000};
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;
        
        if (FD_ISSET(fd, &rfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            ssize_t n = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&client_addr, &client_len);
            if (n <= 0) continue;
            
            uint32_t dest_ip = 0;
            uint16_t dest_port = 0;
            uint32_t pid = 0;
            char process[16] = "unknown";
            
            pthread_mutex_lock(&g_conn_map_mutex);
            time_t now = time(NULL);
            for (int i = g_conn_map_count - 1; i >= 0; i--) {
                if (g_conn_map[i].proto == PROTO_UDP && (now - g_conn_map[i].timestamp) < 5) {
                    dest_ip = g_conn_map[i].dest_ip;
                    dest_port = g_conn_map[i].dest_port;
                    pid = g_conn_map[i].pid;
                    strncpy(process, g_conn_map[i].process, 16);
                    
                    if (i < g_conn_map_count - 1) {
                        memmove(&g_conn_map[i], &g_conn_map[i+1], (g_conn_map_count - i - 1) * sizeof(struct conn_info));
                    }
                    g_conn_map_count--;
                    break;
                }
            }
            pthread_mutex_unlock(&g_conn_map_mutex);
            
            if (dest_ip == 0 || dest_port == 0) continue;
            
            uint8_t action = check_proxy_rules(process, dest_ip, dest_port, PROTO_UDP);
            
            if (g_proxy.proxy_type == PROXY_TYPE_HTTP && action == ACTION_PROXY) {
                action = ACTION_DIRECT;
            }
            
            log_connection(process, pid, dest_ip, dest_port, action, PROTO_UDP);
            
            if (action == ACTION_BLOCK) continue;
            
            if (action == ACTION_DIRECT) {
                int out_fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (out_fd < 0) continue;
                
                struct sockaddr_in dest_addr = {0};
                dest_addr.sin_family = AF_INET;
                dest_addr.sin_addr.s_addr = htonl(dest_ip);
                dest_addr.sin_port = htons(dest_port);
                sendto(out_fd, recv_buf, n, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                
                fd_set r;
                struct timeval t = {1, 0};
                FD_ZERO(&r);
                FD_SET(out_fd, &r);
                if (select(out_fd + 1, &r, NULL, NULL, &t) > 0) {
                    char resp[65536];
                    ssize_t rn = recvfrom(out_fd, resp, sizeof(resp), 0, NULL, NULL);
                    if (rn > 0) sendto(fd, resp, rn, 0, (struct sockaddr*)&client_addr, client_len);
                }
                close(out_fd);
            } else {
                if (!udp_associate_connected) {
                    udp_associate_connected = establish_udp_associate();
                    if (!udp_associate_connected) continue;
                }
                
                send_buf[0] = send_buf[1] = send_buf[2] = 0;
                send_buf[3] = SOCKS5_ATYP_IPV4;
                send_buf[4] = (dest_ip >> 0) & 0xFF;
                send_buf[5] = (dest_ip >> 8) & 0xFF;
                send_buf[6] = (dest_ip >> 16) & 0xFF;
                send_buf[7] = (dest_ip >> 24) & 0xFF;
                send_buf[8] = (dest_port >> 8) & 0xFF;
                send_buf[9] = (dest_port >> 0) & 0xFF;
                memcpy(&send_buf[10], recv_buf, n);
                
                int sent = sendto(socks5_udp_send_socket, send_buf, 10 + n, 0,
                                  (struct sockaddr*)&socks5_udp_relay_addr, sizeof(socks5_udp_relay_addr));
                
                if (sent < 0) {
                    if (socks5_udp_socket >= 0) close(socks5_udp_socket);
                    if (socks5_udp_send_socket >= 0) close(socks5_udp_send_socket);
                    socks5_udp_socket = socks5_udp_send_socket = -1;
                    udp_associate_connected = false;
                }
            }
        }
        
        if (udp_associate_connected && socks5_udp_send_socket >= 0 && FD_ISSET(socks5_udp_send_socket, &rfds)) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(socks5_udp_send_socket, recv_buf, sizeof(recv_buf), 0,
                                 (struct sockaddr*)&from_addr, &from_len);
            
            if (n < 0) {
                if (socks5_udp_socket >= 0) close(socks5_udp_socket);
                if (socks5_udp_send_socket >= 0) close(socks5_udp_send_socket);
                socks5_udp_socket = socks5_udp_send_socket = -1;
                udp_associate_connected = false;
                continue;
            }
            
            if (n > 10 && recv_buf[2] == 0x00 && recv_buf[3] == SOCKS5_ATYP_IPV4) {
                sendto(fd, &recv_buf[10], n - 10, 0, (struct sockaddr*)&from_addr, from_len);
            }
        }
    }
    
    close(fd);
    return NULL;
}

// Event reader thread - stores process names from BPF
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    (void)ctx; (void)cpu;
    struct conn_event *e = (struct conn_event *)data;
    if (data_sz < sizeof(*e)) return;
    
    pthread_mutex_lock(&g_conn_map_mutex);
    if (g_conn_map_count < 1000) {
        strncpy(g_conn_map[g_conn_map_count].process, e->process_name, 16);
        g_conn_map[g_conn_map_count].pid = e->pid;
        g_conn_map[g_conn_map_count].dest_ip = e->dest_ip;
        g_conn_map[g_conn_map_count].dest_port = e->dest_port;
        g_conn_map[g_conn_map_count].proto = e->proto;
        g_conn_map[g_conn_map_count].timestamp = time(NULL);
        g_conn_map_count++;
    }
    pthread_mutex_unlock(&g_conn_map_mutex);
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
    g_cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    
    // Attach TCP hook (connect4)
    if (g_cgroup_fd < 0 || bpf_prog_attach(bpf_program__fd(skel->progs.cgroup_connect4), g_cgroup_fd, BPF_CGROUP_INET4_CONNECT, 0) != 0) {
        fprintf(stderr, "[ERROR] Failed to attach connect4\n");
        proxybridge_bpf__destroy(skel);
        skel = NULL;
        g_running = false;
        if (g_cgroup_fd >= 0) close(g_cgroup_fd);
        g_cgroup_fd = -1;
        return false;
    }
    
    // Attach UDP hook (sendmsg4)
    if (bpf_prog_attach(bpf_program__fd(skel->progs.cgroup_sendmsg4), g_cgroup_fd, BPF_CGROUP_UDP4_SENDMSG, 0) != 0) {
        fprintf(stderr, "[ERROR] Failed to attach sendmsg4\n");
        proxybridge_bpf__destroy(skel);
        skel = NULL;
        g_running = false;
        close(g_cgroup_fd);
        g_cgroup_fd = -1;
        return false;
    }
    
    printf("[BPF] Attached to cgroup\n");
    
    // Store our PID in BPF map so we can skip our own connections (prevent redirect loop)
    uint32_t key = 0;
    uint32_t our_pid = getpid();
    int relay_pid_fd = bpf_map__fd(skel->maps.relay_pid);
    bpf_map_update_elem(relay_pid_fd, &key, &our_pid, BPF_ANY);
    printf("[BPF] Stored relay PID %u to skip redirect loop\n", our_pid);
    
    pthread_create(&g_tcp_thread, NULL, tcp_relay, NULL);
    pthread_create(&g_udp_thread, NULL, udp_relay, NULL);
    pthread_create(&g_event_thread, NULL, event_reader, NULL);
    return true;
}

void ProxyBridge_Stop(void) {
    static volatile bool stopping = false;
    
    // Prevent re-entry (multiple Ctrl+C)
    if (stopping || !g_running) return;
    stopping = true;
    
    g_running = false;
    
    // Close listening sockets first to stop accepting new connections
    if (g_tcp_fd >= 0) { close(g_tcp_fd); g_tcp_fd = -1; }
    if (g_udp_fd >= 0) { close(g_udp_fd); g_udp_fd = -1; }
    
    // Detach BPF BEFORE waiting for threads (critical!)
    if (skel && g_cgroup_fd >= 0) {
        printf("[BPF] Detaching...\n");
        
        int connect4_fd = bpf_program__fd(skel->progs.cgroup_connect4);
        int sendmsg4_fd = bpf_program__fd(skel->progs.cgroup_sendmsg4);
        
        // Try to detach, ignore errors if already detached
        bpf_prog_detach2(connect4_fd, g_cgroup_fd, BPF_CGROUP_INET4_CONNECT);
        bpf_prog_detach2(sendmsg4_fd, g_cgroup_fd, BPF_CGROUP_UDP4_SENDMSG);
        
        close(g_cgroup_fd);
        g_cgroup_fd = -1;
        printf("[BPF] Detached\n");
    }
    
    // Now wait for threads to finish (they'll exit because g_running = false)
    if (g_tcp_thread) { pthread_cancel(g_tcp_thread); pthread_join(g_tcp_thread, NULL); g_tcp_thread = 0; }
    if (g_udp_thread) { pthread_cancel(g_udp_thread); pthread_join(g_udp_thread, NULL); g_udp_thread = 0; }
    if (g_event_thread) { pthread_cancel(g_event_thread); pthread_join(g_event_thread, NULL); g_event_thread = 0; }
    
    // Destroy skeleton last
    if (skel) {
        proxybridge_bpf__destroy(skel);
        skel = NULL;
    }
}

void ProxyBridge_SetProxySettings(const ProxySettings *settings) { if (settings) g_proxy = *settings; }

uint32_t ProxyBridge_AddRule(const ProxyRule *rule) {
    if (!rule) return 0;
    pthread_mutex_lock(&g_rules_mutex);
    if (g_rule_count >= 100) {
        pthread_mutex_unlock(&g_rules_mutex);
        return 0;
    }
    uint32_t id = g_next_rule_id++;
    g_rules[g_rule_count++] = *rule;
    pthread_mutex_unlock(&g_rules_mutex);
    printf("[RULE %u] %s %s:%s %s\n", id, rule->process_name, rule->target_hosts, rule->target_ports,
           rule->action == ACTION_PROXY ? "PROXY" : rule->action == ACTION_BLOCK ? "BLOCK" : "DIRECT");
    return id;
}

bool ProxyBridge_UpdateRule(uint32_t rule_id, const ProxyRule *rule) {
    if (!rule || rule_id == 0 || rule_id > g_rule_count) return false;
    pthread_mutex_lock(&g_rules_mutex);
    g_rules[rule_id - 1] = *rule;
    pthread_mutex_unlock(&g_rules_mutex);
    return true;
}

bool ProxyBridge_RemoveRule(uint32_t rule_id) {
    if (rule_id == 0 || rule_id > g_rule_count) return false;
    pthread_mutex_lock(&g_rules_mutex);
    g_rules[rule_id - 1].enabled = false;
    pthread_mutex_unlock(&g_rules_mutex);
    return true;
}

void ProxyBridge_ClearRules(void) {
    pthread_mutex_lock(&g_rules_mutex);
    memset(g_rules, 0, sizeof(g_rules));
    g_rule_count = 0;
    g_next_rule_id = 1;
    pthread_mutex_unlock(&g_rules_mutex);
}

void ProxyBridge_SetConnectionCallback(ConnectionCallback callback) { g_callback = callback; }
