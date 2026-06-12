#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <netdb.h>
#include <sys/wait.h>
#include "ProxyBridge.h"

#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011
#define MAX_PROCESS_NAME 256
#define PID_CACHE_SIZE 1024
#define PID_CACHE_TTL_MS 1000
#define NUM_PACKET_THREADS 4
#define CONNECTION_HASH_SIZE 256
#define SOCKS5_BUFFER_SIZE 1024
#define HTTP_BUFFER_SIZE 1024
#define LOG_BUFFER_SIZE 1024

// safe way to run commands without shell injection issues
static int run_command_v(const char *cmd_path, char *const argv[]) {
    pid_t pid = fork();
    if (pid == -1) {
        return -1;
    } else if (pid == 0) {
        // child process
        // send output to /dev/null so it doesnt clutter
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execvp(cmd_path, argv);
        _exit(127); // command not found or no perms
    } else {
        // parent waits for child
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return -1;
    }
}

// run iptables commands easier
static int run_iptables_cmd(const char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5, const char *arg6, const char *arg7, const char *arg8, const char *arg9, const char *arg10, const char *arg11, const char *arg12, const char *arg13, const char *arg14) {
    // build argv array skipping null args
    const char *argv[17];
    int i = 0;
    argv[i++] = "iptables";
    if (arg1) argv[i++] = arg1;
    if (arg2) argv[i++] = arg2;
    if (arg3) argv[i++] = arg3;
    if (arg4) argv[i++] = arg4;
    if (arg5) argv[i++] = arg5;
    if (arg6) argv[i++] = arg6;
    if (arg7) argv[i++] = arg7;
    if (arg8) argv[i++] = arg8;
    if (arg9) argv[i++] = arg9;
    if (arg10) argv[i++] = arg10;
    if (arg11) argv[i++] = arg11;
    if (arg12) argv[i++] = arg12;
    if (arg13) argv[i++] = arg13;
    if (arg14) argv[i++] = arg14;
    argv[i] = NULL;

    return run_command_v("iptables", (char **)argv);
}

// convert string to int safely
static int safe_atoi(const char *str) {
    if (!str) return 0;
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (endptr == str) return 0;
    return (int)val;
}


typedef struct PROCESS_RULE {
    uint32_t rule_id;
    char process_name[MAX_PROCESS_NAME];
    char *target_hosts;
    char *target_ports;
    RuleProtocol protocol;
    RuleAction action;
    bool enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_AUTH_NONE 0x00

typedef struct CONNECTION_INFO {
    uint16_t src_port;
    uint32_t src_ip;
    uint32_t orig_dest_ip;
    uint16_t orig_dest_port;
    bool is_tracked;
    uint64_t last_activity;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

typedef struct LOGGED_CONNECTION {
    uint32_t pid;
    uint32_t dest_ip;
    uint16_t dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

typedef struct PID_CACHE_ENTRY {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t pid;
    uint64_t timestamp;
    bool is_udp;
    struct PID_CACHE_ENTRY *next;
} PID_CACHE_ENTRY;

static CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
static LOGGED_CONNECTION *logged_connections = NULL;
static PROCESS_RULE *rules_list = NULL;
static uint32_t g_next_rule_id = 1;
static pthread_rwlock_t conn_lock = PTHREAD_RWLOCK_INITIALIZER;   // read-heavy connection hash
static pthread_rwlock_t rules_lock = PTHREAD_RWLOCK_INITIALIZER;  // read-heavy rules list
static pthread_mutex_t pid_cache_lock = PTHREAD_MUTEX_INITIALIZER; // PID cache only
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;       // logged connections only

typedef struct {
    int client_socket;
    uint32_t orig_dest_ip;
    uint16_t orig_dest_port;
} connection_config_t;

typedef struct {
    int from_socket;
    int to_socket;
} transfer_config_t;

static struct nfq_handle *nfq_h = NULL;
static struct nfq_q_handle *nfq_qh = NULL;
static pthread_t packet_thread[NUM_PACKET_THREADS] = {0};
static pthread_t proxy_thread = 0;
static pthread_t udp_relay_thread = 0;
static pthread_t cleanup_thread = 0;
static PID_CACHE_ENTRY *pid_cache[PID_CACHE_SIZE] = {NULL};
static bool g_has_active_rules = false;
static bool running = false;
static uint32_t g_current_process_id = 0;

// udp relay stuff
static int udp_relay_socket = -1;
static int socks5_udp_control_socket = -1;
static int socks5_udp_send_socket = -1;
static struct sockaddr_in socks5_udp_relay_addr;
static bool udp_associate_connected = false;
static uint64_t last_udp_connect_attempt = 0;

static bool g_traffic_logging_enabled = true;

static char g_proxy_host[256] = "";
static uint16_t g_proxy_port = 0;
static uint16_t g_local_relay_port = LOCAL_PROXY_PORT;
static ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
static char g_proxy_username[256] = "";
static char g_proxy_password[256] = "";
static bool g_dns_via_proxy = true;
static uint32_t g_proxy_ip_cached = 0; // Cached resolved proxy IP
static LogCallback g_log_callback = NULL;
static ConnectionCallback g_connection_callback = NULL;

static void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

static const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_slash = strrchr(path, '/');
    return last_slash ? (last_slash + 1) : path;
}

static inline char* skip_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

static void format_ip_address(uint32_t ip, char *buffer, size_t size)
{
    snprintf(buffer, size, "%d.%d.%d.%d",
        (ip >> 0) & 0xFF, (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

typedef bool (*token_match_func)(const char *token, const void *data);

static bool parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data)
{
    if (list == NULL || list[0] == '\0' || strcmp(list, "*") == 0)
        return true;

    size_t len = strlen(list) + 1;
    char *list_copy = malloc(len);
    if (list_copy == NULL)
        return false;

    memcpy(list_copy, list, len);  // copy including null terminator
    bool matched = false;
    char *saveptr = NULL;
    char *token = strtok_r(list_copy, delimiters, &saveptr);
    while (token != NULL)
    {
        token = skip_whitespace(token);

        // remove spaces at end
        size_t tlen = strlen(token);
        while (tlen > 0 && (token[tlen - 1] == ' ' || token[tlen - 1] == '\t' || token[tlen-1] == '\r' || token[tlen-1] == '\n'))
        {
            token[tlen - 1] = '\0';
            tlen--;
        }

        if (tlen > 0 && match_func(token, match_data))
        {
            matched = true;
            break;
        }
        token = strtok_r(NULL, delimiters, &saveptr);
    }
    free(list_copy);
    return matched;
}

static void configure_tcp_socket(int sock, int bufsize, int timeout_ms)
{
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct timeval timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static void configure_udp_socket(int sock, int bufsize, int timeout_ms)
{
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct timeval timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static ssize_t send_all(int sock, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) return -1;
        sent += n;
    }
    return sent;
}

static uint64_t get_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t parse_ipv4(const char *ip);
static uint32_t resolve_hostname(const char *hostname);
static int socks5_connect(int s, uint32_t dest_ip, uint16_t dest_port);
static bool match_ip_pattern(const char *pattern, uint32_t ip);
static bool match_port_pattern(const char *pattern, uint16_t port);
static bool match_ip_list(const char *ip_list, uint32_t ip);
static bool match_port_list(const char *port_list, uint16_t port);
static bool match_process_pattern(const char *pattern, const char *process_name);
static bool match_process_list(const char *process_list, const char *process_name);
static int http_connect(int s, uint32_t dest_ip, uint16_t dest_port);
static void* local_proxy_server(void *arg);
static void* connection_handler(void *arg);
static void* transfer_handler(void *arg);
static void* packet_processor(void *arg);
static uint32_t get_process_id_from_connection(uint32_t src_ip, uint16_t src_port, bool is_udp);
static bool get_process_name_from_pid(uint32_t pid, char *name, size_t name_size);
static RuleAction match_rule(const char *process_name, uint32_t dest_ip, uint16_t dest_port, bool is_udp);
static RuleAction check_process_rule(uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, bool is_udp, uint32_t *out_pid);
static void add_connection(uint16_t src_port, uint32_t src_ip, uint32_t dest_ip, uint16_t dest_port);
static bool get_connection(uint16_t src_port, uint32_t *dest_ip, uint16_t *dest_port);
static bool is_connection_tracked(uint16_t src_port);
static void cleanup_stale_connections(void);
static bool is_connection_already_logged(uint32_t pid, uint32_t dest_ip, uint16_t dest_port, RuleAction action);
static void add_logged_connection(uint32_t pid, uint32_t dest_ip, uint16_t dest_port, RuleAction action);
static void clear_logged_connections(void);
static bool is_broadcast_or_multicast(uint32_t ip);
static uint32_t get_cached_pid(uint32_t src_ip, uint16_t src_port, bool is_udp);
static void cache_pid(uint32_t src_ip, uint16_t src_port, uint32_t pid, bool is_udp);
static void clear_pid_cache(void);
static void update_has_active_rules(void);

// find which process owns a socket by checking /proc
// uses uid hint to skip processes we dont need to check
static uint32_t find_pid_from_inode(unsigned long target_inode, uint32_t uid_hint)
{
    // build the socket string we're looking for
    char expected[64];
    int expected_len = snprintf(expected, sizeof(expected), "socket:[%lu]", target_inode);

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return 0;

    uint32_t pid = 0;
    struct dirent *proc_entry;

    while ((proc_entry = readdir(proc_dir)) != NULL) {
        // skip stuff that aint a pid folder
        if (proc_entry->d_type != DT_DIR || !isdigit(proc_entry->d_name[0]))
            continue;

        // if we know the user id, skip other users processes
        // makes this way faster cuz less folders to check
        if (uid_hint != (uint32_t)-1) {
            struct stat proc_stat;
            char proc_path[280];
            snprintf(proc_path, sizeof(proc_path), "/proc/%s", proc_entry->d_name);
            if (stat(proc_path, &proc_stat) == 0 && proc_stat.st_uid != uid_hint)
                continue;
        }

        char fd_path[280];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", proc_entry->d_name);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir)
            continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            if (fd_entry->d_name[0] == '.')
                continue;

            char link_path[560];
            snprintf(link_path, sizeof(link_path), "/proc/%s/fd/%s",
                    proc_entry->d_name, fd_entry->d_name);

            char link_target[64];
            ssize_t link_len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (link_len == expected_len) {
                link_target[link_len] = '\0';
                if (memcmp(link_target, expected, expected_len) == 0) {
                    pid = (uint32_t)safe_atoi(proc_entry->d_name);
                    closedir(fd_dir);
                    closedir(proc_dir);
                    return pid;
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return pid;
}

// fast pid lookup using netlink
// tcp uses exact query, udp needs dump
static uint32_t get_process_id_from_connection(uint32_t src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t cached_pid = get_cached_pid(src_ip, src_port, is_udp);
    if (cached_pid != 0)
        return cached_pid;

    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0)
        return 0;

    // short timeout so we dont block packet flow
    struct timeval tv = {0, 100000}; // 100ms
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.r.sdiag_family = AF_INET;
    req.r.sdiag_protocol = is_udp ? IPPROTO_UDP : IPPROTO_TCP;

    // udp needs dump cuz no connection state to match on
    // tcp can filter to only syn_sent and established states
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    if (!is_udp)
        req.r.idiag_states = (1 << 2) | (1 << 3); // SYN_SENT(2) + ESTABLISHED(3) only
    else
        req.r.idiag_states = (uint32_t)-1; // All states for UDP
    req.r.idiag_ext = 0;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }

    uint32_t pid = 0;
    unsigned long target_inode = 0;
    uint32_t target_uid = (uint32_t)-1;
    bool found = false;
    char buf[16384];
    struct iovec iov = {buf, sizeof(buf)};
    struct msghdr msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};

    while (1) {
        ssize_t len = recvmsg(fd, &msg, 0);
        if (len <= 0)
            break;

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        while (NLMSG_OK(h, (size_t)len)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
                goto nl_done;

            if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                struct inet_diag_msg *r = NLMSG_DATA(h);

                // check if this is our socket
                if (r->id.idiag_src[0] == src_ip && ntohs(r->id.idiag_sport) == src_port) {
                    target_inode = r->idiag_inode;
                    target_uid = r->idiag_uid; // UID to narrow /proc scan
                    found = true;
                    goto nl_done;
                }
            }
            h = NLMSG_NEXT(h, len);
        }
    }

nl_done:
    close(fd);

    // if netlink found it, now find pid from inode
    // no need to scan /proc/net/tcp since we got inode already
    if (found && target_inode != 0) {
        pid = find_pid_from_inode(target_inode, target_uid);
    }

    // fallback for udp if netlink didnt find it
    // happens when app uses sendto without connecting socket first
    if (!found && is_udp) {
        const char* udp_files[] = {"/proc/net/udp", "/proc/net/udp6"};
        for (int file_idx = 0; file_idx < 2 && pid == 0; file_idx++) {
            FILE *fp = fopen(udp_files[file_idx], "r");
            if (!fp)
                continue;

            char line[512];
            if (!fgets(line, sizeof(line), fp)) { // skip header
                fclose(fp);
                continue;
            }
            while (fgets(line, sizeof(line), fp)) {
                unsigned int local_addr, local_port;
                unsigned long inode;
                int uid_val;

                if (sscanf(line, "%*d: %X:%X %*X:%*X %*X %*X:%*X %*X:%*X %*X %d %*d %lu",
                          &local_addr, &local_port, &uid_val, &inode) == 4) {
                    if (local_port == src_port && inode != 0) {
                        pid = find_pid_from_inode(inode, (uint32_t)uid_val);
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    if (pid != 0)
        cache_pid(src_ip, src_port, pid, is_udp);
    return pid;
}

static bool get_process_name_from_pid(uint32_t pid, char *name, size_t name_size)
{
    if (pid == 0)
        return false;

    // pid 1 is always init/systemd
    // kinda like windows pid 4 for system stuff
    if (pid == 1)
    {
        snprintf(name, name_size, "systemd");
        return true;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);

    ssize_t len = readlink(path, name, name_size - 1);
    if (len < 0)
        return false;

    name[len] = '\0';
    return true;
}

static bool match_ip_pattern(const char *pattern, uint32_t ip)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF;
    ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF;
    ip_octets[3] = (ip >> 24) & 0xFF;

    char pattern_copy[256];
    strncpy(pattern_copy, pattern, sizeof(pattern_copy) - 1);
    pattern_copy[sizeof(pattern_copy) - 1] = '\0';

    char pattern_octets[4][16];
    int octet_count = 0;
    int char_idx = 0;

    for (size_t i = 0; i <= strlen(pattern_copy) && octet_count < 4; i++)
    {
        if (pattern_copy[i] == '.' || pattern_copy[i] == '\0')
        {
            pattern_octets[octet_count][char_idx] = '\0';
            octet_count++;
            char_idx = 0;
            if (pattern_copy[i] == '\0')
                break;
        }
        else
        {
            if (char_idx < 15)
                pattern_octets[octet_count][char_idx++] = pattern_copy[i];
        }
    }

    if (octet_count != 4)
        return false;

    for (int i = 0; i < 4; i++)
    {
        if (strcmp(pattern_octets[i], "*") == 0)
            continue;

        char *dash = strchr(pattern_octets[i], '-');
        if (dash != NULL)
        {
            int start = safe_atoi(pattern_octets[i]);
            int end = safe_atoi(dash + 1);
            if (ip_octets[i] < start || ip_octets[i] > end)
                return false;
        }
        else
        {
            int pattern_val = safe_atoi(pattern_octets[i]);
            if (pattern_val != ip_octets[i])
                return false;
        }
    }
    return true;
}

static bool match_port_pattern(const char *pattern, uint16_t port)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        int start_port = safe_atoi(pattern);
        int end_port = safe_atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == safe_atoi(pattern));
}

static bool ip_match_wrapper(const char *token, const void *data)
{
    return match_ip_pattern(token, *(const uint32_t*)data);
}

static bool match_ip_list(const char *ip_list, uint32_t ip)
{
    return parse_token_list(ip_list, ";", ip_match_wrapper, &ip);
}

static bool port_match_wrapper(const char *token, const void *data)
{
    return match_port_pattern(token, *(const uint16_t*)data);
}

static bool match_port_list(const char *port_list, uint16_t port)
{
    return parse_token_list(port_list, ",;", port_match_wrapper, &port);
}

static bool match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return true;

    const char *filename = strrchr(process_full_path, '/');
    if (filename != NULL)
        filename++;
    else
        filename = process_full_path;

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    bool is_full_path_pattern = (strchr(pattern, '/') != NULL);
    const char *match_target = is_full_path_pattern ? process_full_path : filename;
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    if (pattern_len > 0 && pattern[pattern_len - 1] == '*')
    {
        return strncasecmp(pattern, match_target, pattern_len - 1) == 0;
    }

    if (pattern_len > 1 && pattern[0] == '*')
    {
        const char *pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len)
        {
            return strcasecmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return false;
    }

    return strcasecmp(pattern, match_target) == 0;
}

typedef struct {
    const char *process_name;
} process_match_data;

static bool process_match_wrapper(const char *token, const void *data)
{
    const process_match_data *pdata = data;
    return match_process_pattern(token, pdata->process_name);
}

static bool match_process_list(const char *process_list, const char *process_name)
{
    process_match_data data = {process_name};
    return parse_token_list(process_list, ";", process_match_wrapper, &data);
}

static uint32_t parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

static uint32_t resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    uint32_t ip = parse_ipv4(hostname);
    if (ip != 0)
        return ip;

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        log_message("failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
            freeaddrinfo(result);
        log_message("no ipv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    uint32_t resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    return resolved_ip;
}

static bool is_broadcast_or_multicast(uint32_t ip)
{
    // localhost
    uint8_t first_octet = (ip >> 0) & 0xFF;
    if (first_octet == 127)
        return true;

    // link-local apipa stuff
    uint8_t second_octet = (ip >> 8) & 0xFF;
    if (first_octet == 169 && second_octet == 254)
        return true;

    // broadcast
    if (ip == 0xFFFFFFFF)
        return true;

    // subnet broadcast
    if ((ip & 0xFF000000) == 0xFF000000)
        return true;

    // multicast range
    if (first_octet >= 224 && first_octet <= 239)
        return true;

    return false;
}

static RuleAction match_rule(const char *process_name, uint32_t dest_ip, uint16_t dest_port, bool is_udp)
{
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;

    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        if (rule->protocol != RULE_PROTOCOL_BOTH)
        {
            if (rule->protocol == RULE_PROTOCOL_TCP && is_udp)
            {
                rule = rule->next;
                continue;
            }
            if (rule->protocol == RULE_PROTOCOL_UDP && !is_udp)
            {
                rule = rule->next;
                continue;
            }
        }

        bool is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcasecmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            bool has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            bool has_port_filter = (strcmp(rule->target_ports, "*") != 0);

            if (has_ip_filter || has_port_filter)
            {
                if (match_ip_list(rule->target_hosts, dest_ip) &&
                    match_port_list(rule->target_ports, dest_port))
                {
                    return rule->action;
                }
                rule = rule->next;
                continue;
            }

            if (wildcard_rule == NULL)
            {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        if (match_process_list(rule->process_name, process_name))
        {
            if (match_ip_list(rule->target_hosts, dest_ip) &&
                match_port_list(rule->target_ports, dest_port))
            {
                return rule->action;
            }
        }

        rule = rule->next;
    }

    if (wildcard_rule != NULL)
    {
        return wildcard_rule->action;
    }

    return RULE_ACTION_DIRECT;
}

static RuleAction check_process_rule(uint32_t src_ip, uint16_t src_port, uint32_t dest_ip, uint16_t dest_port, bool is_udp, uint32_t *out_pid)
{
    uint32_t pid;
    char process_name[MAX_PROCESS_NAME];

    pid = get_process_id_from_connection(src_ip, src_port, is_udp);

    if (out_pid != NULL)
        *out_pid = pid;

    if (pid == 0)
        return RULE_ACTION_DIRECT;

    if (pid == g_current_process_id)
        return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    pthread_rwlock_rdlock(&rules_lock);
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp);
    pthread_rwlock_unlock(&rules_lock);

    if (action == RULE_ACTION_PROXY && is_udp && g_proxy_type == PROXY_TYPE_HTTP)
    {
        return RULE_ACTION_DIRECT;
    }
    if (action == RULE_ACTION_PROXY && (g_proxy_host[0] == '\0' || g_proxy_port == 0))
    {
        return RULE_ACTION_DIRECT;
    }

    return action;
}

static int socks5_connect(int s, uint32_t dest_ip, uint16_t dest_port)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    ssize_t len;
    bool use_auth = (g_proxy_username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;
        if (send(s, buf, 4, MSG_NOSIGNAL) != 4)
        {
            log_message("socks5 failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, buf, 3, MSG_NOSIGNAL) != 3)
        {
            log_message("socks5 failed to send auth methods");
            return -1;
        }
    }

    len = recv(s, buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
    {
        log_message("socks5 invalid auth response");
        return -1;
    }

    if (buf[1] == 0x02 && use_auth)
    {
        size_t ulen = strlen(g_proxy_username);
        size_t plen = strlen(g_proxy_password);
        buf[0] = 0x01;
        buf[1] = (unsigned char)ulen;
        memcpy(buf + 2, g_proxy_username, ulen);
        buf[2 + ulen] = (unsigned char)plen;
        memcpy(buf + 3 + ulen, g_proxy_password, plen);

        if (send(s, buf, 3 + ulen + plen, MSG_NOSIGNAL) != (ssize_t)(3 + ulen + plen))
        {
            log_message("socks5 failed to send credentials");
            return -1;
        }

        len = recv(s, buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
        {
            log_message("socks5 authentication failed");
            return -1;
        }
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("socks5 unsupported auth method");
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    memcpy(buf + 4, &dest_ip, 4);
    uint16_t port_net = htons(dest_port);
    memcpy(buf + 8, &port_net, 2);

    if (send(s, buf, 10, MSG_NOSIGNAL) != 10)
    {
        log_message("socks5 failed to send connect request");
        return -1;
    }

    len = recv(s, buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
    {
        log_message("socks5 connect failed status %d", len > 1 ? buf[1] : -1);
        return -1;
    }

    return 0;
}

static int http_connect(int s, uint32_t dest_ip, uint16_t dest_port)
{
    char buf[HTTP_BUFFER_SIZE];
    char dest_ip_str[32];
    format_ip_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

    int len = snprintf(buf, sizeof(buf),
        "CONNECT %s:%d HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Proxy-Connection: Keep-Alive\r\n",
        dest_ip_str, dest_port, dest_ip_str, dest_port);

    if (g_proxy_username[0] != '\0')
    {
        // encode user:pass in base64
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char auth_raw[512];
        int auth_raw_len = snprintf(auth_raw, sizeof(auth_raw), "%s:%s", g_proxy_username, g_proxy_password);
        char auth_b64[700];
        int j = 0;
        for (int i = 0; i < auth_raw_len; i += 3) {
            unsigned int n = ((unsigned char)auth_raw[i]) << 16;
            if (i + 1 < auth_raw_len) n |= ((unsigned char)auth_raw[i + 1]) << 8;
            if (i + 2 < auth_raw_len) n |= ((unsigned char)auth_raw[i + 2]);
            auth_b64[j++] = b64[(n >> 18) & 0x3F];
            auth_b64[j++] = b64[(n >> 12) & 0x3F];
            auth_b64[j++] = (i + 1 < auth_raw_len) ? b64[(n >> 6) & 0x3F] : '=';
            auth_b64[j++] = (i + 2 < auth_raw_len) ? b64[n & 0x3F] : '=';
        }
        auth_b64[j] = '\0';
        len += snprintf(buf + len, sizeof(buf) - len,
            "Proxy-Authorization: Basic %s\r\n", auth_b64);
    }

    len += snprintf(buf + len, sizeof(buf) - len, "\r\n");

    if (send_all(s, buf, len) < 0)
    {
        log_message("http failed to send connect");
        return -1;
    }

    ssize_t recv_len = recv(s, buf, sizeof(buf) - 1, 0);
    if (recv_len < 12)
    {
        log_message("http invalid response");
        return -1;
    }

    buf[recv_len] = '\0';
    if (strncmp(buf, "HTTP/1.", 7) != 0)
    {
        log_message("http invalid response");
        return -1;
    }

    int status_code = 0;
    if (sscanf(buf + 9, "%d", &status_code) != 1 || status_code != 200)
    {
        log_message("http connect failed status %d", status_code);
        return -1;
    }

    return 0;
}

// relay functions for production use

// connection handler like windows - blocks on connect then transfers data
static void* connection_handler(void *arg)
{
    connection_config_t *config = (connection_config_t *)arg;
    int client_sock = config->client_socket;
    uint32_t dest_ip = config->orig_dest_ip;
    uint16_t dest_port = config->orig_dest_port;
    int proxy_sock;
    struct sockaddr_in proxy_addr;
    uint32_t proxy_ip;

    free(config);

    // use cached proxy ip we resolved earlier
    proxy_ip = g_proxy_ip_cached;
    if (proxy_ip == 0)
    {
        // try resolving again if cache failed
        proxy_ip = resolve_hostname(g_proxy_host);
        if (proxy_ip == 0)
        {
            close(client_sock);
            return NULL;
        }
        g_proxy_ip_cached = proxy_ip;
    }

    proxy_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (proxy_sock < 0)
    {
        close(client_sock);
        return NULL;
    }

    configure_tcp_socket(proxy_sock, 1048576, 60000);
    configure_tcp_socket(client_sock, 1048576, 60000);

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = proxy_ip;
    proxy_addr.sin_port = htons(g_proxy_port);

    if (connect(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0)
    {
        close(client_sock);
        close(proxy_sock);
        return NULL;
    }

    // do handshake blocking
    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(proxy_sock, dest_ip, dest_port) != 0)
        {
            close(client_sock);
            close(proxy_sock);
            return NULL;
        }
    }
    else if (g_proxy_type == PROXY_TYPE_HTTP)
    {
        if (http_connect(proxy_sock, dest_ip, dest_port) != 0)
        {
            close(client_sock);
            close(proxy_sock);
            return NULL;
        }
    }

    // setup transfer config
    transfer_config_t *transfer_config = (transfer_config_t *)malloc(sizeof(transfer_config_t));
    if (transfer_config == NULL)
    {
        close(client_sock);
        close(proxy_sock);
        return NULL;
    }

    transfer_config->from_socket = client_sock;
    transfer_config->to_socket = proxy_sock;

    // transfer data both ways in this thread
    transfer_handler((void*)transfer_config);

    return NULL;
}

// relay data both ways using splice for zero-copy
// data goes kernel to kernel thru pipe, never hits userspace
// way faster than copying thru userspace buffers
static void* transfer_handler(void *arg)
{
    transfer_config_t *config = (transfer_config_t *)arg;
    int sock1 = config->from_socket;  // client socket
    int sock2 = config->to_socket;    // proxy socket
    free(config);

    // make 2 pipes for splice
    // pipe_a: proxy to client (download)
    // pipe_b: client to proxy (upload)
    int pipe_a[2] = {-1, -1};
    int pipe_b[2] = {-1, -1};

    if (pipe2(pipe_a, O_CLOEXEC | O_NONBLOCK) < 0 ||
        pipe2(pipe_b, O_CLOEXEC | O_NONBLOCK) < 0) {
        // pipe failed, cleanup and fallback
        if (pipe_a[0] >= 0) { close(pipe_a[0]); close(pipe_a[1]); }
        if (pipe_b[0] >= 0) { close(pipe_b[0]); close(pipe_b[1]); }
        goto fallback;
    }

    // make pipes bigger for better speed (64kb to 1mb)
    fcntl(pipe_a[0], F_SETPIPE_SZ, 1048576);
    fcntl(pipe_b[0], F_SETPIPE_SZ, 1048576);

    // set sockets to nonblocking for splice
    fcntl(sock1, F_SETFL, fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
    fcntl(sock2, F_SETFL, fcntl(sock2, F_GETFL, 0) | O_NONBLOCK);

    {
        struct pollfd fds[2];
        ssize_t pipe_a_bytes = 0; // bytes in download pipe (proxy→client)
        ssize_t pipe_b_bytes = 0; // bytes in upload pipe (client→proxy)
        bool sock1_done = false;  // client EOF or error
        bool sock2_done = false;  // proxy EOF or error
        bool shut_wr_sock1 = false; // already called shutdown(sock1, SHUT_WR)
        bool shut_wr_sock2 = false; // already called shutdown(sock2, SHUT_WR)

        while (1)
        {
            // build poll set, use fd=-1 to skip closed sockets
            // important: poll reports POLLHUP even with events=0
            // so use fd=-1 to actually skip it or we get busy loop
            fds[0].fd = (!sock1_done || pipe_a_bytes > 0 || pipe_b_bytes > 0) ? sock1 : -1;
            fds[1].fd = (!sock2_done || pipe_b_bytes > 0 || pipe_a_bytes > 0) ? sock2 : -1;
            fds[0].events = 0;
            fds[1].events = 0;
            fds[0].revents = 0;
            fds[1].revents = 0;

            // download: proxy to client
            if (!sock2_done && pipe_a_bytes == 0)
                fds[1].events |= POLLIN;    // read from proxy
            if (pipe_a_bytes > 0)
                fds[0].events |= POLLOUT;   // write to client

            // upload: client to proxy
            if (!sock1_done && pipe_b_bytes == 0)
                fds[0].events |= POLLIN;    // read from client
            if (pipe_b_bytes > 0)
                fds[1].events |= POLLOUT;   // write to proxy

            // all done
            if (fds[0].fd == -1 && fds[1].fd == -1)
                break;
            if (fds[0].events == 0 && fds[1].events == 0)
                break;

            int ready = poll(fds, 2, 60000);
            if (ready < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (ready == 0)
                break; // 60s idle timeout

            // check for errors and hangups
            if (fds[0].revents & POLLERR) break;
            if (fds[1].revents & POLLERR) break;

            // pollhup means other side closed
            if ((fds[1].revents & POLLHUP) && !(fds[1].revents & POLLIN))
                sock2_done = true;
            if ((fds[0].revents & POLLHUP) && !(fds[0].revents & POLLIN))
                sock1_done = true;

            // download path

            if (!sock2_done && pipe_a_bytes == 0 && (fds[1].revents & POLLIN)) {
                ssize_t n = splice(sock2, NULL, pipe_a[1], NULL, 1048576,
                                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0) {
                    pipe_a_bytes = n;
                } else if (n == 0) {
                    sock2_done = true;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    sock2_done = true;
                }
            }

            if (pipe_a_bytes > 0 && (fds[0].revents & POLLOUT)) {
                ssize_t n = splice(pipe_a[0], NULL, sock1, NULL, pipe_a_bytes,
                                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0) {
                    pipe_a_bytes -= n;
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }

            // upload path

            if (!sock1_done && pipe_b_bytes == 0 && (fds[0].revents & POLLIN)) {
                ssize_t n = splice(sock1, NULL, pipe_b[1], NULL, 1048576,
                                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0) {
                    pipe_b_bytes = n;
                } else if (n == 0) {
                    sock1_done = true;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    sock1_done = true;
                }
            }

            if (pipe_b_bytes > 0 && (fds[1].revents & POLLOUT)) {
                ssize_t n = splice(pipe_b[0], NULL, sock2, NULL, pipe_b_bytes,
                                  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
                if (n > 0) {
                    pipe_b_bytes -= n;
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }

            // half-close when one side done and pipe empty
            // tell other side with shutdown
            if (sock2_done && pipe_a_bytes == 0 && !shut_wr_sock1) {
                shutdown(sock1, SHUT_WR);
                shut_wr_sock1 = true;
            }
            if (sock1_done && pipe_b_bytes == 0 && !shut_wr_sock2) {
                shutdown(sock2, SHUT_WR);
                shut_wr_sock2 = true;
            }

            // both sides finished and pipes empty
            if (sock1_done && sock2_done && pipe_a_bytes == 0 && pipe_b_bytes == 0)
                break;
        }
    }

    close(pipe_a[0]); close(pipe_a[1]);
    close(pipe_b[0]); close(pipe_b[1]);
    goto cleanup;

fallback:
    // fallback to normal recv/send if pipes didnt work
    {
        char buf[131072];
        struct pollfd fds[2];
        fds[0].fd = sock1;
        fds[0].events = POLLIN;
        fds[1].fd = sock2;
        fds[1].events = POLLIN;

        while (1) {
            int ready = poll(fds, 2, 60000);
            if (ready <= 0) break;

            if (fds[0].revents & POLLERR || fds[1].revents & POLLERR) break;

            bool did_work = false;
            if (fds[0].revents & POLLIN) {
                ssize_t n = recv(sock1, buf, sizeof(buf), MSG_NOSIGNAL);
                if (n <= 0) break;
                if (send_all(sock2, buf, n) < 0) break;
                did_work = true;
            }
            if (fds[1].revents & POLLIN) {
                ssize_t n = recv(sock2, buf, sizeof(buf), MSG_NOSIGNAL);
                if (n <= 0) break;
                if (send_all(sock1, buf, n) < 0) break;
                did_work = true;
            }

            // pollhup with no data means peer closed
            if (!did_work) break;
        }
    }

cleanup:
    shutdown(sock1, SHUT_RDWR);
    shutdown(sock2, SHUT_RDWR);
    close(sock1);
    close(sock2);
    return NULL;
}

// proxy server accepts connections and spawns threads
static void* local_proxy_server(void *arg)
{
    (void)arg;
    struct sockaddr_in addr;
    int listen_sock;
    int on = 1;

    listen_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_sock < 0)
    {
        log_message("Socket creation failed");
        return NULL;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_local_relay_port);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_message("Bind failed");
        close(listen_sock);
        return NULL;
    }

    if (listen(listen_sock, SOMAXCONN) < 0)
    {
        log_message("Listen failed");
        close(listen_sock);
        return NULL;
    }

    // create thread attrs with small stack (256kb not 8mb)
    // relay threads dont need big buffers anymore cuz splice
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&thread_attr, 262144); // 256KB stack

    struct pollfd pfd;
    pfd.fd = listen_sock;
    pfd.events = POLLIN;

    while (running)
    {
        int ready = poll(&pfd, 1, 1000); // 1s timeout
        if (ready <= 0)
            continue;

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept4(listen_sock, (struct sockaddr *)&client_addr, &addr_len, SOCK_CLOEXEC);

        if (client_sock < 0)
            continue;

        connection_config_t *conn_config = (connection_config_t *)malloc(sizeof(connection_config_t));
        if (conn_config == NULL)
        {
            close(client_sock);
            continue;
        }

        conn_config->client_socket = client_sock;

        uint16_t client_port = ntohs(client_addr.sin_port);
        if (!get_connection(client_port, &conn_config->orig_dest_ip, &conn_config->orig_dest_port))
        {
            close(client_sock);
            free(conn_config);
            continue;
        }

        pthread_t conn_thread;
        if (pthread_create(&conn_thread, &thread_attr, connection_handler, (void*)conn_config) != 0)
        {
            close(client_sock);
            free(conn_config);
            continue;
        }
    }

    pthread_attr_destroy(&thread_attr);
    close(listen_sock);
    return NULL;
}

// socks5 udp associate
static int socks5_udp_associate(int s, struct sockaddr_in *relay_addr)
{
    unsigned char buf[512];
    ssize_t len;

    // auth handshake
    bool use_auth = (g_proxy_username[0] != '\0');
    buf[0] = SOCKS5_VERSION;
    buf[1] = use_auth ? 0x02 : 0x01;
    buf[2] = SOCKS5_AUTH_NONE;
    if (use_auth)
        buf[3] = 0x02;  // username/password auth

    if (send(s, buf, use_auth ? 4 : 3, MSG_NOSIGNAL) != (use_auth ? 4 : 3))
        return -1;

    len = recv(s, buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
        return -1;

    if (buf[1] == 0x02 && use_auth)
    {
        size_t ulen = strlen(g_proxy_username);
        size_t plen = strlen(g_proxy_password);
        buf[0] = 0x01;
        buf[1] = (unsigned char)ulen;
        memcpy(buf + 2, g_proxy_username, ulen);
        buf[2 + ulen] = (unsigned char)plen;
        memcpy(buf + 3 + ulen, g_proxy_password, plen);

        if (send(s, buf, 3 + ulen + plen, MSG_NOSIGNAL) != (ssize_t)(3 + ulen + plen))
            return -1;

        len = recv(s, buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
            return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
        return -1;

    // udp associate request
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    memset(buf + 4, 0, 4);  // 0.0.0.0
    memset(buf + 8, 0, 2);  // port 0

    if (send(s, buf, 10, MSG_NOSIGNAL) != 10)
        return -1;

    len = recv(s, buf, 512, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
        return -1;

    // get relay address
    if (buf[3] == SOCKS5_ATYP_IPV4)
    {
        memset(relay_addr, 0, sizeof(*relay_addr));
        relay_addr->sin_family = AF_INET;
        memcpy(&relay_addr->sin_addr.s_addr, buf + 4, 4);
        memcpy(&relay_addr->sin_port, buf + 8, 2);
        return 0;
    }

    return -1;
}

static bool establish_udp_associate(void)
{
    uint64_t now = get_monotonic_ms();
    if (now - last_udp_connect_attempt < 5000)
        return false;

    last_udp_connect_attempt = now;

    if (socks5_udp_control_socket >= 0)
    {
        close(socks5_udp_control_socket);
        socks5_udp_control_socket = -1;
    }
    if (socks5_udp_send_socket >= 0)
    {
        close(socks5_udp_send_socket);
        socks5_udp_send_socket = -1;
    }

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0)
        return false;

    configure_tcp_socket(tcp_sock, 262144, 3000);

    uint32_t socks5_ip = resolve_hostname(g_proxy_host);
    if (socks5_ip == 0)
    {
        close(tcp_sock);
        return false;
    }

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) < 0)
    {
        close(tcp_sock);
        return false;
    }

    if (socks5_udp_associate(tcp_sock, &socks5_udp_relay_addr) != 0)
    {
        close(tcp_sock);
        return false;
    }

    // rfc says if server gives 0.0.0.0 use proxy servers ip instead
    if (socks5_udp_relay_addr.sin_addr.s_addr == INADDR_ANY)
        socks5_udp_relay_addr.sin_addr.s_addr = socks5_ip;

    socks5_udp_control_socket = tcp_sock;

    socks5_udp_send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socks5_udp_send_socket < 0)
    {
        close(socks5_udp_control_socket);
        socks5_udp_control_socket = -1;
        return false;
    }

    configure_udp_socket(socks5_udp_send_socket, 262144, 30000);

    udp_associate_connected = true;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy");
    return true;
}

// teardown udp associate so next packet reconnects
static void teardown_udp_associate(void)
{
    udp_associate_connected = false;
    if (socks5_udp_control_socket >= 0)
    {
        close(socks5_udp_control_socket);
        socks5_udp_control_socket = -1;
    }
    if (socks5_udp_send_socket >= 0)
    {
        close(socks5_udp_send_socket);
        socks5_udp_send_socket = -1;
    }
}

static void* udp_relay_server(void *arg)
{
    (void)arg;
    struct sockaddr_in local_addr, from_addr;
    unsigned char recv_buf[65536];
    unsigned char send_buf[65536];
    socklen_t from_len;

    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket < 0)
        return NULL;

    int on = 1;
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    configure_udp_socket(udp_relay_socket, 262144, 30000);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);

    if (bind(udp_relay_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        close(udp_relay_socket);
        udp_relay_socket = -1;
        return NULL;
    }

    // try initial connect, not fatal if proxy not up yet
    udp_associate_connected = establish_udp_associate();

    while (running)
    {
        struct pollfd fds[3];
        int nfds = 1;

        // watch local relay socket for client packets
        fds[0].fd = udp_relay_socket;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        // watch socks5 udp socket for proxy responses
        fds[1].fd = (udp_associate_connected && socks5_udp_send_socket >= 0) ? socks5_udp_send_socket : -1;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        // watch socks5 tcp socket to detect if connection dies
        fds[2].fd = (udp_associate_connected && socks5_udp_control_socket >= 0) ? socks5_udp_control_socket : -1;
        fds[2].events = POLLIN;
        fds[2].revents = 0;
        nfds = 3;

        int ready = poll(fds, nfds, 1000); // 1s timeout
        if (ready <= 0)
            continue;

        // check if tcp control still alive
        // if it dies the udp associate is dead too
        if (fds[2].fd >= 0 && (fds[2].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            char peek_buf[1];
            ssize_t peek_len = recv(socks5_udp_control_socket, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
            if (peek_len == 0 || (peek_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
            {
                // tcp died, proxy is gone
                teardown_udp_associate();
                continue;
            }
        }

        // client sending to proxy
        if (fds[0].revents & POLLIN)
        {
            from_len = sizeof(from_addr);
            ssize_t recv_len = recvfrom(udp_relay_socket, recv_buf, sizeof(recv_buf), 0,
                                        (struct sockaddr *)&from_addr, &from_len);
            if (recv_len <= 0)
                continue;

            // try to connect if not connected yet
            if (!udp_associate_connected)
            {
                if (!establish_udp_associate())
                    continue;
            }

            uint16_t client_port = ntohs(from_addr.sin_port);
            uint32_t dest_ip;
            uint16_t dest_port;

            if (!get_connection(client_port, &dest_ip, &dest_port))
                continue;

            // make sure data fits with socks5 header
            if (recv_len > (ssize_t)(sizeof(send_buf) - 10))
                continue;

            // build socks5 udp packet header
            send_buf[0] = 0x00;  // RSV
            send_buf[1] = 0x00;  // RSV
            send_buf[2] = 0x00;  // FRAG
            send_buf[3] = SOCKS5_ATYP_IPV4;
            memcpy(send_buf + 4, &dest_ip, 4);
            uint16_t port_net = htons(dest_port);
            memcpy(send_buf + 8, &port_net, 2);
            memcpy(send_buf + 10, recv_buf, recv_len);

            ssize_t sent = sendto(socks5_udp_send_socket, send_buf, 10 + recv_len, 0,
                   (struct sockaddr *)&socks5_udp_relay_addr, sizeof(socks5_udp_relay_addr));

            // if send fails proxy died, teardown and retry later
            if (sent < 0)
            {
                teardown_udp_associate();
            }
        }

        // proxy sending back to client
        if (fds[1].fd >= 0 && (fds[1].revents & POLLIN))
        {
            from_len = sizeof(from_addr);
            ssize_t recv_len = recvfrom(socks5_udp_send_socket, recv_buf, sizeof(recv_buf), 0,
                                        (struct sockaddr *)&from_addr, &from_len);

            // socket error, proxy might be dead
            if (recv_len < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    teardown_udp_associate();
                continue;
            }
            if (recv_len < 10)
                continue;

            // we dont support fragmented packets
            if (recv_buf[2] != 0x00)
                continue;

            // parse socks5 udp packet
            if (recv_buf[3] != SOCKS5_ATYP_IPV4)
                continue;

            uint32_t src_ip;
            uint16_t src_port;
            memcpy(&src_ip, recv_buf + 4, 4);
            memcpy(&src_port, recv_buf + 8, 2);
            src_port = ntohs(src_port);

            // find which client sent packet to this destination
            // loop thru hash table looking for dest match
            pthread_rwlock_rdlock(&conn_lock);

            struct sockaddr_in client_addr;
            bool found_client = false;

            for (int hash = 0; hash < CONNECTION_HASH_SIZE; hash++)
            {
                CONNECTION_INFO *conn = connection_hash_table[hash];
                while (conn != NULL)
                {
                    if (conn->orig_dest_ip == src_ip &&
                        conn->orig_dest_port == src_port)
                    {
                        // found it, send response back to original client port
                        memset(&client_addr, 0, sizeof(client_addr));
                        client_addr.sin_family = AF_INET;
                        client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        client_addr.sin_port = htons(conn->src_port);
                        found_client = true;
                        break;
                    }
                    conn = conn->next;
                }
                if (found_client)
                    break;
            }

            pthread_rwlock_unlock(&conn_lock);

            if (found_client)
            {
                // send unwrapped data back to client
                ssize_t data_len = recv_len - 10;
                sendto(udp_relay_socket, recv_buf + 10, data_len, 0,
                       (struct sockaddr *)&client_addr, sizeof(client_addr));
            }
        }

        // handle errors on udp send socket
        if (fds[1].fd >= 0 && (fds[1].revents & (POLLHUP | POLLERR)))
        {
            teardown_udp_associate();
        }
    }

    teardown_udp_associate();
    if (udp_relay_socket >= 0)
        close(udp_relay_socket);

    return NULL;
}

// nfqueue callback for packets
static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    if (!ph) return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);

    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfad, &payload);
    if (payload_len < (int)sizeof(struct iphdr))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct iphdr *iph = (struct iphdr *)payload;

    // fast path when no rules
    if (!g_has_active_rules && g_connection_callback == NULL)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    uint32_t src_ip = iph->saddr;
    uint32_t dest_ip = iph->daddr;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    RuleAction action = RULE_ACTION_DIRECT;
    uint32_t pid = 0;

    if (iph->protocol == IPPROTO_TCP)
    {
        if (payload_len < (int)(iph->ihl * 4 + sizeof(struct tcphdr)))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        struct tcphdr *tcph = (struct tcphdr *)(payload + iph->ihl * 4);
        src_port = ntohs(tcph->source);
        dest_port = ntohs(tcph->dest);

        // skip our own packets from local relay
        if (src_port == g_local_relay_port)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (is_connection_tracked(src_port))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        // only look at syn packets for new connections
        if (!(tcph->syn && !tcph->ack))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (dest_port == 53 && !g_dns_via_proxy)
            action = RULE_ACTION_DIRECT;
        else
            action = check_process_rule(src_ip, src_port, dest_ip, dest_port, false, &pid);

        if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(dest_ip))
            action = RULE_ACTION_DIRECT;

        // log it if not from our own process
        if (g_traffic_logging_enabled && g_connection_callback != NULL && (tcph->syn && !tcph->ack) && pid > 0 && pid != g_current_process_id)
        {
            char process_name[MAX_PROCESS_NAME];
            if (get_process_name_from_pid(pid, process_name, sizeof(process_name)))
            {
                if (!is_connection_already_logged(pid, dest_ip, dest_port, action))
                {
                    char dest_ip_str[32];
                    format_ip_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                    char proxy_info[300];
                    if (action == RULE_ACTION_PROXY)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "proxy %s://%s:%d tcp",
                            g_proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5",
                            g_proxy_host, g_proxy_port);
                    }
                    else if (action == RULE_ACTION_DIRECT)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "direct tcp");
                    }
                    else if (action == RULE_ACTION_BLOCK)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "blocked tcp");
                    }

                    const char* display_name = extract_filename(process_name);
                    g_connection_callback(display_name, pid, dest_ip_str, dest_port, proxy_info);

                    add_logged_connection(pid, dest_ip, dest_port, action);
                }
            }
        }

        if (action == RULE_ACTION_DIRECT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        else if (action == RULE_ACTION_BLOCK)
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        else if (action == RULE_ACTION_PROXY)
        {
            // store connection info
            add_connection(src_port, src_ip, dest_ip, dest_port);

            // mark packet so nat table REDIRECT rule will catch it
            uint32_t mark = 1;
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
        }
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        if (payload_len < (int)(iph->ihl * 4 + sizeof(struct udphdr)))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        struct udphdr *udph = (struct udphdr *)(payload + iph->ihl * 4);
        src_port = ntohs(udph->source);
        dest_port = ntohs(udph->dest);

        if (src_port == LOCAL_UDP_RELAY_PORT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (is_connection_tracked(src_port))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (dest_port == 53 && !g_dns_via_proxy)
            action = RULE_ACTION_DIRECT;
        else
            action = check_process_rule(src_ip, src_port, dest_ip, dest_port, true, &pid);

        if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(dest_ip))
            action = RULE_ACTION_DIRECT;

        if (action == RULE_ACTION_PROXY && (dest_port == 67 || dest_port == 68))
            action = RULE_ACTION_DIRECT;

        // UDP proxy only works with SOCKS5, not HTTP
        if (action == RULE_ACTION_PROXY && g_proxy_type != PROXY_TYPE_SOCKS5)
            action = RULE_ACTION_DIRECT;

        // log (skip our own process, log even without PID for ephemeral UDP sockets)
        if (g_traffic_logging_enabled && g_connection_callback != NULL && pid != g_current_process_id)
        {
            char process_name[MAX_PROCESS_NAME];
            uint32_t log_pid = (pid == 0) ? 1 : pid;  // Use PID 1 for unknown processes

            if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
            {
                // Got process name from PID
            }
            else
            {
                // UDP socket not found - ephemeral or timing issue
                snprintf(process_name, sizeof(process_name), "unknown");
            }

            if (!is_connection_already_logged(log_pid, dest_ip, dest_port, action))
            {
                    char dest_ip_str[32];
                    format_ip_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                    char proxy_info[300];
                    if (action == RULE_ACTION_PROXY)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "proxy socks5://%s:%d udp",
                            g_proxy_host, g_proxy_port);
                    }
                    else if (action == RULE_ACTION_DIRECT)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "direct udp");
                    }
                    else if (action == RULE_ACTION_BLOCK)
                    {
                        snprintf(proxy_info, sizeof(proxy_info), "blocked udp");
                    }

                    const char* display_name = extract_filename(process_name);
                    g_connection_callback(display_name, log_pid, dest_ip_str, dest_port, proxy_info);

                    add_logged_connection(log_pid, dest_ip, dest_port, action);
                }
        }

        if (action == RULE_ACTION_DIRECT)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        else if (action == RULE_ACTION_BLOCK)
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        else if (action == RULE_ACTION_PROXY)
        {
            // UDP proxy via SOCKS5 UDP ASSOCIATE
            add_connection(src_port, src_ip, dest_ip, dest_port);

            // Mark UDP packet for redirect to local UDP relay (port 34011)
            uint32_t mark = 2;  // Use mark=2 for UDP (mark=1 is for TCP)
            return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static void* packet_processor(void *arg)
{
    (void)arg;
    char buf[4096] __attribute__((aligned));
    int fd = nfq_fd(nfq_h);
    ssize_t rv;

    while (running)
    {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0)
            nfq_handle_packet(nfq_h, buf, rv);
        // On error: ENOBUFS = kernel queue full (normal under load),
        // EINTR = signal, other = transient. Always continue -
        // stopping the thread would break all network traffic.
    }

    return NULL;
}

static inline uint32_t connection_hash(uint16_t port)
{
    return port % CONNECTION_HASH_SIZE;
}

static void add_connection(uint16_t src_port, uint32_t src_ip, uint32_t dest_ip, uint16_t dest_port)
{
    uint32_t hash = connection_hash(src_port);
    pthread_rwlock_wrlock(&conn_lock);

    CONNECTION_INFO *conn = connection_hash_table[hash];
    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            conn->orig_dest_ip = dest_ip;
            conn->orig_dest_port = dest_port;
            conn->src_ip = src_ip;
            conn->is_tracked = true;
            conn->last_activity = get_monotonic_ms();
            pthread_rwlock_unlock(&conn_lock);
            return;
        }
        conn = conn->next;
    }

    CONNECTION_INFO *new_conn = malloc(sizeof(CONNECTION_INFO));
    if (new_conn != NULL)
    {
        new_conn->src_port = src_port;
        new_conn->src_ip = src_ip;
        new_conn->orig_dest_ip = dest_ip;
        new_conn->orig_dest_port = dest_port;
        new_conn->is_tracked = true;
        new_conn->last_activity = get_monotonic_ms();
        new_conn->next = connection_hash_table[hash];
        connection_hash_table[hash] = new_conn;
    }

    pthread_rwlock_unlock(&conn_lock);
}

static bool get_connection(uint16_t src_port, uint32_t *dest_ip, uint16_t *dest_port)
{
    uint32_t hash = connection_hash(src_port);
    pthread_rwlock_rdlock(&conn_lock);

    CONNECTION_INFO *conn = connection_hash_table[hash];
    while (conn != NULL)
    {
        if (conn->src_port == src_port && conn->is_tracked)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            conn->last_activity = get_monotonic_ms(); // benign race on timestamp
            pthread_rwlock_unlock(&conn_lock);
            return true;
        }
        conn = conn->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return false;
}

static bool is_connection_tracked(uint16_t src_port)
{
    uint32_t hash = connection_hash(src_port);
    pthread_rwlock_rdlock(&conn_lock);

    CONNECTION_INFO *conn = connection_hash_table[hash];
    while (conn != NULL)
    {
        if (conn->src_port == src_port && conn->is_tracked)
        {
            pthread_rwlock_unlock(&conn_lock);
            return true;
        }
        conn = conn->next;
    }

    pthread_rwlock_unlock(&conn_lock);
    return false;
}

static void __attribute__((unused)) remove_connection(uint16_t src_port)
{
    uint32_t hash = connection_hash(src_port);
    pthread_rwlock_wrlock(&conn_lock);

    CONNECTION_INFO **conn_ptr = &connection_hash_table[hash];
    while (*conn_ptr != NULL)
    {
        if ((*conn_ptr)->src_port == src_port)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            free(to_free);
            pthread_rwlock_unlock(&conn_lock);
            return;
        }
        conn_ptr = &(*conn_ptr)->next;
    }

    pthread_rwlock_unlock(&conn_lock);
}

static void cleanup_stale_connections(void)
{
    uint64_t now = get_monotonic_ms();

    // Cleanup connection hash table
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        pthread_rwlock_wrlock(&conn_lock);
        CONNECTION_INFO **conn_ptr = &connection_hash_table[i];

        while (*conn_ptr != NULL)
        {
            if (now - (*conn_ptr)->last_activity > 60000)  // 60 sec timeout
            {
                CONNECTION_INFO *to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                free(to_free);
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        pthread_rwlock_unlock(&conn_lock);
    }

    // Cleanup PID cache (separate lock - no contention with connection lookups)
    uint64_t now_cache = get_monotonic_ms();
    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        pthread_mutex_lock(&pid_cache_lock);
        PID_CACHE_ENTRY **entry_ptr = &pid_cache[i];
        while (*entry_ptr != NULL)
        {
            if (now_cache - (*entry_ptr)->timestamp > 10000)  // 10 sec cache TTL
            {
                PID_CACHE_ENTRY *to_free = *entry_ptr;
                *entry_ptr = (*entry_ptr)->next;
                free(to_free);
            }
            else
            {
                entry_ptr = &(*entry_ptr)->next;
            }
        }
        pthread_mutex_unlock(&pid_cache_lock);
    }

    // Keep only last 100 logged connections
    pthread_mutex_lock(&log_lock);
    int logged_count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL)
    {
        logged_count++;
        temp = temp->next;
    }

    if (logged_count > 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 99 && temp != NULL; i++)
        {
            temp = temp->next;
        }
        if (temp != NULL && temp->next != NULL)
        {
            LOGGED_CONNECTION *to_free = temp->next;
            temp->next = NULL;
            while (to_free != NULL)
            {
                LOGGED_CONNECTION *next = to_free->next;
                free(to_free);
                to_free = next;
            }
        }
    }
    pthread_mutex_unlock(&log_lock);
}

static bool is_connection_already_logged(uint32_t pid, uint32_t dest_ip, uint16_t dest_port, RuleAction action)
{
    pthread_mutex_lock(&log_lock);

    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid && logged->dest_ip == dest_ip &&
            logged->dest_port == dest_port && logged->action == action)
        {
            pthread_mutex_unlock(&log_lock);
            return true;
        }
        logged = logged->next;
    }

    pthread_mutex_unlock(&log_lock);
    return false;
}

static void add_logged_connection(uint32_t pid, uint32_t dest_ip, uint16_t dest_port, RuleAction action)
{
    pthread_mutex_lock(&log_lock);

    // keep only last 100 entries to avoid memory growth
    int count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL && count < 100)
    {
        count++;
        temp = temp->next;
    }

    if (count >= 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 98 && temp != NULL; i++)
        {
            temp = temp->next;
        }

        if (temp != NULL && temp->next != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;

            // Free excess entries (still under log_lock, but this is rare)
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
        }
    }

    LOGGED_CONNECTION *logged = malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->dest_ip = dest_ip;
        logged->dest_port = dest_port;
        logged->action = action;
        logged->next = logged_connections;
        logged_connections = logged;
    }

    pthread_mutex_unlock(&log_lock);
}

static void clear_logged_connections(void)
{
    pthread_mutex_lock(&log_lock);

    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }

    pthread_mutex_unlock(&log_lock);
}

static uint32_t pid_cache_hash(uint32_t src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t hash = src_ip ^ ((uint32_t)src_port << 16) ^ (is_udp ? 0x80000000 : 0);
    return hash % PID_CACHE_SIZE;
}

static uint32_t get_cached_pid(uint32_t src_ip, uint16_t src_port, bool is_udp)
{
    uint32_t hash = pid_cache_hash(src_ip, src_port, is_udp);
    uint64_t current_time = get_monotonic_ms();
    uint32_t pid = 0;

    pthread_mutex_lock(&pid_cache_lock);

    PID_CACHE_ENTRY *entry = pid_cache[hash];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->src_port == src_port &&
            entry->is_udp == is_udp)
        {
            if (current_time - entry->timestamp < PID_CACHE_TTL_MS)
            {
                pid = entry->pid;
                break;
            }
            else
            {
                break;
            }
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&pid_cache_lock);
    return pid;
}

static void cache_pid(uint32_t src_ip, uint16_t src_port, uint32_t pid, bool is_udp)
{
    uint32_t hash = pid_cache_hash(src_ip, src_port, is_udp);
    uint64_t current_time = get_monotonic_ms();

    pthread_mutex_lock(&pid_cache_lock);

    PID_CACHE_ENTRY *entry = pid_cache[hash];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->src_port == src_port &&
            entry->is_udp == is_udp)
        {
            entry->pid = pid;
            entry->timestamp = current_time;
            pthread_mutex_unlock(&pid_cache_lock);
            return;
        }
        entry = entry->next;
    }

    PID_CACHE_ENTRY *new_entry = malloc(sizeof(PID_CACHE_ENTRY));
    if (new_entry != NULL)
    {
        new_entry->src_ip = src_ip;
        new_entry->src_port = src_port;
        new_entry->pid = pid;
        new_entry->timestamp = current_time;
        new_entry->is_udp = is_udp;
        new_entry->next = pid_cache[hash];
        pid_cache[hash] = new_entry;
    }

    pthread_mutex_unlock(&pid_cache_lock);
}

static void clear_pid_cache(void)
{
    pthread_mutex_lock(&pid_cache_lock);

    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        while (pid_cache[i] != NULL)
        {
            PID_CACHE_ENTRY *to_free = pid_cache[i];
            pid_cache[i] = pid_cache[i]->next;
            free(to_free);
        }
    }

    pthread_mutex_unlock(&pid_cache_lock);
}

static void* cleanup_worker(void *arg)
{
    (void)arg;
    while (running)
    {
        sleep(30);  // 30 seconds
        if (running)
        {
            cleanup_stale_connections();
        }
    }
    return NULL;
}

static void update_has_active_rules(void)
{
    g_has_active_rules = false;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->enabled)
        {
            g_has_active_rules = true;
            break;
        }
        rule = rule->next;
    }
}

uint32_t ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    if (process_name == NULL || process_name[0] == '\0')
        return 0;

    PROCESS_RULE *rule = malloc(sizeof(PROCESS_RULE));
    if (rule == NULL)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';
    rule->protocol = protocol;

    if (target_hosts != NULL && target_hosts[0] != '\0')
    {
        rule->target_hosts = strdup(target_hosts);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
    }
    else
    {
        rule->target_hosts = strdup("*");
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
    }

    if (target_ports != NULL && target_ports[0] != '\0')
    {
        rule->target_ports = strdup(target_ports);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
    }
    else
    {
        rule->target_ports = strdup("*");
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
    }

    rule->action = action;
    rule->enabled = true;

    pthread_rwlock_wrlock(&rules_lock);
    rule->next = rules_list;
    rules_list = rule;
    update_has_active_rules();
    pthread_rwlock_unlock(&rules_lock);

    log_message("added rule id %u for process %s protocol %d action %d", rule->rule_id, process_name, protocol, action);

    return rule->rule_id;
}

bool ProxyBridge_EnableRule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = true;
            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("enabled rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool ProxyBridge_DisableRule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = false;
            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("disabled rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool ProxyBridge_DeleteRule(uint32_t rule_id)
{
    if (rule_id == 0)
        return false;

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;

    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            if (prev == NULL)
                rules_list = rule->next;
            else
                prev->next = rule->next;

            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);

            if (rule->target_hosts != NULL)
                free(rule->target_hosts);
            if (rule->target_ports != NULL)
                free(rule->target_ports);
            free(rule);

            log_message("deleted rule id %u", rule_id);
            return true;
        }
        prev = rule;
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);
    return false;
}

bool ProxyBridge_EditRule(uint32_t rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    if (rule_id == 0 || process_name == NULL || target_hosts == NULL || target_ports == NULL)
        return false;

    // Pre-allocate new strings before taking lock to minimize hold time
    char *new_hosts = strdup(target_hosts);
    char *new_ports = strdup(target_ports);
    if (new_hosts == NULL || new_ports == NULL)
    {
        free(new_hosts);
        free(new_ports);
        return false;
    }

    pthread_rwlock_wrlock(&rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
            rule->process_name[MAX_PROCESS_NAME - 1] = '\0';

            free(rule->target_hosts);
            rule->target_hosts = new_hosts;

            free(rule->target_ports);
            rule->target_ports = new_ports;

            rule->protocol = protocol;
            rule->action = action;

            update_has_active_rules();
            pthread_rwlock_unlock(&rules_lock);
            log_message("updated rule id %u", rule_id);
            return true;
        }
        rule = rule->next;
    }
    pthread_rwlock_unlock(&rules_lock);

    // Rule not found - free pre-allocated strings
    free(new_hosts);
    free(new_ports);
    return false;
}

bool ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, uint16_t proxy_port, const char* username, const char* password)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return false;

    g_proxy_ip_cached = resolve_hostname(proxy_ip);
    if (g_proxy_ip_cached == 0)
        return false;

    strncpy(g_proxy_host, proxy_ip, sizeof(g_proxy_host) - 1);
    g_proxy_host[sizeof(g_proxy_host) - 1] = '\0';
    g_proxy_port = proxy_port;
    g_proxy_type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;

    if (username != NULL)
    {
        strncpy(g_proxy_username, username, sizeof(g_proxy_username) - 1);
        g_proxy_username[sizeof(g_proxy_username) - 1] = '\0';
    }
    else
    {
        g_proxy_username[0] = '\0';
    }

    if (password != NULL)
    {
        strncpy(g_proxy_password, password, sizeof(g_proxy_password) - 1);
        g_proxy_password[sizeof(g_proxy_password) - 1] = '\0';
    }
    else
    {
        g_proxy_password[0] = '\0';
    }

    log_message("proxy configured %s %s:%d", type == PROXY_TYPE_HTTP ? "http" : "socks5", proxy_ip, proxy_port);
    return true;
}

void ProxyBridge_SetDnsViaProxy(bool enable)
{
    g_dns_via_proxy = enable;
    log_message("dns via proxy %s", enable ? "enabled" : "disabled");
}

void ProxyBridge_SetLogCallback(LogCallback callback)
{
    g_log_callback = callback;
}

void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

void ProxyBridge_SetTrafficLoggingEnabled(bool enable)
{
    g_traffic_logging_enabled = enable;
}

void ProxyBridge_ClearConnectionLogs(void)
{
    clear_logged_connections();
}

bool ProxyBridge_Start(void)
{
    if (running)
        return false;

    running = true;
    g_current_process_id = getpid();

    // Ignore SIGPIPE - send() on a closed socket must return EPIPE, not kill the process
    signal(SIGPIPE, SIG_IGN);

    // Raise system socket buffer limits for high throughput (requires root)
    // Default rmem_max/wmem_max is usually 208KB, far too small for >100Mbps
    FILE *fp;
    fp = fopen("/proc/sys/net/core/rmem_max", "w");
    if (fp) { fprintf(fp, "4194304"); fclose(fp); } // 4MB
    fp = fopen("/proc/sys/net/core/wmem_max", "w");
    if (fp) { fprintf(fp, "4194304"); fclose(fp); } // 4MB

    if (pthread_create(&proxy_thread, NULL, local_proxy_server, NULL) != 0)
    {
        running = false;
        return false;
    }

    if (pthread_create(&cleanup_thread, NULL, cleanup_worker, NULL) != 0)
    {
        running = false;
        pthread_cancel(proxy_thread);
        pthread_join(proxy_thread, NULL);
        proxy_thread = 0;
        return false;
    }

    // Start UDP relay server if SOCKS5 proxy
    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (pthread_create(&udp_relay_thread, NULL, udp_relay_server, NULL) != 0)
        {
            log_message("failed to create UDP relay thread");
        }
    }

    nfq_h = nfq_open();
    if (!nfq_h)
    {
        log_message("nfq_open failed");
        goto start_fail;
    }

    if (nfq_unbind_pf(nfq_h, AF_INET) < 0)
    {
        log_message("nfq_unbind_pf failed");
    }

    if (nfq_bind_pf(nfq_h, AF_INET) < 0)
    {
        log_message("nfq_bind_pf failed");
        nfq_close(nfq_h);
        nfq_h = NULL;
        goto start_fail;
    }

    nfq_qh = nfq_create_queue(nfq_h, 0, &packet_callback, NULL);
    if (!nfq_qh)
    {
        log_message("nfq_create_queue failed");
        nfq_close(nfq_h);
        nfq_h = NULL;
        goto start_fail;
    }

    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        log_message("nfq_set_mode failed");
        nfq_destroy_queue(nfq_qh);
        nfq_qh = NULL;
        nfq_close(nfq_h);
        nfq_h = NULL;
        goto start_fail;
    }

    // Set larger queue length for better performance (16384 like Windows)
    nfq_set_queue_maxlen(nfq_qh, 16384);

    // setup iptables rules for packet interception - USE MANGLE table so it runs BEFORE nat
    log_message("setting up iptables rules");
    // mangle table runs before nat, so we can mark packets there.
    // Exclude loopback first: local (lo) traffic must never be queued and reinjected,
    // otherwise non-trivial 127.0.0.0/8 responses stall. Loopback never needs proxying.
    int ret0 = run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL);
    int ret1 = run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);
    int ret2 = run_iptables_cmd("-t", "mangle", "-A", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);

    if (ret0 != 0 || ret1 != 0 || ret2 != 0) {
        log_message("failed to add iptables rules ret0=%d ret1=%d ret2=%d", ret0, ret1, ret2);
    } else {
        log_message("iptables nfqueue rules added successfully");
    }

    // setup nat redirect for marked packets
    int ret3 = run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    int ret4 = run_iptables_cmd("-t", "nat", "-A", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    if (ret3 != 0 || ret4 != 0) {
        log_message("failed to add nat redirect rules");
    }

    (void)ret3;
    (void)ret4;

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (pthread_create(&packet_thread[i], NULL, packet_processor, NULL) != 0)
        {
            log_message("failed to create packet thread %d", i);
        }
    }

    log_message("proxybridge started");
    return true;

start_fail:
    running = false;
    if (proxy_thread != 0) { pthread_cancel(proxy_thread); pthread_join(proxy_thread, NULL); proxy_thread = 0; }
    if (cleanup_thread != 0) { pthread_cancel(cleanup_thread); pthread_join(cleanup_thread, NULL); cleanup_thread = 0; }
    if (udp_relay_thread != 0) { pthread_cancel(udp_relay_thread); pthread_join(udp_relay_thread, NULL); udp_relay_thread = 0; }
    return false;
}

bool ProxyBridge_Stop(void)
{
    if (!running)
        return false;

    running = false;

    // cleanup iptables
    int ret0 = run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL);
    int ret1 = run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);
    int ret2 = run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);
    int ret3 = run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
    int ret4 = run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    (void)ret0;
    (void)ret1;
    (void)ret2;
    (void)ret3;
    (void)ret4;

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (packet_thread[i] != 0)
        {
            pthread_cancel(packet_thread[i]);
            pthread_join(packet_thread[i], NULL);
            packet_thread[i] = 0;
        }
    }

    if (nfq_qh)
    {
        nfq_destroy_queue(nfq_qh);
        nfq_qh = NULL;
    }

    if (nfq_h)
    {
        nfq_close(nfq_h);
        nfq_h = NULL;
    }

    if (proxy_thread != 0)
    {
        pthread_cancel(proxy_thread);
        pthread_join(proxy_thread, NULL);
        proxy_thread = 0;
    }

    if (udp_relay_thread != 0)
    {
        pthread_cancel(udp_relay_thread);
        pthread_join(udp_relay_thread, NULL);
        udp_relay_thread = 0;
    }

    if (cleanup_thread != 0)
    {
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, NULL);
        cleanup_thread = 0;
    }

    // Free all connections in hash table
    pthread_rwlock_wrlock(&conn_lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != NULL)
        {
            CONNECTION_INFO *to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            free(to_free);
        }
    }
    pthread_rwlock_unlock(&conn_lock);

    // Free all rules
    pthread_rwlock_wrlock(&rules_lock);
    while (rules_list != NULL)
    {
        PROCESS_RULE *to_free = rules_list;
        rules_list = rules_list->next;
        free(to_free->target_hosts);
        free(to_free->target_ports);
        free(to_free);
    }
    g_has_active_rules = false;
    g_next_rule_id = 1;
    pthread_rwlock_unlock(&rules_lock);

    clear_logged_connections();
    clear_pid_cache();

    log_message("proxybridge stopped");
    return true;
}

int ProxyBridge_TestConnection(const char* target_host, uint16_t target_port, char* result_buffer, size_t buffer_size)
{
    int test_sock = -1;
    struct sockaddr_in proxy_addr;
    uint32_t target_ip;
    int ret = -1;
    char temp_buffer[512];

    if (g_proxy_host[0] == '\0' || g_proxy_port == 0)
    {
        snprintf(result_buffer, buffer_size, "error no proxy configured");
        return -1;
    }

    if (target_host == NULL || target_host[0] == '\0')
    {
        snprintf(result_buffer, buffer_size, "error invalid target host");
        return -1;
    }

    snprintf(temp_buffer, sizeof(temp_buffer), "testing connection to %s:%d via %s proxy %s:%d\n",
        target_host, target_port,
        g_proxy_type == PROXY_TYPE_HTTP ? "http" : "socks5",
        g_proxy_host, g_proxy_port);
    strncpy(result_buffer, temp_buffer, buffer_size - 1);
    result_buffer[buffer_size - 1] = '\0';

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int gai_ret = getaddrinfo(target_host, NULL, &hints, &res);
    if (gai_ret != 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to resolve hostname %s: %s\n",
                target_host, gai_strerror(gai_ret));
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        return -1;
    }
    target_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    snprintf(temp_buffer, sizeof(temp_buffer), "resolved %s to %d.%d.%d.%d\n",
        target_host,
        (target_ip >> 0) & 0xFF, (target_ip >> 8) & 0xFF,
        (target_ip >> 16) & 0xFF, (target_ip >> 24) & 0xFF);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    test_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (test_sock < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error socket creation failed\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        return -1;
    }

    configure_tcp_socket(test_sock, 65536, 10000);

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = resolve_hostname(g_proxy_host);
    proxy_addr.sin_port = htons(g_proxy_port);

    snprintf(temp_buffer, sizeof(temp_buffer), "connecting to proxy %s:%d\n", g_proxy_host, g_proxy_port);
    strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);

    if (connect(test_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to connect to proxy\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        close(test_sock);
        return -1;
    }

    strncat(result_buffer, "connected to proxy server\n", buffer_size - strlen(result_buffer) - 1);

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error socks5 handshake failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            close(test_sock);
            return -1;
        }
        strncat(result_buffer, "socks5 handshake successful\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        if (http_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error http connect failed\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            close(test_sock);
            return -1;
        }
        strncat(result_buffer, "http connect successful\n", buffer_size - strlen(result_buffer) - 1);
    }

    char http_request[512];
    snprintf(http_request, sizeof(http_request),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: ProxyBridge/1.0\r\n"
        "\r\n", target_host);

    if (send_all(test_sock, http_request, strlen(http_request)) < 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to send test request\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        close(test_sock);
        return -1;
    }

    strncat(result_buffer, "sent http get request\n", buffer_size - strlen(result_buffer) - 1);
    char response[1024];
    ssize_t bytes_received = recv(test_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0';

        if (strstr(response, "HTTP/") != NULL)
        {
            char* status_line = strstr(response, "HTTP/");
            int status_code = 0;
            if (status_line != NULL)
            {
                sscanf(status_line, "HTTP/%*s %d", &status_code);
            }

            snprintf(temp_buffer, sizeof(temp_buffer), "success received http %d response %ld bytes\n", status_code, (long)bytes_received);
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = 0;
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "error received data but not valid http response\n");
            strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
            ret = -1;
        }
    }
    else
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "error failed to receive response\n");
        strncat(result_buffer, temp_buffer, buffer_size - strlen(result_buffer) - 1);
        ret = -1;
    }

    close(test_sock);

    if (ret == 0)
    {
        strncat(result_buffer, "\nproxy connection test passed\n", buffer_size - strlen(result_buffer) - 1);
    }
    else
    {
        strncat(result_buffer, "\nproxy connection test failed\n", buffer_size - strlen(result_buffer) - 1);
    }

    return ret;
}

// Library destructor - automatically cleanup when library is unloaded
__attribute__((destructor))
static void library_cleanup(void)
{
    if (running)
    {
        log_message("library unloading - cleaning up automatically");
        ProxyBridge_Stop();
    }
    else
    {
        // Even if not running, ensure iptables rules are removed
        // This handles cases where the app crashed before calling Stop
        run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL);
        run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);
        run_iptables_cmd("-t", "mangle", "-D", "OUTPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", "0", NULL, NULL, NULL, NULL);
        run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "mark", "--mark", "1", "-j", "REDIRECT", "--to-port", "34010");
        run_iptables_cmd("-t", "nat", "-D", "OUTPUT", "-p", "udp", "-m", "mark", "--mark", "2", "-j", "REDIRECT", "--to-port", "34011");
    }
}
