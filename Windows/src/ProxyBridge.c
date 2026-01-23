#include <winsock2.h>
#include <windows.h>
#include "ProxyBridge.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAXBUF 0xFFFF
#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011  // its running UDP port still make sure to not run on same port as TCP, opening same port and tcp and udp cause issue and handling port at relay server response injection
#define MAX_PROCESS_NAME 256
#define VERSION "3.1.0"
#define PID_CACHE_SIZE 1024
#define PID_CACHE_TTL_MS 1000
#define NUM_PACKET_THREADS 4
#define CONNECTION_HASH_SIZE 256
#define SOCKS5_BUFFER_SIZE 1024
#define HTTP_BUFFER_SIZE 1024
#define FILTER_BUFFER_SIZE 512
#define LOG_BUFFER_SIZE 1024

typedef struct PROCESS_RULE {
    UINT32 rule_id;
    char process_name[MAX_PROCESS_NAME];
    char *target_hosts;   // Dynamic: IP filter "*", "192.168.*.*", "10.0.0.1;172.16.0.0"
    char *target_ports;   // Dynamic: Port filter "*", "80", "80;443", "8000-9000"
    RuleProtocol protocol;  // TCP, UDP, or BOTH
    RuleAction action;
    BOOL enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_AUTH_NONE 0x00

typedef struct CONNECTION_INFO {
    UINT16 src_port;
    UINT32 src_ip;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    BOOL is_tracked;
    ULONGLONG last_activity;  // GetTickCount64() timestamp for cleanup
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

typedef struct {
    SOCKET client_socket;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
} CONNECTION_CONFIG;

typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

// Track logged connections to avoid dupli
typedef struct LOGGED_CONNECTION {
    DWORD pid;
    UINT32 dest_ip;
    UINT16 dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

// Impoved slow speed due to PID checking // Added pid cache
typedef struct PID_CACHE_ENTRY {
    UINT32 src_ip;
    UINT16 src_port;
    DWORD pid;
    DWORD timestamp;
    BOOL is_udp;
    struct PID_CACHE_ENTRY *next;
} PID_CACHE_ENTRY;

static CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
static LOGGED_CONNECTION *logged_connections = NULL;
static PROCESS_RULE *rules_list = NULL;
static UINT32 g_next_rule_id = 1;
static HANDLE lock = NULL;
static HANDLE windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE packet_thread[NUM_PACKET_THREADS] = {NULL};
static HANDLE proxy_thread = NULL;
static HANDLE udp_relay_thread = NULL;
static HANDLE cleanup_thread = NULL;
static PID_CACHE_ENTRY *pid_cache[PID_CACHE_SIZE] = {NULL};
static BOOL g_has_active_rules = FALSE;
static SOCKET udp_relay_socket = INVALID_SOCKET;
static SOCKET socks5_udp_socket = INVALID_SOCKET;
static SOCKET socks5_udp_send_socket = INVALID_SOCKET;
static struct sockaddr_in socks5_udp_relay_addr;
static BOOL udp_associate_connected = FALSE;
static DWORD last_udp_connect_attempt = 0;
static BOOL running = FALSE;
static DWORD g_current_process_id = 0;

static BOOL g_traffic_logging_enabled = TRUE;

static char g_proxy_host[256] = "";  // Can be IP address or hostname
static UINT16 g_proxy_port = 0;
static UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
static ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
static char g_proxy_username[256] = "";
static char g_proxy_password[256] = "";
static BOOL g_dns_via_proxy = TRUE;
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

// Extract filename from full path  C:\path\chrome.exe  >> chrome.exe
static const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

static inline char* skip_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

static void format_ip_address(UINT32 ip, char *buffer, size_t size)
{
    snprintf(buffer, size, "%d.%d.%d.%d",
        (ip >> 0) & 0xFF, (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

typedef BOOL (*token_match_func)(const char *token, const void *data);

static BOOL parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data)
{
    if (list == NULL || list[0] == '\0' || strcmp(list, "*") == 0)
        return TRUE;

    size_t len = strlen(list) + 1;
    char *list_copy = (char *)malloc(len);
    if (list_copy == NULL)
        return FALSE;

    strncpy_s(list_copy, len, list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, delimiters, &context);
    while (token != NULL)
    {
        token = skip_whitespace(token);
        if (match_func(token, match_data))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, delimiters, &context);
    }
    free(list_copy);
    return matched;
}

static void configure_tcp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}

static void configure_udp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}

static int send_all(SOCKET sock, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n == SOCKET_ERROR) return SOCKET_ERROR;
        sent += n;
    }
    return sent;
}

static UINT32 parse_ipv4(const char *ip);
static UINT32 resolve_hostname(const char *hostname);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static int socks5_udp_associate(SOCKET s, struct sockaddr_in *relay_addr);
static DWORD WINAPI udp_relay_server(LPVOID arg);
static BOOL match_ip_pattern(const char *pattern, UINT32 ip);
static BOOL match_port_pattern(const char *pattern, UINT16 port);
static BOOL match_ip_list(const char *ip_list, UINT32 ip);
static BOOL match_port_list(const char *port_list, UINT16 port);
static BOOL match_process_pattern(const char *pattern, const char *process_name);
static BOOL match_process_list(const char *process_list, const char *process_name);
static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port);
static DWORD WINAPI local_proxy_server(LPVOID arg);
static DWORD WINAPI connection_handler(LPVOID arg);
static DWORD WINAPI transfer_handler(LPVOID arg);
static DWORD WINAPI packet_processor(LPVOID arg);
static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
static DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port);
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp);
static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, DWORD *out_pid);
static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port);
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
static BOOL is_connection_tracked(UINT16 src_port);
static void remove_connection(UINT16 src_port);
static void cleanup_stale_connections(void);
static BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
static void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
static void clear_logged_connections(void);
static BOOL is_broadcast_or_multicast(UINT32 ip);
static DWORD get_cached_pid(UINT32 src_ip, UINT16 src_port, BOOL is_udp);
static void cache_pid(UINT32 src_ip, UINT16 src_port, DWORD pid, BOOL is_udp);
static void clear_pid_cache(void);
static void update_has_active_rules(void);


static DWORD WINAPI packet_processor(LPVOID arg)
{
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    while (running)
    {
        if (!WinDivertRecv(windivert_handle, packet, sizeof(packet), &packet_len, &addr))
        {
            if (GetLastError() == ERROR_INVALID_HANDLE)
                break;
            log_message("Failed to receive packet (%lu)", GetLastError());
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
            NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        if (ip_header == NULL)
            continue;

        if (udp_header != NULL && tcp_header == NULL)
        {
            if (addr.Outbound)
            {
                if (udp_header->SrcPort == htons(LOCAL_UDP_RELAY_PORT))
                {
                    UINT16 dst_port = ntohs(udp_header->DstPort);
                    UINT32 orig_dest_ip;
                    UINT16 orig_dest_port;

                    if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                    {
                        // Restore both source IP and port to original destination
                        ip_header->SrcAddr = orig_dest_ip;
                        udp_header->SrcPort = htons(orig_dest_port);
                    }                    addr.Outbound = FALSE;
                }
                else if (is_connection_tracked(ntohs(udp_header->SrcPort)))
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    UINT32 temp_addr = ip_header->DstAddr;
                    udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }
                else
                {
                    UINT16 src_port = ntohs(udp_header->SrcPort);
                    UINT32 src_ip = ip_header->SrcAddr;
                    UINT32 dest_ip = ip_header->DstAddr;
                    UINT16 dest_port = ntohs(udp_header->DstPort);

                    // if no rule configuree all connection direct with no checks avoid unwanted memory and pocessing whcich could delay
                    if (!g_has_active_rules && g_connection_callback == NULL)
                    {
                        // No rules and no logging - pass through immediately (no checksum needed for unmodified packets)
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }

                    RuleAction action;
                    DWORD pid = 0;

                    if (dest_port == 53 && !g_dns_via_proxy)
                        action = RULE_ACTION_DIRECT;
                    else
                        action = check_process_rule(src_ip, src_port, dest_ip, dest_port, TRUE, &pid);

                    // Override PROXY to DIRECT for critical IPs and ports
                    if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(dest_ip))
                        action = RULE_ACTION_DIRECT;

                    // Override PROXY to DIRECT for DHCP ports (67=server, 68=client)
                    if (action == RULE_ACTION_PROXY && (dest_port == 67 || dest_port == 68))
                        action = RULE_ACTION_DIRECT;

                    // only log if callback is set
                    // reuse pid from check_process_rule
                    // CLI use no log flag
                    if (g_connection_callback != NULL && pid > 0)
                    {
                        char process_name[MAX_PROCESS_NAME];

                        if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                        {
                            if (!is_connection_already_logged(pid, dest_ip, dest_port, action))
                            {
                                char dest_ip_str[32];
                                format_ip_address(dest_ip, dest_ip_str, sizeof(dest_ip_str));

                                char proxy_info[128];
                                if (action == RULE_ACTION_PROXY)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy SOCKS5://%s:%d (UDP)",
                                        g_proxy_host, g_proxy_port);
                                }
                                else if (action == RULE_ACTION_DIRECT)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Direct (UDP)");
                                }
                                else if (action == RULE_ACTION_BLOCK)
                                {
                                    snprintf(proxy_info, sizeof(proxy_info), "Blocked (UDP)");
                                }

                                const char* display_name = extract_filename(process_name);
                                g_connection_callback(display_name, pid, dest_ip_str, dest_port, proxy_info);

                                if (g_traffic_logging_enabled)
                                {
                                    add_logged_connection(pid, dest_ip, dest_port, action);
                                }
                            }
                        }
                    }

                    if (action == RULE_ACTION_BLOCK)
                    {
                        continue;
                    }

                    if (action == RULE_ACTION_PROXY)
                    {
                        add_connection(src_port, src_ip, dest_ip, dest_port);

                        // dest to rely udp
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);

                        // Set destination to localhost (127.0.0.1)
                        ip_header->DstAddr = htonl(INADDR_LOOPBACK);

                        // Keep source IP unchanged
                        addr.Outbound = FALSE;

                    }
                }
            }
            else
            {
                if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT))
                {
                    // Unmodified packet no checksum needed
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

            }

            // Modified UDP packet calculate checksums
            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
            WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
            continue;
        }        // TCP packets only from here
        if (tcp_header == NULL)
            continue;

        if (addr.Outbound)
        {
            if (tcp_header->SrcPort == htons(g_local_relay_port))
            {
                UINT16 dst_port = ntohs(tcp_header->DstPort);
                UINT32 orig_dest_ip;
                UINT16 orig_dest_port;

                if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                    tcp_header->SrcPort = htons(orig_dest_port);

                UINT32 temp_addr = ip_header->DstAddr;
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;

                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(dst_port);
            }
            else if (is_connection_tracked(ntohs(tcp_header->SrcPort)))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);

                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(src_port);

                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
            }
            else
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT32 src_ip = ip_header->SrcAddr;
                UINT32 orig_dest_ip = ip_header->DstAddr;
                UINT16 orig_dest_port = ntohs(tcp_header->DstPort);

                // avoid rule pocess and packet process if no rules
                if (!g_has_active_rules && g_connection_callback == NULL)
                {
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }

                RuleAction action;
                DWORD pid = 0;

                if (orig_dest_port == 53 && !g_dns_via_proxy)
                    action = RULE_ACTION_DIRECT;
                else
                    action = check_process_rule(src_ip, src_port, orig_dest_ip, orig_dest_port, FALSE, &pid);

                // Override PROXY to DIRECT for criticl ips
                if (action == RULE_ACTION_PROXY && is_broadcast_or_multicast(orig_dest_ip))
                    action = RULE_ACTION_DIRECT;

                // only new TCP/SYN inital fist packet
                if (g_connection_callback != NULL && tcp_header->Syn && !tcp_header->Ack && pid > 0)
                {
                    char process_name[MAX_PROCESS_NAME];
                    if (pid > 0 && get_process_name_from_pid(pid, process_name, sizeof(process_name)))
                    {
                        if (!is_connection_already_logged(pid, orig_dest_ip, orig_dest_port, action))
                        {
                            char dest_ip_str[32];
                            snprintf(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
                                (orig_dest_ip >> 0) & 0xFF, (orig_dest_ip >> 8) & 0xFF,
                                (orig_dest_ip >> 16) & 0xFF, (orig_dest_ip >> 24) & 0xFF);

                            char proxy_info[128];
                            if (action == RULE_ACTION_PROXY)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d",
                                    g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                    g_proxy_host, g_proxy_port);
                            }
                            else if (action == RULE_ACTION_DIRECT)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Direct");
                            }
                            else if (action == RULE_ACTION_BLOCK)
                            {
                                snprintf(proxy_info, sizeof(proxy_info), "Blocked");
                            }

                            const char* display_name = extract_filename(process_name);
                            g_connection_callback(display_name, pid, dest_ip_str, orig_dest_port, proxy_info);

                            if (g_traffic_logging_enabled)
                            {
                                add_logged_connection(pid, orig_dest_ip, orig_dest_port, action);
                            }
                        }
                    }
                }

                if (action == RULE_ACTION_DIRECT)
                {
                    // Unmodified packet no checksum needed
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
                else if (action == RULE_ACTION_BLOCK)
                {
                    // Drop the packet - don't send it anywhere
                    continue;
                }
                else if (action == RULE_ACTION_PROXY)
            {
                add_connection(src_port, src_ip, orig_dest_ip, orig_dest_port);

                UINT32 temp_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(g_local_relay_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = temp_addr;
                addr.Outbound = FALSE;
                }
            }
        }
        else
        {
            if (tcp_header->DstPort != htons(g_local_relay_port))
            {
                // Unmodified return packet no checksum needed
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                continue;
            }
        }

        // Modified TCP packet calculate checksums
        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr))
        {
            log_message("Failed to send packet (%lu)", GetLastError());
        }
    }

    return 0;
}

static UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf_s(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

// Resolve hostname to IPv4 address (supports both IP addresses and domain names)
static UINT32 resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // First try to parse as IP address
    UINT32 ip = parse_ipv4(hostname);
    if (ip != 0)
        return ip;

    // Not an IP address, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
            freeaddrinfo(result);
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    log_message("Resolved %s to %d.%d.%d.%d", hostname,
        (resolved_ip >> 0) & 0xFF, (resolved_ip >> 8) & 0xFF,
        (resolved_ip >> 16) & 0xFF, (resolved_ip >> 24) & 0xFF);

    return resolved_ip;
}

static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port)
{
    // check cache first
    DWORD cached_pid = get_cached_pid(src_ip, src_port, FALSE);
    if (cached_pid != 0)
        return cached_pid;

    MIB_TCPTABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
    {
        return 0;
    }

    tcp_table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (tcp_table == NULL)
    {
        return 0;
    }

    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
    {
        free(tcp_table);
        return 0;
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++)
    {
        MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];

        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
        {
            pid = row->dwOwningPid;
            break;
        }
    }

    free(tcp_table);

    // store cache the result
    if (pid != 0)
        cache_pid(src_ip, src_port, pid, FALSE);

    return pid;
}

// Get process ID for UDP connection
static DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port)
{
    DWORD cached_pid = get_cached_pid(src_ip, src_port, TRUE);
    if (cached_pid != 0)
        return cached_pid;

    MIB_UDPTABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    DWORD pid = 0;

    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
    {
        return 0;
    }

    udp_table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (udp_table == NULL)
    {
        return 0;
    }

    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
    {
        free(udp_table);
        return 0;
    }

    // First pass: Try exact match (IP + port)
    for (DWORD i = 0; i < udp_table->dwNumEntries; i++)
    {
        MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];

        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
        {
            pid = row->dwOwningPid;
            break;
        }
    }

    // Second pass: If not found, try matching port on 0.0.0.0 (INADDR_ANY)
    // Many UDP applications bind to 0.0.0.0:port instead of specific IP
    if (pid == 0)
    {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++)
        {
            MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];

            if (row->dwLocalAddr == 0 &&  // 0.0.0.0 (INADDR_ANY)
                ntohs((UINT16)row->dwLocalPort) == src_port)
            {
                pid = row->dwOwningPid;
                break;
            }
        }
    }

    free(udp_table);

    if (pid != 0)
        cache_pid(src_ip, src_port, pid, TRUE);

    return pid;
}


static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size)
{
    HANDLE hProcess;
    char full_path[MAX_PATH];
    DWORD path_len = MAX_PATH;

    if (pid == 0)
    {
        return FALSE;
    }

    // ERROR in getting process name for PID 4 reserved by system
    // SMB is managed by system process
    if (pid == 4)
    {
        strncpy_s(name, name_size, "System", _TRUNCATE);
        return TRUE;
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL)
    {
        return FALSE;
    }

    if (QueryFullProcessImageNameA(hProcess, 0, full_path, &path_len))
    {


        strncpy_s(name, name_size, full_path, _TRUNCATE);
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

// Match IP pattern against IP address
// Supports: "*" (all), "192.168.1.1" (exact), "192.168.*.*" (wildcard)
static BOOL match_ip_pattern(const char *pattern, UINT32 ip)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract 4 octets from IP (little-endian)
    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF;
    ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF;
    ip_octets[3] = (ip >> 24) & 0xFF;

    // Parse pattern manually
    char pattern_copy[256];
    strncpy_s(pattern_copy, sizeof(pattern_copy), pattern, _TRUNCATE);

    char pattern_octets[4][16];
    int octet_count = 0;
    int char_idx = 0;

    for (int i = 0; i <= (int)strlen(pattern_copy) && octet_count < 4; i++)
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
        return FALSE;

    for (int i = 0; i < 4; i++)
    {
        if (strcmp(pattern_octets[i], "*") == 0)
            continue;
        int pattern_val = atoi(pattern_octets[i]);
        if (pattern_val != ip_octets[i])
            return FALSE;
    }
    return TRUE;
}

// Match port pattern: "*", "80", "8000-9000"
static BOOL match_port_pattern(const char *pattern, UINT16 port)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        int start_port = atoi(pattern);
        int end_port = atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == atoi(pattern));
}

static BOOL ip_match_wrapper(const char *token, const void *data)
{
    return match_ip_pattern(token, *(const UINT32*)data);
}

// Match IP list: "192.168.*.*;10.0.0.1"
static BOOL match_ip_list(const char *ip_list, UINT32 ip)
{
    return parse_token_list(ip_list, ";", ip_match_wrapper, &ip);
}

static BOOL port_match_wrapper(const char *token, const void *data)
{
    return match_port_pattern(token, *(const UINT16*)data);
}

// Match port list: "80;443;8000-9000"
static BOOL match_port_list(const char *port_list, UINT16 port)
{
    return parse_token_list(port_list, ",;", port_match_wrapper, &port);
}

// Match process name with wildcard support
// Supports: "*" (all),
// "chrome.exe" (exact), "fire*.exe" (wildcard), "*.bin" (extension wildcard)
// added support for full paths - C:\Program Files\Google\Chrome\Application\chrome.exe
// Nedd to Test all combination at sanme time
static BOOL match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract just the filename from the full path for comparison
    // Windows path sucks
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL)
        filename++; // Skip the backslash
    else
        filename = process_full_path; // No path separator, use as-is

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    // Check if pattern contains path separators (backslash or forward slash)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);

    // check if pattern has path seperator match for full path
    const char *match_target = is_full_path_pattern ? process_full_path : filename; // match against filename only
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    // check for * at the end: "fire*" or "C:\Program Files\*"
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*')
    {
        // Match prefix: "fire*" matches "firefox.exe"
        return _strnicmp(pattern, match_target, pattern_len - 1) == 0;
    }

    // Check for wildcard at the beginning: "*.exe"
    if (pattern_len > 1 && pattern[0] == '*')
    {
        // Match suffix: "*.exe" matches "chrome.exe"
        const char *pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len)
        {
            return _stricmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return FALSE;
    }

    // check for *  in the middle: "fire*.exe" or C:\Program Files\*\chrome.exe
    const char *star = strchr(pattern, '*');
    if (star != NULL)
    {
        size_t prefix_len = star - pattern;
        const char *suffix = star + 1;
        size_t suffix_len = strlen(suffix);

        // Check prefix matches
        if (_strnicmp(pattern, match_target, prefix_len) != 0)
            return FALSE;

        if (target_len < prefix_len + suffix_len)
            return FALSE;

        return _stricmp(match_target + target_len - suffix_len, suffix) == 0;
    }

    // No * , use case insensitive
    return _stricmp(pattern, match_target) == 0;
}

// Match process list: "chrome.exe;firefox.exe;*.bin"
static BOOL match_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0)
        return TRUE;

    size_t len = strlen(process_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (list_copy == NULL)
        return FALSE;

    strncpy_s(list_copy, len, process_list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;

    // Support both semicolon and comma as separators - Need to figure complex rules in CLI parsing
    char *token = strtok_s(list_copy, ",;", &context);
    while (token != NULL)
    {
        // Skip leading whitespace
        while (*token == ' ' || *token == '\t')
            token++;

        // Remove trailing whitespace   // this shit cause error in CLI parsing
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t'))
        {
            *end = '\0';
            end--;
        }

        // Remove quotes if present: "C:\some app.exe"  - Need to carefully handle this in CLI app
        if (*token == '"' && strlen(token) > 1)
        {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL)
                *quote = '\0';
        }

        if (match_process_pattern(token, process_name))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, ",;", &context);
    }
    free(list_copy);
    return matched;
}


static BOOL is_broadcast_or_multicast(UINT32 ip)
{
    // Localhost: 127.0.0.0/8 (127.x.x.x)
    BYTE first_octet = (ip >> 0) & 0xFF;
    if (first_octet == 127)
        return TRUE;

    // APIPA (Link-Local): 169.254.0.0/16 (169.254.x.x)
    BYTE second_octet = (ip >> 8) & 0xFF;
    if (first_octet == 169 && second_octet == 254)
        return TRUE;

    // Broadcast: 255.255.255.255
    if (ip == 0xFFFFFFFF)
        return TRUE;

    // x.x.x.255
    if ((ip & 0xFF000000) == 0xFF000000)
        return TRUE;

    // Multicast: 224.0.0.0 - 239.255.255.255 (first octet 224-239)
    if (first_octet >= 224 && first_octet <= 239)
        return TRUE;

    return FALSE;
}

// Unified rule matching function for both TCP and UDP
// Matches rules by process name, IP, port, and protocol
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp)
{
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;  // Save fully wildcard rule for last

    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        // Check protocol compatibility
        // RULE_PROTOCOL_BOTH (0x03) matches both TCP and UDP
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

        // Check if this is a wildcard process rule
        BOOL is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            // Check if wildcard has specific filters
            BOOL has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            BOOL has_port_filter = (strcmp(rule->target_ports, "*") != 0);

            if (has_ip_filter || has_port_filter)
            {
                // Filtered wildcard - check if it matches
                if (match_ip_list(rule->target_hosts, dest_ip) &&
                    match_port_list(rule->target_ports, dest_port))
                {
                    // Matched! Return this rule's action
                    return rule->action;
                }
                // Didn't match, continue
                rule = rule->next;
                continue;
            }

            // Fully wildcard rule (no filters) - save for later
            if (wildcard_rule == NULL)
            {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        // Check if process name matches
        if (match_process_list(rule->process_name, process_name))
        {
            // Process matched! Check IP and port filters
            if (match_ip_list(rule->target_hosts, dest_ip) &&
                match_port_list(rule->target_ports, dest_port))
            {
                // All filters matched! Return this rule's action
                return rule->action;
            }
        }

        rule = rule->next;
    }

    // No specific rule matched, use wildcard if available
    if (wildcard_rule != NULL)
    {
        return wildcard_rule->action;
    }

    // No rule matched at all
    return RULE_ACTION_DIRECT;
}

static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, DWORD *out_pid)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];

    pid = is_udp ? get_process_id_from_udp_connection(src_ip, src_port) : get_process_id_from_connection(src_ip, src_port);
    if (pid == 0 && is_udp)
        pid = get_process_id_from_connection(src_ip, src_port);

        // this may cause issues - need to find alternative
    if (out_pid != NULL)
        *out_pid = pid;

    if (pid == 0)
        return RULE_ACTION_DIRECT;

    // Auto-exclude: Always bypass the process that loaded this DLL (prevents loops)
    if (pid == g_current_process_id)
        return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    // Use unified rule matching function
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp);

    // Additional checks for proxy configuration
    if (action == RULE_ACTION_PROXY && is_udp && g_proxy_type == PROXY_TYPE_HTTP)
    {
        return RULE_ACTION_DIRECT;  // HTTP proxy doesn't support UDP
    }
    if (action == RULE_ACTION_PROXY && (g_proxy_host[0] == '\0' || g_proxy_port == 0))
    {
        return RULE_ACTION_DIRECT;  // No proxy configured
    }

    return action;
}


static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;  // Username/password auth
        if (send(s, (char*)buf, 4, 0) != 4)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }

    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
    {
        log_message("SOCKS5: Invalid auth response");
        return -1;
    }

    // Handle authentication
    if (buf[1] == 0x02)  // Username/password required
    {
        if (!use_auth)
        {
            log_message("SOCKS5: Server requires authentication but no credentials provided");
            return -1;
        }

        // Send username/password (RFC 1929)
        size_t user_len = strlen(g_proxy_username);
        size_t pass_len = strlen(g_proxy_password);
        if (user_len > 255 || pass_len > 255)
        {
            log_message("SOCKS5: Username or password too long");
            return -1;
        }

        buf[0] = 0x01;  // Version of username/password auth
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], g_proxy_username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], g_proxy_password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
        {
            log_message("SOCKS5: Failed to send credentials");
            return -1;
        }

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
        {
            log_message("SOCKS5: Authentication failed");
            return -1;
        }
        log_message("SOCKS5: Authentication successful");
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("SOCKS5: Unsupported auth method: 0x%02X", buf[1]);
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = (dest_ip >> 0) & 0xFF;
    buf[5] = (dest_ip >> 8) & 0xFF;
    buf[6] = (dest_ip >> 16) & 0xFF;
    buf[7] = (dest_ip >> 24) & 0xFF;
    buf[8] = (dest_port >> 8) & 0xFF;
    buf[9] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 10, 0) != 10)
    {
        log_message("SOCKS5: Failed to send CONNECT");
        return -1;
    }

    len = recv(s, (char*)buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
    {
        log_message("SOCKS5: CONNECT failed (reply=%d)", len > 1 ? buf[1] : -1);
        return -1;
    }

    return 0;
}



static void base64_encode(const char* input, char* output, size_t output_size)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strlen(input);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3)
    {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port)
{
    char request[HTTP_BUFFER_SIZE];
    char response[4096];
    int len;
    char *status_line;
    int status_code;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    if (use_auth)
    {
        // Create "username:password" string and encode as Base64
        char credentials[SOCKS5_BUFFER_SIZE];
        char encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", g_proxy_username, g_proxy_password);
        base64_encode(credentials, encoded, sizeof(encoded));

        char ip_str[32];
        format_ip_address(dest_ip, ip_str, sizeof(ip_str));
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            ip_str, dest_port, ip_str, dest_port, encoded);
    }
    else
    {
        char ip_str[32];
        format_ip_address(dest_ip, ip_str, sizeof(ip_str));
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            ip_str, dest_port, ip_str, dest_port);
    }

    if (send(s, request, len, 0) != len)
    {
        log_message("HTTP: Failed to send CONNECT request");
        return -1;
    }

    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0)
    {
        log_message("HTTP: Failed to receive response");
        return -1;
    }
    response[len] = '\0';

    status_line = response;
    if (strncmp(status_line, "HTTP/1.", 7) != 0)
    {
        log_message("HTTP: Invalid response format");
        return -1;
    }

    status_code = 0;
    char *code_start = strchr(status_line, ' ');
    if (code_start != NULL)
        status_code = atoi(code_start + 1);

    if (status_code != 200)
    {
        log_message("HTTP: CONNECT failed with status %d", status_code);
        return -1;
    }

    return 0;
}

static int socks5_udp_associate(SOCKET s, struct sockaddr_in *relay_addr)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (g_proxy_username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;
        if (send(s, (char*)buf, 4, 0) != 4)
            return -1;
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
            return -1;
    }

    len = recv(s, (char*)buf, 2, 0);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
        return -1;

    if (buf[1] == 0x02)
    {
        if (!use_auth)
            return -1;

        size_t user_len = strlen(g_proxy_username);
        size_t pass_len = strlen(g_proxy_password);
        if (user_len > 255 || pass_len > 255)
            return -1;

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], g_proxy_username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], g_proxy_password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
            return -1;

        len = recv(s, (char*)buf, 2, 0);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
            return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;

    if (send(s, (char*)buf, 10, 0) != 10)
        return -1;

    len = recv(s, (char*)buf, 10, 0);
    if (len < 10 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00)
        return -1;

    relay_addr->sin_family = AF_INET;
    relay_addr->sin_addr.s_addr = *(UINT32*)&buf[4];
    relay_addr->sin_port = *(UINT16*)&buf[8];

    return 0;
}

// connect UDP ASSOCIATE with SOCKS5 proxy
// Need to monitor the System memory and CPU usage
static BOOL establish_udp_associate(void)
{
    // Prevent retry spam - only try every 5 seconds
    ULONGLONG now = GetTickCount64();
    if (now - last_udp_connect_attempt < 5000)
        return FALSE;

    last_udp_connect_attempt = now;

    // Close existing connections if any
    if (socks5_udp_socket != INVALID_SOCKET)
    {
        closesocket(socks5_udp_socket);
        socks5_udp_socket = INVALID_SOCKET;
    }
    if (socks5_udp_send_socket != INVALID_SOCKET)
    {
        closesocket(socks5_udp_send_socket);
        socks5_udp_send_socket = INVALID_SOCKET;
    }

    // Create TCP control connection
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET)
        return FALSE;

    configure_tcp_socket(tcp_sock, 262144, 3000);

    UINT32 socks5_ip = resolve_hostname(g_proxy_host);
    if (socks5_ip == 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    if (socks5_udp_associate(tcp_sock, &socks5_udp_relay_addr) != 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    socks5_udp_socket = tcp_sock;

    // ccreate UDP socket for sending to SOCKS5 proxy
    socks5_udp_send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socks5_udp_send_socket == INVALID_SOCKET)
    {
        closesocket(socks5_udp_socket);
        socks5_udp_socket = INVALID_SOCKET;
        return FALSE;
    }

    configure_udp_socket(socks5_udp_send_socket, 262144, 30000);

    udp_associate_connected = TRUE;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy");
    return TRUE;
}

static DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr, from_addr;
    unsigned char recv_buf[MAXBUF];
    unsigned char send_buf[MAXBUF];
    int recv_len, from_len;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 1;

    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    int on = 1;
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    configure_udp_socket(udp_relay_socket, 262144, 30000);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);

    if (bind(udp_relay_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
    {
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    // Try initial UDP ASSOCIATE (non-fatal if it fails)
    udp_associate_connected = establish_udp_associate();

    log_message("UDP relay listening on port %d", LOCAL_UDP_RELAY_PORT);
    if (!udp_associate_connected)
    {
        log_message("UDP ASSOCIATE not available yet - will retry when needed");
    }

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_relay_socket, &read_fds);

        // monitor both TCP control connection and UDP send socket
        if (udp_associate_connected && socks5_udp_socket != INVALID_SOCKET)
            FD_SET(socks5_udp_socket, &read_fds);

        if (udp_associate_connected && socks5_udp_send_socket != INVALID_SOCKET)
            FD_SET(socks5_udp_send_socket, &read_fds);

        struct timeval timeout = {1, 0};

        SOCKET max_fd = udp_relay_socket;
        if (socks5_udp_socket > max_fd) max_fd = socks5_udp_socket;
        if (socks5_udp_send_socket > max_fd) max_fd = socks5_udp_send_socket;

        if (select(max_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        // check SOCKS5 server disconnected
        if (udp_associate_connected && socks5_udp_socket != INVALID_SOCKET && FD_ISSET(socks5_udp_socket, &read_fds))
        {
            char test_buf[1];
            int result = recv(socks5_udp_socket, test_buf, sizeof(test_buf), MSG_PEEK);
            if (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK))
            {
                log_message("[UDP RELAY] TCP control connection closed - SOCKS5 proxy disconnected");

                // close all connections
                if (socks5_udp_socket != INVALID_SOCKET)
                {
                    closesocket(socks5_udp_socket);
                    socks5_udp_socket = INVALID_SOCKET;
                }
                if (socks5_udp_send_socket != INVALID_SOCKET)
                {
                    closesocket(socks5_udp_send_socket);
                    socks5_udp_send_socket = INVALID_SOCKET;
                }
                udp_associate_connected = FALSE;
                continue;
            }
        }

        // Check if packet is from local application
        if (FD_ISSET(udp_relay_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len > 0)
            {
            // Buffer overflow protection
            if (recv_len > MAXBUF - 10) continue;

                UINT32 from_ip = from_addr.sin_addr.s_addr;
                UINT16 from_port = ntohs(from_addr.sin_port);
                UINT32 dest_ip;
                UINT16 dest_port;
                if (get_connection(from_port, &dest_ip, &dest_port))
                {

                    // Ensure UDP ASSOCIATE is established (retry if needed)
                    if (!udp_associate_connected)
                    {
                        udp_associate_connected = establish_udp_associate();
                        if (!udp_associate_connected)
                        {
                            log_message("[UDP RELAY] Cannot send - UDP ASSOCIATE not established");
                            continue;
                        }
                    }

                    send_buf[0] = 0;
                    send_buf[1] = 0;
                    send_buf[2] = 0;
                    send_buf[3] = SOCKS5_ATYP_IPV4;
                    send_buf[4] = (dest_ip >> 0) & 0xFF;
                    send_buf[5] = (dest_ip >> 8) & 0xFF;
                    send_buf[6] = (dest_ip >> 16) & 0xFF;
                    send_buf[7] = (dest_ip >> 24) & 0xFF;
                    send_buf[8] = (dest_port >> 8) & 0xFF;
                    send_buf[9] = (dest_port >> 0) & 0xFF;
                    memcpy(&send_buf[10], recv_buf, recv_len);

                    int sent = sendto(socks5_udp_send_socket, (char*)send_buf, 10 + recv_len, 0,
                          (struct sockaddr *)&socks5_udp_relay_addr, sizeof(socks5_udp_relay_addr));

                    if (sent == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        log_message("[UDP RELAY ERROR] Failed to send to SOCKS5 proxy: %d - closing connection", err);

                        // connection is broken close all sockets and retry
                        if (socks5_udp_socket != INVALID_SOCKET)
                        {
                            closesocket(socks5_udp_socket);
                            socks5_udp_socket = INVALID_SOCKET;
                        }
                        if (socks5_udp_send_socket != INVALID_SOCKET)
                        {
                            closesocket(socks5_udp_send_socket);
                            socks5_udp_send_socket = INVALID_SOCKET;
                        }
                        udp_associate_connected = FALSE;
                    }
                }
                else
                {
                    log_message("[UDP RELAY] No connection found for port %d", from_port);
                }
            }
        }

        // Check if packet is from SOCKS5 proxy (only if connected)
        if (udp_associate_connected && socks5_udp_send_socket != INVALID_SOCKET && FD_ISSET(socks5_udp_send_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(socks5_udp_send_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                log_message("[UDP RELAY ERROR] Failed to receive from SOCKS5 proxy: %d - closing connection", err);
                if (socks5_udp_socket != INVALID_SOCKET)
                {
                    closesocket(socks5_udp_socket);
                    socks5_udp_socket = INVALID_SOCKET;
                }
                if (socks5_udp_send_socket != INVALID_SOCKET)
                {
                    closesocket(socks5_udp_send_socket);
                    socks5_udp_send_socket = INVALID_SOCKET;
                }
                udp_associate_connected = FALSE;
                continue;
            }

            if (recv_len > 0)
            {
                // Packet from SOCKS5 proxy - decapsulate and forward to original sender
                if (recv_len < 10)
                    continue;

                // SOCKS5 UDP packet format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
                if (recv_buf[2] != 0x00)  // FRAG must be 0
                    continue;

                if (recv_buf[3] != SOCKS5_ATYP_IPV4)  // Only IPv4 supported
                    continue;

                // Extract source IP and port from SOCKS5 header
                UINT32 src_ip = (recv_buf[4] << 0) | (recv_buf[5] << 8) |
                               (recv_buf[6] << 16) | (recv_buf[7] << 24);
                UINT16 src_port = (recv_buf[8] << 8) | recv_buf[9];

                // Find which local port this packet should go to
                WaitForSingleObject(lock, INFINITE);
                struct sockaddr_in target_addr;
                BOOL found = FALSE;
                UINT32 target_ip = 0;
                UINT16 target_port = 0;

                // search all hash for reverse lookup in bucket
                for (int i = 0; i < CONNECTION_HASH_SIZE && !found; i++)
                {
                    CONNECTION_INFO *conn = connection_hash_table[i];
                    while (conn != NULL)
                    {
                        if (conn->orig_dest_ip == src_ip && conn->orig_dest_port == src_port)
                        {
                            target_ip = conn->src_ip;
                            target_port = conn->src_port;
                            found = TRUE;
                            break;
                        }
                        conn = conn->next;
                    }
                }
                ReleaseMutex(lock);

                if (found)
                {
                    memset(&target_addr, 0, sizeof(target_addr));
                    target_addr.sin_family = AF_INET;
                    target_addr.sin_addr.s_addr = target_ip;
                    target_addr.sin_port = htons(target_port);

                    sendto(udp_relay_socket, (char*)&recv_buf[10], recv_len - 10, 0,
                          (struct sockaddr *)&target_addr, sizeof(target_addr));
                }
            }
        }
    }

    closesocket(socks5_udp_socket);
    closesocket(socks5_udp_send_socket);
    closesocket(udp_relay_socket);
    udp_relay_socket = INVALID_SOCKET;
    socks5_udp_socket = INVALID_SOCKET;
    socks5_udp_send_socket = INVALID_SOCKET;
    WSACleanup();
    return 0;
}


static DWORD WINAPI local_proxy_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in addr;
    SOCKET listen_sock;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        log_message("WSAStartup failed (%lu)", GetLastError());
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    int nodelay = 1;
    setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_local_relay_port);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_message("Bind failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
    {
        log_message("Listen failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    log_message("Local proxy listening on port %d", g_local_relay_port);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        struct timeval timeout = {1, 0};

        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock == INVALID_SOCKET)
            continue;

        CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
        if (conn_config == NULL)
        {
            closesocket(client_sock);
            continue;
        }

        conn_config->client_socket = client_sock;


        UINT16 client_port = ntohs(client_addr.sin_port);
        if (!get_connection(client_port, &conn_config->orig_dest_ip, &conn_config->orig_dest_port))
        {
            closesocket(client_sock);
            free(conn_config);
            continue;
        }

        HANDLE conn_thread = CreateThread(NULL, 1, connection_handler,
                                          (LPVOID)conn_config, 0, NULL);
        if (conn_thread == NULL)
        {
            log_message("CreateThread failed (%lu)", GetLastError());
            closesocket(client_sock);
            free(conn_config);
            continue;
        }
        CloseHandle(conn_thread);
    }

    closesocket(listen_sock);
    WSACleanup();
    return 0;
}


static DWORD WINAPI connection_handler(LPVOID arg)
{
    CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)arg;
    SOCKET client_sock = config->client_socket;
    UINT32 dest_ip = config->orig_dest_ip;
    UINT16 dest_port = config->orig_dest_port;
    SOCKET socks_sock;
    struct sockaddr_in socks_addr;
    UINT32 socks5_ip;

    free(config);

    // Connect to SOCKS5 proxy
    socks5_ip = resolve_hostname(g_proxy_host);
    if (socks5_ip == 0)
    {
        closesocket(client_sock);
        return 1;
    }

    socks_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    configure_tcp_socket(socks_sock, 524288, 30000);
    configure_tcp_socket(client_sock, 524288, 30000);

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(g_proxy_port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        log_message("Failed to connect to proxy (%d)", WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(socks_sock, dest_ip, dest_port) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }
    else if (g_proxy_type == PROXY_TYPE_HTTP)
    {
        if (http_connect(socks_sock, dest_ip, dest_port) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }

    //
    // educes thread count by 50% and CPU usage significantly
    TRANSFER_CONFIG *transfer_config = (TRANSFER_CONFIG *)malloc(sizeof(TRANSFER_CONFIG));

    if (transfer_config == NULL)
    {
        log_message("Memory allocation failed for transfer_config");
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    transfer_config->from_socket = client_sock;
    transfer_config->to_socket = socks_sock;

    // both transfer in current thread
    transfer_handler((LPVOID)transfer_config);

    // Sockets already closed in transfer_handler!

    return 0;
}

static DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET sock1 = config->from_socket;  // client socket
    SOCKET sock2 = config->to_socket;     // proxy socket
    char buf[131072];  // 128KB buffer for high-speed transfers
    int len;

    free(config);

    // monitor BOTH socket in one thread
    while (TRUE)
    {
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(sock1, &readfds);  // client
        FD_SET(sock2, &readfds);  // proxy

        // short timeout for responsive upload/download (50ms)
        timeout.tv_sec = 0;
        timeout.tv_usec = 50000;  // 50ms

        int ready = select(0, &readfds, NULL, NULL, &timeout);

        if (ready == SOCKET_ERROR)
        {

            break;
        }

        if (ready == 0)
        {
            // timeotjust continue to check again
            continue;
        }

        // check if  client to proxy
        if (FD_ISSET(sock1, &readfds))
        {
            len = recv(sock1, buf, sizeof(buf), 0);
            if (len <= 0)
                break;

            if (send_all(sock2, buf, len) == SOCKET_ERROR)
                goto cleanup;
        }

        // check if proxyto client
        if (FD_ISSET(sock2, &readfds))
        {
            len = recv(sock2, buf, sizeof(buf), 0);
            if (len <= 0)
                break;

            if (send_all(sock1, buf, len) == SOCKET_ERROR)
                goto cleanup;
        }
    }

cleanup:
    // graceful shutdown
    shutdown(sock1, SD_BOTH);
    shutdown(sock2, SD_BOTH);
    closesocket(sock1);
    closesocket(sock2);
    return 0;
}

static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port)
{
    WaitForSingleObject(lock, INFINITE);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = connection_hash_table[hash];

    // check if already exists in this hash bucket
    while (existing != NULL) {
        if (existing->src_port == src_port) {
            // Update existing entry
            existing->src_ip = src_ip;
            existing->orig_dest_ip = dest_ip;
            existing->orig_dest_port = dest_port;
            existing->is_tracked = TRUE;
            ReleaseMutex(lock);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseMutex(lock);
        return;
    }

    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();

    // insert at head of hash bucket
    //reuse hash variable from lookup above
    conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = conn;
    ReleaseMutex(lock);
}

static BOOL is_connection_tracked(UINT16 src_port)
{
    BOOL tracked = FALSE;
    WaitForSingleObject(lock, INFINITE);

    // Hash table lookup - O(1)
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_tracked) {
            tracked = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseMutex(lock);
    return tracked;
}

static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port)
{
    BOOL found = FALSE;

    WaitForSingleObject(lock, INFINITE);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            conn->last_activity = GetTickCount64();  // Update activity to prevent stale cleanup
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseMutex(lock);

    return found;
}

static void remove_connection(UINT16 src_port)
{
    WaitForSingleObject(lock, INFINITE);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO **conn_ptr = &connection_hash_table[hash];

    while (*conn_ptr != NULL)
    {
        if ((*conn_ptr)->src_port == src_port)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    ReleaseMutex(lock);
}

static void cleanup_stale_connections(void)
{
    ULONGLONG now = GetTickCount64();
    int removed = 0;

    // Process each hash bucket with minimal lock time
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        WaitForSingleObject(lock, INFINITE);
        CONNECTION_INFO **conn_ptr = &connection_hash_table[i];

        while (*conn_ptr != NULL)
        {
            if (now - (*conn_ptr)->last_activity > 60000)
            {
                CONNECTION_INFO *to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                ReleaseMutex(lock);
                free(to_free);  // Free outside lock
                removed++;
                WaitForSingleObject(lock, INFINITE);
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        ReleaseMutex(lock);
    }

    // Cleanup PID cache with separate lock acquisitions
    ULONGLONG now_cache = GetTickCount64();
    int cache_removed = 0;
    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        WaitForSingleObject(lock, INFINITE);
        PID_CACHE_ENTRY **entry_ptr = &pid_cache[i];
        while (*entry_ptr != NULL)
        {
            if (now_cache - (*entry_ptr)->timestamp > 10000)
            {
                PID_CACHE_ENTRY *to_free = *entry_ptr;
                *entry_ptr = (*entry_ptr)->next;
                ReleaseMutex(lock);
                free(to_free);  // Free outside lock
                cache_removed++;
                WaitForSingleObject(lock, INFINITE);
            }
            else
            {
                entry_ptr = &(*entry_ptr)->next;
            }
        }
        ReleaseMutex(lock);
    }

    // keep only last 100 for memory efficiency // 100 will keep speed upto the mark
    WaitForSingleObject(lock, INFINITE);
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

        if (temp != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;  // Cut the list

            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
        }
    }

    ReleaseMutex(lock);
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    if (process_name == NULL || process_name[0] == '\0')
        return 0;

    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (rule == NULL)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy_s(rule->process_name, MAX_PROCESS_NAME, process_name, _TRUNCATE);
    rule->protocol = protocol;

    if (target_hosts != NULL && target_hosts[0] != '\0')
    {
        size_t len = strlen(target_hosts) + 1;
        rule->target_hosts = (char *)malloc(len);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strncpy_s(rule->target_hosts, len, target_hosts, _TRUNCATE);
    }
    else
    {
        // Default to "*" ll IPs
        rule->target_hosts = (char *)malloc(2);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strcpy_s(rule->target_hosts, 2, "*");
    }

    // Dynamically allocate memory for target_ports no size limit!
    if (target_ports != NULL && target_ports[0] != '\0')
    {
        size_t len = strlen(target_ports) + 1;
        rule->target_ports = (char *)malloc(len);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strncpy_s(rule->target_ports, len, target_ports, _TRUNCATE);
    }
    else
    {
        // Default to "*" - all ports
        rule->target_ports = (char *)malloc(2);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strcpy_s(rule->target_ports, 2, "*");
    }

    rule->action = action;
    rule->enabled = TRUE;
    rule->next = rules_list;
    rules_list = rule;

    update_has_active_rules();
    log_message("Added rule ID: %u for process '%s' (Protocol: %d, Action: %d)", rule->rule_id, process_name, protocol, action);

    return rule->rule_id;
}

PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = TRUE;
            update_has_active_rules();
            log_message("Enabled rule ID: %u", rule_id);
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = FALSE;
            update_has_active_rules();  // Phase 1: Update fast-path flag
            log_message("Disabled rule ID: %u", rule_id);
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

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

            if (rule->target_hosts != NULL)
                free(rule->target_hosts);
            if (rule->target_ports != NULL)
                free(rule->target_ports);
            free(rule);

            update_has_active_rules();
            log_message("Deleted rule ID: %u", rule_id);
            return TRUE;
        }
        prev = rule;
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    if (rule_id == 0 || process_name == NULL || target_hosts == NULL || target_ports == NULL)
        return FALSE;

    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            strncpy_s(rule->process_name, MAX_PROCESS_NAME, process_name, _TRUNCATE);

            if (rule->target_hosts != NULL)
                free(rule->target_hosts);
            rule->target_hosts = _strdup(target_hosts);
            if (rule->target_hosts == NULL)
            {
                return FALSE;
            }

            if (rule->target_ports != NULL)
                free(rule->target_ports);
            rule->target_ports = _strdup(target_ports);
            if (rule->target_ports == NULL)
            {
                free(rule->target_hosts);
                rule->target_hosts = NULL;
                return FALSE;
            }

            rule->protocol = protocol;
            rule->action = action;

            update_has_active_rules();
            log_message("Updated rule ID: %u", rule_id);
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return FALSE;

    // Validate that the hostname/IP can be resolved
    if (resolve_hostname(proxy_ip) == 0)
        return FALSE;

    strncpy_s(g_proxy_host, sizeof(g_proxy_host), proxy_ip, _TRUNCATE);
    g_proxy_port = proxy_port;
    g_proxy_type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;

    // Store credentials if there
    if (username != NULL && username[0] != '\0')
    {
        strncpy_s(g_proxy_username, sizeof(g_proxy_username), username, _TRUNCATE);
    }
    else
    {
        g_proxy_username[0] = '\0';
    }

    if (password != NULL && password[0] != '\0')
    {
        strncpy_s(g_proxy_password, sizeof(g_proxy_password), password, _TRUNCATE);
    }
    else
    {
        g_proxy_password[0] = '\0';
    }

    return TRUE;
}

PROXYBRIDGE_API void ProxyBridge_SetDnsViaProxy(BOOL enable)
{
    g_dns_via_proxy = enable;
    log_message("DNS routing: %s", enable ? "via proxy" : "direct");
}

PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback)
{
    g_log_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback)
{
    g_connection_callback = callback;
}

PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable)
{
    g_traffic_logging_enabled = enable;
    if (!enable)
    {
        clear_logged_connections();
    }
}

PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void)
{
    clear_logged_connections();
    log_message("Connection logs cleared");
}

// Check if connection already logged (deduplication)
static BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    BOOL found = FALSE;
    WaitForSingleObject(lock, INFINITE);

    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid &&
            logged->dest_ip == dest_ip &&
            logged->dest_port == dest_port &&
            logged->action == action)
        {
            found = TRUE;
            break;
        }
        logged = logged->next;
    }

    ReleaseMutex(lock);
    return found;
}


// Memory usage and cpu usage are limitation of the ProxyBridge arch
// Relay server takes huge amount of memory and cpu and add extra hops
// hops can cuase slight delay in network speed
// relay server are ippoved to process it as fast as possible with minimal impact on memory usage

static void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    WaitForSingleObject(lock, INFINITE);

    int count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL)
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

            ReleaseMutex(lock);
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
            WaitForSingleObject(lock, INFINITE);
        }
    }

    LOGGED_CONNECTION *logged = (LOGGED_CONNECTION *)malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->dest_ip = dest_ip;
        logged->dest_port = dest_port;
        logged->action = action;
        logged->next = logged_connections;
        logged_connections = logged;
    }

    ReleaseMutex(lock);
}

static void clear_logged_connections(void)
{
    WaitForSingleObject(lock, INFINITE);

    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }

    ReleaseMutex(lock);
}

//  cache pid
// This can be imprroved
// Need to work on this before releease for potential collusion
// need to remove unwanted entires from table
static UINT32 pid_cache_hash(UINT32 src_ip, UINT16 src_port, BOOL is_udp)
{
    UINT32 hash = src_ip ^ ((UINT32)src_port << 16) ^ (is_udp ? 0x80000000 : 0);
    return hash % PID_CACHE_SIZE;
}

static DWORD get_cached_pid(UINT32 src_ip, UINT16 src_port, BOOL is_udp)
{
    UINT32 hash = pid_cache_hash(src_ip, src_port, is_udp);
    ULONGLONG current_time = GetTickCount64();
    DWORD pid = 0;

    WaitForSingleObject(lock, INFINITE);

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

    ReleaseMutex(lock);
    return pid;
}

static void cache_pid(UINT32 src_ip, UINT16 src_port, DWORD pid, BOOL is_udp)
{
    UINT32 hash = pid_cache_hash(src_ip, src_port, is_udp);
    ULONGLONG current_time = GetTickCount64();

    WaitForSingleObject(lock, INFINITE);

    PID_CACHE_ENTRY *entry = pid_cache[hash];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->src_port == src_port &&
            entry->is_udp == is_udp)
        {
            entry->pid = pid;
            entry->timestamp = current_time;
            ReleaseMutex(lock);
            return;
        }
        entry = entry->next;
    }

    PID_CACHE_ENTRY *new_entry = (PID_CACHE_ENTRY *)malloc(sizeof(PID_CACHE_ENTRY));
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

    ReleaseMutex(lock);
}

static void clear_pid_cache(void)
{
    WaitForSingleObject(lock, INFINITE);

    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        while (pid_cache[i] != NULL)
        {
            PID_CACHE_ENTRY *to_free = pid_cache[i];
            pid_cache[i] = pid_cache[i]->next;
            free(to_free);
        }
    }

    ReleaseMutex(lock);
}

// Dedicated cleanup thread - runs independently without blocking packet processing
static DWORD WINAPI cleanup_worker(LPVOID arg)
{
    while (running)
    {
        Sleep(30000);  // 30 seconds
        if (running)
        {
            cleanup_stale_connections();
        }
    }
    return 0;
}

static void update_has_active_rules(void)
{
    g_has_active_rules = FALSE;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->enabled)
        {
            g_has_active_rules = TRUE;
            break;
        }
        rule = rule->next;
    }
}

PROXYBRIDGE_API BOOL ProxyBridge_Start(void)
{
    char filter[FILTER_BUFFER_SIZE];
    INT16 priority = 123;

    if (running)
        return FALSE;

    if (lock == NULL)
    {
        lock = CreateMutex(NULL, FALSE, NULL);
        if (lock == NULL)
            return FALSE;
    }

    running = TRUE;

    proxy_thread = CreateThread(NULL, 1, local_proxy_server, NULL, 0, NULL);
    if (proxy_thread == NULL)
    {
        running = FALSE;
        return FALSE;
    }

    // Start cleanup thread to avoid blocking packet processing
    cleanup_thread = CreateThread(NULL, 1, cleanup_worker, NULL, 0, NULL);
    if (cleanup_thread == NULL)
    {
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        udp_relay_thread = CreateThread(NULL, 1, udp_relay_server, NULL, 0, NULL);
        if (udp_relay_thread == NULL)
        {
            running = FALSE;
            WaitForSingleObject(cleanup_thread, INFINITE);
            CloseHandle(cleanup_thread);
            cleanup_thread = NULL;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    Sleep(500);

    snprintf(filter, sizeof(filter),
        "(tcp and (outbound or (tcp.DstPort == %d or tcp.SrcPort == %d))) or (udp and (outbound or (udp.DstPort == %d or udp.SrcPort == %d)))",
        g_local_relay_port, g_local_relay_port, LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE)
    {
        log_message("Failed to open WinDivert (%lu)", GetLastError());
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 8);  // 8ms for low latency

    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        packet_thread[i] = CreateThread(NULL, 0, packet_processor, NULL, 0, NULL);
        if (packet_thread[i] == NULL)
        {
            running = FALSE;
            for (int j = 0; j < i; j++)
            {
                if (packet_thread[j] != NULL)
                {
                    WaitForSingleObject(packet_thread[j], 5000);
                    CloseHandle(packet_thread[j]);
                    packet_thread[j] = NULL;
                }
            }
            WinDivertClose(windivert_handle);
            windivert_handle = INVALID_HANDLE_VALUE;
            WaitForSingleObject(proxy_thread, INFINITE);
            CloseHandle(proxy_thread);
            proxy_thread = NULL;
            return FALSE;
        }
    }

    update_has_active_rules();

    log_message("ProxyBridge started");
    log_message("Local relay: localhost:%d", g_local_relay_port);
    log_message("%s proxy: %s:%d", g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5", g_proxy_host, g_proxy_port);

    int rule_count = 0;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        const char *action_str = (rule->action == RULE_ACTION_PROXY) ? "PROXY" :
                                 (rule->action == RULE_ACTION_BLOCK) ? "BLOCK" : "DIRECT";
        log_message("Rule: %s -> %s", rule->process_name, action_str);
        rule_count++;
        rule = rule->next;
    }
    if (rule_count == 0)
        log_message("No rules configured - all traffic will be direct");

    return TRUE;
}

PROXYBRIDGE_API BOOL ProxyBridge_Stop(void)
{
    if (!running)
        return FALSE;

    running = FALSE;

    if (windivert_handle != INVALID_HANDLE_VALUE)
    {
        WinDivertShutdown(windivert_handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    // process alll packets before we stop, make sure packets are not dropped
    for (int i = 0; i < NUM_PACKET_THREADS; i++)
    {
        if (packet_thread[i] != NULL)
        {
            WaitForSingleObject(packet_thread[i], 1000);  // 1 second timeout
            CloseHandle(packet_thread[i]);
            packet_thread[i] = NULL;
        }
    }

    if (proxy_thread != NULL)
    {
        WaitForSingleObject(proxy_thread, 1000);  // 1 second timeout
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }

    if (cleanup_thread != NULL)
    {
        WaitForSingleObject(cleanup_thread, 1000);  // 1 second timeout
        CloseHandle(cleanup_thread);
        cleanup_thread = NULL;
    }

    if (udp_relay_thread != NULL)
    {
        WaitForSingleObject(udp_relay_thread, 1000);  // 1 second timeout
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }

    WaitForSingleObject(lock, INFINITE);
    // free all connections in hash table
    // avoid unwanted data and free the memory
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != NULL)
        {
            CONNECTION_INFO *to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            free(to_free);
        }
    }
    ReleaseMutex(lock);

    // Clear logged connections list
    clear_logged_connections();

    clear_pid_cache();

    log_message("ProxyBridge stopped");

    return TRUE;
}


PROXYBRIDGE_API int ProxyBridge_TestConnection(const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size)
{
    WSADATA wsa;
    SOCKET test_sock = INVALID_SOCKET;
    struct sockaddr_in proxy_addr;
    struct hostent* host_info;
    UINT32 target_ip;
    int ret = -1;
    char temp_buffer[FILTER_BUFFER_SIZE];

    if (g_proxy_host[0] == '\0' || g_proxy_port == 0)
    {
        snprintf(result_buffer, buffer_size, "ERROR: No proxy configured");
        return -1;
    }

    if (target_host == NULL || target_host[0] == '\0')
    {
        snprintf(result_buffer, buffer_size, "ERROR: Invalid target host");
        return -1;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        snprintf(result_buffer, buffer_size, "ERROR: WSAStartup failed (%d)", WSAGetLastError());
        return -1;
    }

    snprintf(temp_buffer, sizeof(temp_buffer), "Testing connection to %s:%d via %s proxy %s:%d...\n",
        target_host, target_port,
        g_proxy_type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
        g_proxy_host, g_proxy_port);
    strncpy_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);


    host_info = gethostbyname(target_host);
    if (host_info == NULL)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to resolve hostname %s (%d)\n", target_host, WSAGetLastError());
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        WSACleanup();
        return -1;
    }
    target_ip = *(UINT32*)host_info->h_addr_list[0];

    snprintf(temp_buffer, sizeof(temp_buffer), "Resolved %s to %d.%d.%d.%d\n",
        target_host,
        (target_ip >> 0) & 0xFF, (target_ip >> 8) & 0xFF,
        (target_ip >> 16) & 0xFF, (target_ip >> 24) & 0xFF);
    strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);

    // Create socket
    test_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (test_sock == INVALID_SOCKET)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Socket creation failed (%d)\n", WSAGetLastError());
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        WSACleanup();
        return -1;
    }

    DWORD timeout = 10000;
    setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(test_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = resolve_hostname(g_proxy_host);
    proxy_addr.sin_port = htons(g_proxy_port);

    snprintf(temp_buffer, sizeof(temp_buffer), "Connecting to proxy %s:%d...\n", g_proxy_host, g_proxy_port);
    strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);

    if (connect(test_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to connect to proxy (%d)\n", WSAGetLastError());
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        closesocket(test_sock);
        WSACleanup();
        return -1;
    }

    strncat_s(result_buffer, buffer_size, "Connected to proxy server\n", _TRUNCATE);

    if (g_proxy_type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: SOCKS5 handshake failed\n");
            strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
            closesocket(test_sock);
            WSACleanup();
            return -1;
        }
        strncat_s(result_buffer, buffer_size, "SOCKS5 handshake successful\n", _TRUNCATE);
    }
    else
    {
        if (http_connect(test_sock, target_ip, target_port) != 0)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: HTTP CONNECT failed\n");
            strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
            closesocket(test_sock);
            WSACleanup();
            return -1;
        }
        strncat_s(result_buffer, buffer_size, "HTTP CONNECT successful\n", _TRUNCATE);
    }


    char http_request[FILTER_BUFFER_SIZE];
    snprintf(http_request, sizeof(http_request),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: ProxyBridge/1.0\r\n"
        "\r\n", target_host);

    if (send(test_sock, http_request, strlen(http_request), 0) == SOCKET_ERROR)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to send test request (%d)\n", WSAGetLastError());
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        closesocket(test_sock);
        WSACleanup();
        return -1;
    }

    strncat_s(result_buffer, buffer_size, "Sent HTTP GET request\n", _TRUNCATE);
    char response[1024];
    int bytes_received = recv(test_sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0)
    {
        response[bytes_received] = '\0';

        if (strstr(response, "HTTP/") != NULL)
        {
            char* status_line = strstr(response, "HTTP/");
            int status_code = 0;
            if (status_line != NULL)
            {
                sscanf_s(status_line, "HTTP/%*s %d", &status_code);
            }

            snprintf(temp_buffer, sizeof(temp_buffer), "SUCCESS: Received HTTP %d response (%d bytes)\n", status_code, bytes_received);
            strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
            ret = 0; // Success
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Received data but not valid HTTP response\n");
            strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
            ret = -1; // Failure - not a valid HTTP response
        }
    }
    else if (bytes_received == 0)
    {
        snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Connection closed by remote host (no data received)\n");
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        ret = -1; // Failure
    }
    else
    {
        int error_code = WSAGetLastError();
        if (error_code == WSAETIMEDOUT)
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Connection timeout - no response received\n");
        }
        else
        {
            snprintf(temp_buffer, sizeof(temp_buffer), "ERROR: Failed to receive response (%d)\n", error_code);
        }
        strncat_s(result_buffer, buffer_size, temp_buffer, _TRUNCATE);
        ret = -1; // Failure
    }

    closesocket(test_sock);
    WSACleanup();

    if (ret == 0)
    {
        strncat_s(result_buffer, buffer_size, "\n✓ Proxy connection test PASSED\n", _TRUNCATE);
    }
    else
    {
        strncat_s(result_buffer, buffer_size, "\n✗ Proxy connection test FAILED\n", _TRUNCATE);
    }

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Store the PID of the process that loaded this DLL
            g_current_process_id = GetCurrentProcessId();
            break;
        case DLL_PROCESS_DETACH:
            if (running)
                ProxyBridge_Stop();
            if (lock != NULL)
            {
                CloseHandle(lock);
                lock = NULL;
            }
            while (rules_list != NULL)
            {
                PROCESS_RULE *to_free = rules_list;
                rules_list = rules_list->next;

                if (to_free->target_hosts != NULL)
                    free(to_free->target_hosts);
                if (to_free->target_ports != NULL)
                    free(to_free->target_ports);

                free(to_free);
            }
            break;
    }
    return TRUE;
}