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
#define MAX_PROCESS_NAME 1024
#define VERSION "4.0.0"
#define PID_CACHE_SIZE 1024
#define PID_CACHE_TTL_MS 30000
// Single packet-processor thread eliminates TCP packet reordering.
// With multiple threads each racing to WinDivertRecv+WinDivertSend, thread N+1
// can re-inject its segment before thread N injects segment N, causing the
// relay's TCP stack to send DUPACKs back to the browser.  The browser
// interprets 3+ DUPACKs as loss, halves its congestion window, and upload
// throughput collapses 50% A single ordered thread prevents this entirely.
// One thread is fast enough at 200 Mbps with 1460-byte segments there are
// 17 000 packets/sec a single core processes well over 200000 packets/sec.
#define NUM_PACKET_THREADS 1
#define CONNECTION_HASH_SIZE 4096
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
    UINT32 proxy_config_id;  // Which proxy config to route this rule through (0 = first available)
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
    UINT32 proxy_config_id;  // Which proxy config handles this connection
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

typedef struct {
    SOCKET client_socket;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    UINT32 proxy_config_id;  // Which proxy config to use for this connection
} CONNECTION_CONFIG;

typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

// Two-thread bidirectional relay: each direction runs in its own thread so
// a slow proxy (upload) never stalls the download pipe and vice-versa.
typedef struct {
    SOCKET sock_client;   // app-side socket
    SOCKET sock_proxy;    // proxy-side socket
    volatile LONG refs;   // ref-count; last thread out closes both sockets
} RELAY_PAIR;

typedef struct {
    RELAY_PAIR *pair;
    SOCKET from;
    SOCKET to;
} ONE_WAY_CONFIG;

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

// Internal proxy configuration with per-config UDP SOCKS5 state
typedef struct {
    UINT32 config_id;           // Unique ID (1-based), 0 = unused slot
    ProxyType type;
    char host[256];
    UINT16 port;
    char username[256];
    char password[256];
    UINT32 resolved_ip;         // cached at add/edit time - avoids DNS per connection
    ULONGLONG last_udp_attempt;
    SOCKET udp_tcp_ctrl;
    SOCKET udp_send_sock;
    struct sockaddr_in udp_relay_addr;
    BOOL udp_connected;
} PROXY_CONFIG;

static PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
static int g_proxy_config_count = 0;
static UINT32 g_next_config_id = 1;

static CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE] = {NULL};
static LOGGED_CONNECTION *logged_connections = NULL;
static PROCESS_RULE *rules_list = NULL;
static UINT32 g_next_rule_id = 1;
static SRWLOCK lock;
static HANDLE windivert_handle = INVALID_HANDLE_VALUE;
static HANDLE packet_thread[NUM_PACKET_THREADS] = {NULL};
static HANDLE proxy_thread = NULL;
static HANDLE udp_relay_thread = NULL;
static HANDLE cleanup_thread = NULL;
static PID_CACHE_ENTRY *pid_cache[PID_CACHE_SIZE] = {NULL};
static volatile BOOL g_has_active_rules = FALSE;
static SOCKET udp_relay_socket = INVALID_SOCKET;
static volatile BOOL running = FALSE;
static DWORD g_current_process_id = 0;

static BOOL g_traffic_logging_enabled = TRUE;

// per src port decision cache.
//
// check_process_rule() resolves (src_port) to DIRECT, PROXY, or BLOCK,
// every subsequent packet from that port gets the cached answer in 5 cycles
// (one atomic read). this is needed else every outbound data/ack segment from an
// established connection re runs the full check_process_rule() path:
//   GetExtendedTcpTable (malloc + kernel roundtrip)
//   + OpenProcess + QueryFullProcessImageName
//   + rule list walk
// On a sustained 300 Mbps download (17 000 packets/sec) that is thousands of
// kernel calls per second, saturating a single core.
//
// Layout: two 2048-LONG bitmaps, 8 KB each.
//   port_decided_bitmap : bit set = decision is cached for this port
//   port_direct_bitmap  : bit set = decision was DIRECT (bit clear = PROXY/BLOCK)
// Together they encode three states per port:
//   decided=0            -> no cached decision, call check_process_rule
//   decided=1, direct=1  -> DIRECT, pass packet unchanged
//   decided=1, direct=0  -> already added to connection (PROXY/BLOCK handled)
//
// Thread safety: InterlockedOr/And for writes; plain aligned 32-bit read for
// reads (x86/x64 aligned read is atomic; we only need visibility, not ordering).
static volatile LONG port_decided_bitmap[2048] = {0};  // 8 KB
static volatile LONG port_direct_bitmap[2048]  = {0};  // 8 KB

static __forceinline BOOL port_is_decided(UINT16 p)
{
    return (port_decided_bitmap[p >> 5] >> (p & 31)) & 1;
}
static __forceinline BOOL port_is_direct(UINT16 p)
{
    return (port_direct_bitmap[p >> 5] >> (p & 31)) & 1;
}
static __forceinline void port_set_direct(UINT16 p)
{
    InterlockedOr(&port_decided_bitmap[p >> 5], (LONG)(1u << (p & 31)));
    InterlockedOr(&port_direct_bitmap[p >> 5],  (LONG)(1u << (p & 31)));
}
static __forceinline void port_set_decided(UINT16 p)  // decided, but NOT direct (proxy/block)
{
    InterlockedOr(&port_decided_bitmap[p >> 5], (LONG)(1u << (p & 31)));
    // leave port_direct_bitmap bit at 0
}
static __forceinline void port_clear(UINT16 p)
{
    InterlockedAnd(&port_decided_bitmap[p >> 5], (LONG)~(1u << (p & 31)));
    InterlockedAnd(&port_direct_bitmap[p >> 5],  (LONG)~(1u << (p & 31)));
}

static UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
static BOOL g_dns_via_proxy = TRUE;
static BOOL g_localhost_via_proxy = FALSE;  // default disabled for security - most proxy server block localhost for ssrf and also many app might not work if localhost trafic goes to remote server if proxy server is on diffrent machine
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
static PROXY_CONFIG* find_proxy_config(UINT32 config_id);
static BOOL any_socks5_config(void);
static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg);
static int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg);
static BOOL establish_udp_associate_for_config(PROXY_CONFIG *cfg);
static DWORD WINAPI udp_relay_server(LPVOID arg);
static BOOL match_ip_pattern(const char *pattern, UINT32 ip);
static BOOL match_port_pattern(const char *pattern, UINT16 port);
static BOOL match_ip_list(const char *ip_list, UINT32 ip);
static BOOL match_port_list(const char *port_list, UINT16 port);
static BOOL match_process_pattern(const char *pattern, const char *process_name);
static BOOL match_process_list(const char *process_list, const char *process_name);
static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg);
static DWORD WINAPI local_proxy_server(LPVOID arg);
static DWORD WINAPI connection_handler(LPVOID arg);
static DWORD WINAPI transfer_handler(LPVOID arg);
static DWORD WINAPI packet_processor(LPVOID arg);
static DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
static DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port);
static BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id);
static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, DWORD *out_pid, UINT32 *out_proxy_config_id);
static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id);
static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
static BOOL get_connection_full(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id);
static UINT32 get_connection_proxy_id(UINT16 src_port);
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

        PWINDIVERT_IPV6HDR ipv6_header = NULL;
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL,
            NULL, NULL, &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        if (ip_header == NULL)
        {
            // IPv6 traffic pass directly without proxying
            if (ipv6_header != NULL)
            {
                WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
            }
            continue;
        }

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
                    UINT32 proxy_config_id = 0;

                    if (dest_port == 53 && !g_dns_via_proxy)
                        action = RULE_ACTION_DIRECT;
                    else
                        action = check_process_rule(src_ip, src_port, dest_ip, dest_port, TRUE, &pid, &proxy_config_id);

                    // override PROXY to DIRECT if localhost proxy is disabled and destination is localhost
                    BYTE dest_first_octet = (dest_ip >> 0) & 0xFF;
                    if (action == RULE_ACTION_PROXY && !g_localhost_via_proxy && dest_first_octet == 127)
                        action = RULE_ACTION_DIRECT;

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
                                    PROXY_CONFIG *pcfg = find_proxy_config(proxy_config_id);
                                    if (pcfg != NULL)
                                        snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d (UDP)",
                                            pcfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                            pcfg->host, pcfg->port);
                                    else
                                        snprintf(proxy_info, sizeof(proxy_info), "Proxy (UDP)");
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
                        add_connection(src_port, src_ip, dest_ip, dest_port, proxy_config_id);

                        // redirect to UDP relay server at 127.0.0.1:34011
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                        ip_header->DstAddr = htonl(INADDR_LOOPBACK);

                        // check if source is localhos
                        BYTE src_first_octet = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                        BOOL src_is_loopback = (src_first_octet == 127);

                        if (!src_is_loopback)
                        {
                            // for non loopback source: mark as inbound
                            addr.Outbound = FALSE;
                        }
                        // for loopback we need keep as outbound (127.x.x.x -> 127.0.0.1)
                        // for a fucking stupid reason i missed this part for 6 months
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
            // per port decision fast-path.
            // Once check_process_rule() has run for a source port and decided DIRECT,
            // every subsequent packet from that port takes this branch one bitmap
            // read 5 cycle + WinDivertSend, with zero kernel calls
            // FIN/RST clears the cache entry so port can be reused safely
            // Part of this taken from Cluade to fix windivert packet error
            {
                UINT16 sp = ntohs(tcp_header->SrcPort);
                if (port_is_decided(sp))
                {
                    if (tcp_header->Fin || tcp_header->Rst)
                        port_clear(sp);
                    if (port_is_direct(sp))
                    {
                        WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                        continue;
                    }
                    // For PROXY/BLOCK decisions the connection was already added on the
                    // first packet; subsequent packets are handled by is_connection_tracked
                    // below so just fall through.
                }
            }

            if (tcp_header->SrcPort == htons(g_local_relay_port))
            {
                UINT16 dst_port = ntohs(tcp_header->DstPort);
                UINT32 orig_dest_ip;
                UINT16 orig_dest_port;

                if (get_connection(dst_port, &orig_dest_ip, &orig_dest_port))
                    tcp_header->SrcPort = htons(orig_dest_port);

                BYTE src_first = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback = (src_first == 127 && dst_first == 127);

                if (!is_loopback)
                {
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }


                if (tcp_header->Fin || tcp_header->Rst)
                    remove_connection(dst_port);
            }
            else if (is_connection_tracked(ntohs(tcp_header->SrcPort)))
            {
                UINT16 src_port = ntohs(tcp_header->SrcPort);

                if (tcp_header->Fin || tcp_header->Rst)
                {
                    remove_connection(src_port);
                    port_clear(src_port);
                }

                tcp_header->DstPort = htons(g_local_relay_port);

                BYTE src_first = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback = (src_first == 127 && dst_first == 127);

                if (!is_loopback)
                {
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }

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
                UINT32 proxy_config_id = 0;

                if (orig_dest_port == 53 && !g_dns_via_proxy)
                    action = RULE_ACTION_DIRECT;
                else
                    action = check_process_rule(src_ip, src_port, orig_dest_ip, orig_dest_port, FALSE, &pid, &proxy_config_id);

                BYTE orig_dest_first_octet = (orig_dest_ip >> 0) & 0xFF;
                if (action == RULE_ACTION_PROXY && !g_localhost_via_proxy && orig_dest_first_octet == 127)
                    action = RULE_ACTION_DIRECT;

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
                                PROXY_CONFIG *pcfg = find_proxy_config(proxy_config_id);
                                if (pcfg != NULL)
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy %s://%s:%d",
                                        pcfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
                                        pcfg->host, pcfg->port);
                                else
                                    snprintf(proxy_info, sizeof(proxy_info), "Proxy");
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
                    // Cache this decision so all subsequent packets from this port
                    // fast-path at the top of the outbound branch (zero kernel calls).
                    port_set_direct(src_port);
                    // Unmodified packet no checksum needed
                    WinDivertSend(windivert_handle, packet, packet_len, NULL, &addr);
                    continue;
                }
                else if (action == RULE_ACTION_BLOCK)
                {
                    port_set_decided(src_port);  // mark decided (not direct) so we don't re-run rule check
                    // Drop the packet - don't send it anywhere
                    continue;
                }
                else if (action == RULE_ACTION_PROXY)
            {
                add_connection(src_port, src_ip, orig_dest_ip, orig_dest_port, proxy_config_id);
                // Mark this port as decided (not direct) so subsequent packets from
                // the same source port skip the rule check.  The is_connection_tracked
                // branch above handles the actual per-packet redirect.
                port_set_decided(src_port);

                tcp_header->DstPort = htons(g_local_relay_port);

                // check if this is localhost -> localhost traffic
                BYTE src_first_octet = (ntohl(ip_header->SrcAddr) >> 24) & 0xFF;
                BYTE dst_first_octet = (ntohl(ip_header->DstAddr) >> 24) & 0xFF;
                BOOL is_loopback_to_loopback = (src_first_octet == 127 && dst_first_octet == 127);

                if (is_loopback_to_loopback)
                {
                    // for localhost -> localhost just change port, keep as outbound
                    // dont swap IPs Windows loopback routing needs both to stay 127.x.x.x
                    log_message("[PACKET] Loopback redirect: 127.x.x.x:%d -> 127.x.x.x:%d (relay port %d)",
                        ntohs(tcp_header->SrcPort), orig_dest_port, g_local_relay_port);
                    // addr.Outbound stays TRUE
                }
                else
                {
                    // for normal traffic: swap IPs and mark as inbound (standard relay behavior)
                    UINT32 temp_addr = ip_header->DstAddr;
                    ip_header->DstAddr = ip_header->SrcAddr;
                    ip_header->SrcAddr = temp_addr;
                    addr.Outbound = FALSE;
                }
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
    WCHAR full_path_w[MAX_PATH];
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

    if (QueryFullProcessImageNameW(hProcess, 0, full_path_w, &path_len))
    {
        // Convert wide string to UTF-8 so Chinese/non-ASCII paths are preserved
        int converted = WideCharToMultiByte(CP_UTF8, 0, full_path_w, -1, name, (int)name_size, NULL, NULL);
        CloseHandle(hProcess);
        return converted > 0;
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

    // check for IP range
    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        char start_ip_str[64], end_ip_str[64];
        size_t start_len = dash - pattern;
        if (start_len >= sizeof(start_ip_str))
            return FALSE;

        strncpy_s(start_ip_str, sizeof(start_ip_str), pattern, start_len);
        start_ip_str[start_len] = '\0';
        strncpy_s(end_ip_str, sizeof(end_ip_str), dash + 1, _TRUNCATE);

        // parse start and end IPs
        UINT32 start_ip = 0, end_ip = 0;
        int s1, s2, s3, s4, e1, e2, e3, e4;

        if (sscanf_s(start_ip_str, "%d.%d.%d.%d", &s1, &s2, &s3, &s4) == 4 &&
            sscanf_s(end_ip_str, "%d.%d.%d.%d", &e1, &e2, &e3, &e4) == 4)
        {
            start_ip = (s1 << 0) | (s2 << 8) | (s3 << 16) | (s4 << 24);
            end_ip = (e1 << 0) | (e2 << 8) | (e3 << 16) | (e4 << 24);

            // checking as network byte order would be wrong, compare as little-endian UINT32
            // change to big-endian for proper comparison
            UINT32 ip_be = ((ip & 0xFF) << 24) | ((ip & 0xFF00) << 8) | ((ip & 0xFF0000) >> 8) | ((ip & 0xFF000000) >> 24);
            UINT32 start_be = ((start_ip & 0xFF) << 24) | ((start_ip & 0xFF00) << 8) | ((start_ip & 0xFF0000) >> 8) | ((start_ip & 0xFF000000) >> 24);
            UINT32 end_be = ((end_ip & 0xFF) << 24) | ((end_ip & 0xFF00) << 8) | ((end_ip & 0xFF0000) >> 8) | ((end_ip & 0xFF000000) >> 24);

            return (ip_be >= start_be && ip_be <= end_be);
        }
        return FALSE;
    }

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
// Case-insensitive wildcard match; '*' matches any sequence (including empty).
// Handles multiple wildcards anywhere in the pattern, e.g. "*steam*", "fire*.exe".
static BOOL wildcard_match(const char *pattern, const char *text)
{
    while (*text != '\0')
    {
        if (*pattern == '*')
        {
            while (*pattern == '*') pattern++;   // collapse consecutive *
            if (*pattern == '\0') return TRUE;   // trailing * matches rest
            while (*text != '\0')
            {
                if (wildcard_match(pattern, text))
                    return TRUE;
                text++;
            }
            return FALSE;
        }
        else
        {
            if (tolower((unsigned char)*pattern) != tolower((unsigned char)*text))
                return FALSE;
            pattern++;
            text++;
        }
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

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

    // Check if pattern contains path separators (backslash or forward slash)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);

    // match against full path if pattern has a path separator, otherwise filename only
    const char *match_target = is_full_path_pattern ? process_full_path : filename;

    // Wildcard pattern: use full wildcard matcher (handles *, *x*, x*y, etc.)
    if (strchr(pattern, '*') != NULL)
        return wildcard_match(pattern, match_target);

    // No wildcard, plain case-insensitive comparison
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
    // note: Localhost (127.x.x.x) is now supported for proxying
    // This allows intercepting localhost connections for MITM scenarios

    BYTE first_octet = (ip >> 0) & 0xFF;
    BYTE second_octet = (ip >> 8) & 0xFF;

    // APIPA (Link-Local): 169.254.0.0/16 (169.254.x.x)
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
static RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
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
                    if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
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
                if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
                return rule->action;
            }
        }

        rule = rule->next;
    }

    // No specific rule matched, use wildcard if available
    if (wildcard_rule != NULL)
    {
        if (out_proxy_config_id != NULL) *out_proxy_config_id = wildcard_rule->proxy_config_id;
        return wildcard_rule->action;
    }

    // No rule matched at all
    if (out_proxy_config_id != NULL) *out_proxy_config_id = 0;
    return RULE_ACTION_DIRECT;
}

static RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, DWORD *out_pid, UINT32 *out_proxy_config_id)
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
    UINT32 proxy_config_id = 0;
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp, &proxy_config_id);

    // Additional checks for proxy configuration
    if (action == RULE_ACTION_PROXY)
    {
        PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);
        if (cfg == NULL || cfg->host[0] == '\0' || cfg->port == 0)
            return RULE_ACTION_DIRECT;  // No proxy configured

        // UDP: HTTP proxy doesn't support UDP - use per-rule proxy config type
        if (is_udp && cfg->type == PROXY_TYPE_HTTP)
            return RULE_ACTION_DIRECT;
    }

    if (out_proxy_config_id != NULL)
        *out_proxy_config_id = proxy_config_id;

    return action;
}


// Helper: find proxy config by ID; falls back to first config if not found
static PROXY_CONFIG* find_proxy_config(UINT32 config_id)
{
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].config_id == config_id)
            return &g_proxy_configs[i];
    }
    // Fall back to first available config
    if (g_proxy_config_count > 0)
        return &g_proxy_configs[0];
    return NULL;
}

// Helper: check if any proxy config is SOCKS5 (needed to decide whether to start UDP relay)
static BOOL any_socks5_config(void)
{
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].type == PROXY_TYPE_SOCKS5 &&
            g_proxy_configs[i].host[0] != '\0' &&
            g_proxy_configs[i].port != 0)
            return TRUE;
    }
    return FALSE;
}

static int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

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
        size_t user_len = strlen(cfg->username);
        size_t pass_len = strlen(cfg->password);
        if (user_len > 255 || pass_len > 255)
        {
            log_message("SOCKS5: Username or password too long");
            return -1;
        }

        buf[0] = 0x01;  // Version of username/password auth
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], cfg->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], cfg->password, pass_len);

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

static int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char request[HTTP_BUFFER_SIZE];
    char response[4096];
    int len;
    char *status_line;
    int status_code;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    if (use_auth)
    {
        // Create "username:password" string and encode as Base64
        char credentials[SOCKS5_BUFFER_SIZE];
        char encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
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

static int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

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

        size_t user_len = strlen(cfg->username);
        size_t pass_len = strlen(cfg->password);
        if (user_len > 255 || pass_len > 255)
            return -1;

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], cfg->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], cfg->password, pass_len);

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

// connect UDP ASSOCIATE with SOCKS5 proxy (per proxy config)
static BOOL establish_udp_associate_for_config(PROXY_CONFIG *cfg)
{
    if (cfg == NULL || cfg->host[0] == '\0' || cfg->port == 0)
        return FALSE;
    if (cfg->type != PROXY_TYPE_SOCKS5)
        return FALSE;

    // Prevent retry spam - only try every 5 seconds per config
    ULONGLONG now = GetTickCount64();
    if (now - cfg->last_udp_attempt < 5000)
        return FALSE;

    cfg->last_udp_attempt = now;

    // Close existing connections if any
    if (cfg->udp_tcp_ctrl != INVALID_SOCKET)
    {
        closesocket(cfg->udp_tcp_ctrl);
        cfg->udp_tcp_ctrl = INVALID_SOCKET;
    }
    if (cfg->udp_send_sock != INVALID_SOCKET)
    {
        closesocket(cfg->udp_send_sock);
        cfg->udp_send_sock = INVALID_SOCKET;
    }

    // Create TCP control connection
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET)
        return FALSE;

    configure_tcp_socket(tcp_sock, 262144, 3000);

    UINT32 socks5_ip = resolve_hostname(cfg->host);
    if (socks5_ip == 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(cfg->port);

    if (connect(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    if (socks5_udp_associate_with_config(tcp_sock, &cfg->udp_relay_addr, cfg) != 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    cfg->udp_tcp_ctrl = tcp_sock;

    // create UDP socket for sending to SOCKS5 proxy
    cfg->udp_send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cfg->udp_send_sock == INVALID_SOCKET)
    {
        closesocket(cfg->udp_tcp_ctrl);
        cfg->udp_tcp_ctrl = INVALID_SOCKET;
        cfg->udp_connected = FALSE;
        return FALSE;
    }

    configure_udp_socket(cfg->udp_send_sock, 262144, 30000);

    cfg->udp_connected = TRUE;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy %s:%d", cfg->host, cfg->port);
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

    // Try initial UDP ASSOCIATE for all SOCKS5 configs
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].type == PROXY_TYPE_SOCKS5)
        {
            establish_udp_associate_for_config(&g_proxy_configs[i]);
        }
    }

    log_message("UDP relay listening on port %d", LOCAL_UDP_RELAY_PORT);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_relay_socket, &read_fds);

        // Add all SOCKS5 configs' TCP control and UDP send sockets
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5) continue;
            if (cfg->udp_connected && cfg->udp_tcp_ctrl != INVALID_SOCKET)
                FD_SET(cfg->udp_tcp_ctrl, &read_fds);
            if (cfg->udp_connected && cfg->udp_send_sock != INVALID_SOCKET)
                FD_SET(cfg->udp_send_sock, &read_fds);
        }

        struct timeval timeout = {1, 0};
        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        // Check if any SOCKS5 proxy TCP control socket disconnected
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5 || !cfg->udp_connected) continue;
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET && FD_ISSET(cfg->udp_tcp_ctrl, &read_fds))
            {
                char test_buf[1];
                int result = recv(cfg->udp_tcp_ctrl, test_buf, sizeof(test_buf), MSG_PEEK);
                if (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK))
                {
                    log_message("[UDP RELAY] TCP control connection closed for proxy %s:%d", cfg->host, cfg->port);
                    closesocket(cfg->udp_tcp_ctrl);
                    cfg->udp_tcp_ctrl = INVALID_SOCKET;
                    if (cfg->udp_send_sock != INVALID_SOCKET)
                    {
                        closesocket(cfg->udp_send_sock);
                        cfg->udp_send_sock = INVALID_SOCKET;
                    }
                    cfg->udp_connected = FALSE;
                }
            }
        }

        // Check if packet is from local application
        if (FD_ISSET(udp_relay_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len == SOCKET_ERROR)
            {
                // take the error  unreachable so
                // https://github.com/InterceptSuite/ProxyBridge/issues/89
                // select() does not immediately return readable again, causing a spin.
                continue;
            }

            if (recv_len > 0)
            {
                // Buffer overflow protection
                if (recv_len > MAXBUF - 10) continue;

                UINT16 from_port = ntohs(from_addr.sin_port);
                UINT32 dest_ip;
                UINT16 dest_port;

                if (get_connection(from_port, &dest_ip, &dest_port))
                {
                    // Get the proxy config for this connection
                    UINT32 proxy_config_id = get_connection_proxy_id(from_port);
                    PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);

                    if (cfg == NULL || cfg->type != PROXY_TYPE_SOCKS5)
                    {
                        log_message("[UDP RELAY] No SOCKS5 config for port %d", from_port);
                        continue;
                    }

                    // Ensure UDP ASSOCIATE is established (retry if needed)
                    if (!cfg->udp_connected)
                    {
                        if (!establish_udp_associate_for_config(cfg))
                        {
                            log_message("[UDP RELAY] Cannot send - UDP ASSOCIATE not established for %s:%d", cfg->host, cfg->port);
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

                    int sent = sendto(cfg->udp_send_sock, (char*)send_buf, 10 + recv_len, 0,
                          (struct sockaddr *)&cfg->udp_relay_addr, sizeof(cfg->udp_relay_addr));

                    if (sent == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        log_message("[UDP RELAY ERROR] Failed to send to SOCKS5 proxy %s:%d: %d - closing", cfg->host, cfg->port, err);
                        if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
                        if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
                        cfg->udp_connected = FALSE;
                    }
                }
                else
                {
                    log_message("[UDP RELAY] No connection found for port %d", from_port);
                }
            }
        }

        // Check if packet is from any SOCKS5 proxy's UDP socket
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5 || !cfg->udp_connected) continue;
            if (cfg->udp_send_sock == INVALID_SOCKET || !FD_ISSET(cfg->udp_send_sock, &read_fds)) continue;

            from_len = sizeof(from_addr);
            recv_len = recvfrom(cfg->udp_send_sock, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                log_message("[UDP RELAY ERROR] Failed to receive from proxy %s:%d: %d - closing", cfg->host, cfg->port, err);
                if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
                closesocket(cfg->udp_send_sock);
                cfg->udp_send_sock = INVALID_SOCKET;
                cfg->udp_connected = FALSE;
                continue;
            }

            if (recv_len > 0)
            {
                // Packet from SOCKS5 proxy - decapsulate and forward to original sender
                if (recv_len < 10) continue;

                // SOCKS5 UDP packet format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
                if (recv_buf[2] != 0x00) continue;  // FRAG must be 0
                if (recv_buf[3] != SOCKS5_ATYP_IPV4) continue;  // Only IPv4 supported

                UINT32 src_ip = (recv_buf[4] << 0) | (recv_buf[5] << 8) |
                               (recv_buf[6] << 16) | (recv_buf[7] << 24);
                UINT16 src_port = (recv_buf[8] << 8) | recv_buf[9];

                AcquireSRWLockShared(&lock);
                struct sockaddr_in target_addr;
                BOOL found = FALSE;
                UINT32 target_ip = 0;
                UINT16 target_port = 0;
                ULONGLONG best_activity = 0;

                // Scan all buckets and pick the recent active match so 
                // a stale entry from a previous session does not shadow a live one
                // sharing the same destination IP:port
                // https://github.com/InterceptSuite/ProxyBridge/issues/133
                for (int b = 0; b < CONNECTION_HASH_SIZE; b++)
                {
                    CONNECTION_INFO *conn = connection_hash_table[b];
                    while (conn != NULL)
                    {
                        if (conn->orig_dest_ip == src_ip && conn->orig_dest_port == src_port)
                        {
                            if (!found || conn->last_activity > best_activity)
                            {
                                target_ip = conn->src_ip;
                                target_port = conn->src_port;
                                best_activity = conn->last_activity;
                                found = TRUE;
                            }
                        }
                        conn = conn->next;
                    }
                }
                ReleaseSRWLockShared(&lock);

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

    // Clean up all proxy UDP sockets
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
        if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
        cfg->udp_connected = FALSE;
    }
    closesocket(udp_relay_socket);
    udp_relay_socket = INVALID_SOCKET;
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
        if (!get_connection_full(client_port, &conn_config->orig_dest_ip, &conn_config->orig_dest_port, &conn_config->proxy_config_id))
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
    UINT32 proxy_config_id = config->proxy_config_id;
    SOCKET socks_sock;
    struct sockaddr_in socks_addr;

    free(config);

    // Look up the proxy config for this connection
    PROXY_CONFIG *proxy = find_proxy_config(proxy_config_id);
    if (proxy == NULL || proxy->host[0] == '\0' || proxy->port == 0)
    {
        log_message("[RELAY] No proxy config (id=%u) - dropping connection", proxy_config_id);
        closesocket(client_sock);
        return 1;
    }

    // Connect to proxy, use cached resolved IP to avoid DNS per connection
    UINT32 proxy_ip = proxy->resolved_ip ? proxy->resolved_ip : resolve_hostname(proxy->host);
    if (proxy_ip == 0)
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

    // 4 MB kernel socket buffers for the relay sockets.
    // The upload path writes from client→proxy over a real network with non-zero
    // RTT; a small (512 KB) send buffer causes send_all() to block the moment
    // the proxy's receive window fills up, which stalls the relay loop and
    // triggers TCP flow-control on the client side → massive upload throughput
    // loss.  4 MB gives plenty of headroom even at high bitrates / high RTT.
    configure_tcp_socket(socks_sock, 4194304, 30000);  // 4 MB – proxy connection
    configure_tcp_socket(client_sock, 4194304, 30000); // 4 MB – app connection

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = proxy_ip;
    socks_addr.sin_port = htons(proxy->port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        log_message("[RELAY] Failed to connect to proxy %s:%d (%d)", proxy->host, proxy->port, WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    if (proxy->type == PROXY_TYPE_SOCKS5)
    {
        if (socks5_connect(socks_sock, dest_ip, dest_port, proxy) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }
    else if (proxy->type == PROXY_TYPE_HTTP)
    {
        if (http_connect(socks_sock, dest_ip, dest_port, proxy) != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }

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

// One-directional relay: reads from `from` and writes to `to`.
// Runs as a dedicated thread so upload and download never block each other.
// Uses a shared RELAY_PAIR reference count for safe socket cleanup:
//   - whichever direction finishes first calls shutdown() on both sockets,
//     which causes the sibling thread's recv() to return 0 and exit cleanly.
//   - the last thread to exit (refs drops to 0) closes both sockets and
//     frees the shared RELAY_PAIR.
static DWORD WINAPI one_way_relay(LPVOID arg)
{
    ONE_WAY_CONFIG *cfg = (ONE_WAY_CONFIG *)arg;
    RELAY_PAIR *pair = cfg->pair;
    SOCKET from = cfg->from;
    SOCKET to   = cfg->to;
    free(cfg);

    char *buf = (char *)malloc(131072);  // 128 KB per-direction buffer
    if (buf)
    {
        int len;
        while ((len = recv(from, buf, 131072, 0)) > 0)
        {
            if (send_all(to, buf, len) == SOCKET_ERROR)
                break;
        }
        free(buf);
    }

    // Signal the sibling relay to stop by shutting down both sockets.
    // shutdown() is safe to call from any thread; it just drains/resets the
    // socket without closing the handle, so the other thread's recv() returns 0.
    shutdown(pair->sock_client, SD_BOTH);
    shutdown(pair->sock_proxy,  SD_BOTH);

    // Last thread out closes and frees everything.
    if (InterlockedDecrement(&pair->refs) == 0)
    {
        closesocket(pair->sock_client);
        closesocket(pair->sock_proxy);
        free(pair);
    }

    return 0;
}

// Bidirectional relay: spawns one thread for upload (client→proxy) and runs
// the download (proxy→client) direction in the calling thread.  Blocks until
// both directions have finished so the caller (connection_handler) can return
// cleanly and its thread handle can be closed.
static DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET sock_client = config->from_socket;
    SOCKET sock_proxy  = config->to_socket;
    free(config);

    RELAY_PAIR *pair = (RELAY_PAIR *)malloc(sizeof(RELAY_PAIR));
    if (!pair)
    {
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }
    pair->sock_client = sock_client;
    pair->sock_proxy  = sock_proxy;
    pair->refs        = 2;

    // Upload: client → proxy  (dedicated thread — may block on slow proxy send)
    ONE_WAY_CONFIG *up = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));
    // Download: proxy → client (runs in this thread — loopback, rarely blocks)
    ONE_WAY_CONFIG *dn = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));

    if (!up || !dn)
    {
        free(up);
        free(dn);
        free(pair);
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }

    up->pair = pair;  up->from = sock_client;  up->to = sock_proxy;
    dn->pair = pair;  dn->from = sock_proxy;   dn->to = sock_client;

    // Spawn the upload relay in its own thread.
    HANDLE upload_thread = CreateThread(NULL, 0, one_way_relay, up, 0, NULL);
    if (!upload_thread)
    {
        free(up);
        free(dn);
        free(pair);
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }

    // Run the download relay in this thread (blocks until done).
    one_way_relay(dn);

    // Wait for the upload relay thread to finish, then clean up its handle.
    WaitForSingleObject(upload_thread, INFINITE);
    CloseHandle(upload_thread);

    return 0;
}

static void add_connection(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id)
{
    AcquireSRWLockExclusive(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = connection_hash_table[hash];

    // check if already exists in this hash bucket
    while (existing != NULL) {
        if (existing->src_port == src_port) {
            existing->src_ip = src_ip;
            existing->orig_dest_ip = dest_ip;
            existing->orig_dest_port = dest_port;
            existing->proxy_config_id = proxy_config_id;
            existing->is_tracked = TRUE;
            ReleaseSRWLockExclusive(&lock);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&lock);
        return;
    }

    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();

    conn->next = connection_hash_table[hash];
    connection_hash_table[hash] = conn;
    ReleaseSRWLockExclusive(&lock);
}

static BOOL is_connection_tracked(UINT16 src_port)
{
    BOOL tracked = FALSE;
    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_tracked) {
            tracked = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);
    return tracked;
}

static BOOL get_connection(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port)
{
    BOOL found = FALSE;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return found;
}

static BOOL get_connection_full(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id)
{
    BOOL found = FALSE;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            if (proxy_config_id != NULL) *proxy_config_id = conn->proxy_config_id;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return found;
}

static UINT32 get_connection_proxy_id(UINT16 src_port)
{
    UINT32 proxy_config_id = 0;

    AcquireSRWLockShared(&lock);

    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = connection_hash_table[hash];

    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            proxy_config_id = conn->proxy_config_id;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&lock);

    return proxy_config_id;
}

static void remove_connection(UINT16 src_port)
{
    AcquireSRWLockExclusive(&lock);

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
    ReleaseSRWLockExclusive(&lock);
}

static void cleanup_stale_connections(void)
{
    ULONGLONG now = GetTickCount64();

    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        AcquireSRWLockExclusive(&lock);
        CONNECTION_INFO **conn_ptr = &connection_hash_table[i];

        while (*conn_ptr != NULL)
        {
            if (now - (*conn_ptr)->last_activity > 60000)
            {
                CONNECTION_INFO *to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                ReleaseSRWLockExclusive(&lock);
                free(to_free);
                AcquireSRWLockExclusive(&lock);
            }
            else
            {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        ReleaseSRWLockExclusive(&lock);
    }

    ULONGLONG now_cache = GetTickCount64();
    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        AcquireSRWLockExclusive(&lock);
        PID_CACHE_ENTRY **entry_ptr = &pid_cache[i];
        while (*entry_ptr != NULL)
        {
            if (now_cache - (*entry_ptr)->timestamp > 10000)
            {
                PID_CACHE_ENTRY *to_free = *entry_ptr;
                *entry_ptr = (*entry_ptr)->next;
                ReleaseSRWLockExclusive(&lock);
                free(to_free);
                AcquireSRWLockExclusive(&lock);
            }
            else
            {
                entry_ptr = &(*entry_ptr)->next;
            }
        }
        ReleaseSRWLockExclusive(&lock);
    }

    AcquireSRWLockExclusive(&lock);
    int logged_count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL) { logged_count++; temp = temp->next; }

    if (logged_count > 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 99 && temp != NULL; i++)
            temp = temp->next;

        if (temp != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
        }
    }
    ReleaseSRWLockExclusive(&lock);
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id)
{
    if (process_name == NULL || process_name[0] == '\0')
        return 0;

    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (rule == NULL)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy_s(rule->process_name, MAX_PROCESS_NAME, process_name, _TRUNCATE);
    rule->protocol = protocol;
    rule->proxy_config_id = proxy_config_id;

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
    log_message("Added rule ID: %u for process '%s' (Protocol: %d, Action: %d, ProxyConfigId: %u)", rule->rule_id, process_name, protocol, action, proxy_config_id);

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

PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id)
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
            rule->proxy_config_id = proxy_config_id;

            update_has_active_rules();
            log_message("Updated rule ID: %u (ProxyConfigId: %u)", rule_id, proxy_config_id);
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id)
{
    if (rule_id == 0)
        return 0;

    UINT32 position = 1;
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
            return position;
        position++;
        rule = rule->next;
    }
    return 0;
}

PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position)
{
    if (rule_id == 0 || new_position == 0)
        return FALSE;

    // first rule and remove it from current position
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;

    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
            break;
        prev = rule;
        rule = rule->next;
    }

    if (rule == NULL)
        return FALSE;

    // Remove from current position
    if (prev == NULL)
    {
        rules_list = rule->next;
    }
    else
    {
        prev->next = rule->next;
    }

    // Insert at new position
    if (new_position == 1)
    {
        // Insert at head
        rule->next = rules_list;
        rules_list = rule;
    }
    else
    {
        // taken from stackflow
        PROCESS_RULE *current = rules_list;
        UINT32 pos = 1;

        while (current != NULL && pos < new_position - 1)
        {
            current = current->next;
            pos++;
        }

        if (current == NULL)
        {
            // position is beyond list end we can append to tail
            current = rules_list;
            while (current->next != NULL)
                current = current->next;
            current->next = rule;
            rule->next = NULL;
        }
        else
        {
            rule->next = current->next;
            current->next = rule;
        }
    }

    log_message("Moved rule ID %u to position %u", rule_id, new_position);
    return TRUE;
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return 0;

    if (resolve_hostname(proxy_ip) == 0)
        return 0;

    if (g_proxy_config_count >= MAX_PROXY_CONFIGS)
        return 0;

    PROXY_CONFIG *cfg = &g_proxy_configs[g_proxy_config_count];
    memset(cfg, 0, sizeof(PROXY_CONFIG));

    cfg->config_id = g_next_config_id++;
    cfg->type      = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    cfg->port      = proxy_port;
    strncpy_s(cfg->host, sizeof(cfg->host), proxy_ip, _TRUNCATE);
    cfg->resolved_ip = resolve_hostname(proxy_ip);
    if (username != NULL) strncpy_s(cfg->username, sizeof(cfg->username), username, _TRUNCATE);
    if (password != NULL) strncpy_s(cfg->password, sizeof(cfg->password), password, _TRUNCATE);
    cfg->udp_tcp_ctrl  = INVALID_SOCKET;
    cfg->udp_send_sock = INVALID_SOCKET;
    cfg->udp_connected = FALSE;

    g_proxy_config_count++;
    log_message("Added proxy config ID %u: %s:%u (type %d)", cfg->config_id, cfg->host, cfg->port, cfg->type);
    return cfg->config_id;
}

PROXYBRIDGE_API BOOL ProxyBridge_EditProxyConfig(UINT32 config_id, ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (proxy_ip == NULL || proxy_ip[0] == '\0' || proxy_port == 0)
        return FALSE;

    if (resolve_hostname(proxy_ip) == 0)
        return FALSE;

    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->config_id == config_id)
        {
            // Close any open UDP state before changing config
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  cfg->udp_tcp_ctrl  = INVALID_SOCKET; }
            if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
            cfg->udp_connected = FALSE;

            cfg->type = (type == PROXY_TYPE_HTTP) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
            cfg->port = proxy_port;
            strncpy_s(cfg->host, sizeof(cfg->host), proxy_ip, _TRUNCATE);
            cfg->resolved_ip = resolve_hostname(proxy_ip);
            cfg->username[0] = '\0';
            cfg->password[0] = '\0';
            if (username != NULL) strncpy_s(cfg->username, sizeof(cfg->username), username, _TRUNCATE);
            if (password != NULL) strncpy_s(cfg->password, sizeof(cfg->password), password, _TRUNCATE);

            log_message("Edited proxy config ID %u: %s:%u (type %d)", config_id, cfg->host, cfg->port, cfg->type);
            return TRUE;
        }
    }
    return FALSE;
}

PROXYBRIDGE_API BOOL ProxyBridge_DeleteProxyConfig(UINT32 config_id)
{
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->config_id == config_id)
        {
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  }
            if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); }

            // Shift remaining entries down
            int remaining = g_proxy_config_count - i - 1;
            if (remaining > 0)
                memmove(&g_proxy_configs[i], &g_proxy_configs[i + 1], remaining * sizeof(PROXY_CONFIG));

            g_proxy_config_count--;
            log_message("Deleted proxy config ID %u", config_id);
            return TRUE;
        }
    }
    return FALSE;
}

PROXYBRIDGE_API int ProxyBridge_TestProxyConfig(UINT32 config_id, const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size)
{
    PROXY_CONFIG *cfg = find_proxy_config(config_id);
    if (cfg == NULL)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "No proxy config found", _TRUNCATE);
        return -1;
    }

    UINT32 dest_ip = resolve_hostname(target_host);
    if (dest_ip == 0)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to resolve target host", _TRUNCATE);
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to create socket", _TRUNCATE);
        return -1;
    }

    // Set timeout
    DWORD timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port   = htons(cfg->port);
    UINT32 proxy_ip = resolve_hostname(cfg->host);
    if (proxy_ip == 0)
    {
        closesocket(sock);
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to resolve proxy host", _TRUNCATE);
        return -1;
    }
    proxy_addr.sin_addr.s_addr = proxy_ip;

    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0)
    {
        closesocket(sock);
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Failed to connect to proxy", _TRUNCATE);
        return -1;
    }

    int result;
    if (cfg->type == PROXY_TYPE_SOCKS5)
        result = socks5_connect(sock, dest_ip, target_port, cfg);
    else
        result = http_connect(sock, dest_ip, target_port, cfg);

    closesocket(sock);

    if (result == 0)
    {
        if (result_buffer && buffer_size > 0)
            strncpy_s(result_buffer, buffer_size, "Connection successful", _TRUNCATE);
        return 0;
    }
    else
    {
        if (result_buffer && buffer_size > 0)
            snprintf(result_buffer, buffer_size, "Connection failed (code %d)", result);
        return result;
    }
}

PROXYBRIDGE_API void ProxyBridge_SetDnsViaProxy(BOOL enable)
{
    g_dns_via_proxy = enable;
    log_message("DNS routing: %s", enable ? "via proxy" : "direct");
}

PROXYBRIDGE_API void ProxyBridge_SetLocalhostViaProxy(BOOL enable)
{
    g_localhost_via_proxy = enable;
    log_message("Localhost routing: %s (most proxies block localhost for SSRF prevention)", enable ? "via proxy" : "direct");
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
    AcquireSRWLockShared(&lock);

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

    ReleaseSRWLockShared(&lock);
    return found;
}


static void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action)
{
    AcquireSRWLockExclusive(&lock);

    int count = 0;
    LOGGED_CONNECTION *temp = logged_connections;
    while (temp != NULL) { count++; temp = temp->next; }

    if (count >= 100)
    {
        temp = logged_connections;
        for (int i = 0; i < 98 && temp != NULL; i++)
            temp = temp->next;

        if (temp != NULL && temp->next != NULL)
        {
            LOGGED_CONNECTION *to_free_list = temp->next;
            temp->next = NULL;

            ReleaseSRWLockExclusive(&lock);
            while (to_free_list != NULL)
            {
                LOGGED_CONNECTION *next = to_free_list->next;
                free(to_free_list);
                to_free_list = next;
            }
            AcquireSRWLockExclusive(&lock);
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

    ReleaseSRWLockExclusive(&lock);
}

static void clear_logged_connections(void)
{
    AcquireSRWLockExclusive(&lock);

    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }

    ReleaseSRWLockExclusive(&lock);
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

    AcquireSRWLockShared(&lock);

    PID_CACHE_ENTRY *entry = pid_cache[hash];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->src_port == src_port &&
            entry->is_udp == is_udp)
        {
            pid = (current_time - entry->timestamp < PID_CACHE_TTL_MS) ? entry->pid : 0;
            break;
        }
        entry = entry->next;
    }

    ReleaseSRWLockShared(&lock);
    return pid;
}

static void cache_pid(UINT32 src_ip, UINT16 src_port, DWORD pid, BOOL is_udp)
{
    UINT32 hash = pid_cache_hash(src_ip, src_port, is_udp);
    ULONGLONG current_time = GetTickCount64();

    AcquireSRWLockExclusive(&lock);

    PID_CACHE_ENTRY *entry = pid_cache[hash];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->src_port == src_port &&
            entry->is_udp == is_udp)
        {
            entry->pid = pid;
            entry->timestamp = current_time;
            ReleaseSRWLockExclusive(&lock);
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

    ReleaseSRWLockExclusive(&lock);
}

static void clear_pid_cache(void)
{
    AcquireSRWLockExclusive(&lock);

    for (int i = 0; i < PID_CACHE_SIZE; i++)
    {
        while (pid_cache[i] != NULL)
        {
            PID_CACHE_ENTRY *to_free = pid_cache[i];
            pid_cache[i] = pid_cache[i]->next;
            free(to_free);
        }
    }

    ReleaseSRWLockExclusive(&lock);
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

    InitializeSRWLock(&lock);

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

    if (any_socks5_config())
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
        "(tcp and (outbound or loopback or (tcp.DstPort == %d or tcp.SrcPort == %d))) or (udp and (outbound or loopback or (udp.DstPort == %d or udp.SrcPort == %d)))",
        g_local_relay_port, g_local_relay_port, LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

    // Note: Added 'loopback' to filter to capture localhost (127.x.x.x) traffic
    // This enables proxying local connections for MITM scenarios
    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE)
    {
        DWORD wd_err = GetLastError();
        switch (wd_err)
        {
            case 2:    // ERROR_FILE_NOT_FOUND
                log_message("Failed to open WinDivert (%lu): WinDivert64.sys not found - it may have been quarantined or deleted by antivirus. Whitelist WinDivert64.sys and ProxyBridgeCore.dll in your AV and reinstall.", wd_err);
                break;
            case 5:    // ERROR_ACCESS_DENIED
                log_message("Failed to open WinDivert (%lu): Access denied - make sure ProxyBridge is running as Administrator.", wd_err);
                break;
            case 577:  // ERROR_INVALID_IMAGE_HASH - driver signature check failed
                log_message("Failed to open WinDivert (%lu): Driver signature verification failed - WinDivert64.sys may have been modified or blocked by security software. Reinstall ProxyBridge.", wd_err);
                break;
            case 1058: // ERROR_SERVICE_DISABLED
                log_message("Failed to open WinDivert (%lu): A stale WinDivert driver entry from a previous install is marked disabled. Reinstall ProxyBridge to fix it, or manually delete the registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert", wd_err);
                break;
            case 1275: // ERROR_DRIVER_BLOCKED
                log_message("Failed to open WinDivert (%lu): WinDivert64.sys is blocked by Windows security policy or antivirus (BYOVD protection). Whitelist WinDivert64.sys in your security software.", wd_err);
                break;
            default:
                log_message("Failed to open WinDivert (%lu): Ensure ProxyBridge is installed correctly and running as Administrator.", wd_err);
                break;
        }
        running = FALSE;
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
        return FALSE;
    }

    // WINDIVERT_PARAM_QUEUE_LENGTH: max packets in queue (range 32–16384).
    // Under heavy upload the kernel enqueues bursts of outbound packets faster
    // than the 4 packet threads can drain them; a full queue drops arriving
    // packets → TCP sees loss → retransmit + congestion-window halving.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    // WINDIVERT_PARAM_QUEUE_TIME: ms a packet waits before being dropped
    // (range 100–16000, default 2000).  The old value of 8 ms was below the
    // minimum (100 ms) and caused aggressive packet drops under any sustained
    // upload load, directly producing the 40-60% upload throughput loss.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    // WINDIVERT_PARAM_QUEUE_SIZE: max total bytes in queue (range 65535–33553920).
    // Raise to the maximum so a burst of large packets never hits a byte cap.
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_SIZE, 33553920);

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
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        log_message("Proxy config ID %u: %s %s:%u",
            cfg->config_id,
            cfg->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
            cfg->host, cfg->port);
    }
    if (g_proxy_config_count == 0)
        log_message("Warning: No proxy configs configured");

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

    AcquireSRWLockExclusive(&lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++)
    {
        while (connection_hash_table[i] != NULL)
        {
            CONNECTION_INFO *to_free = connection_hash_table[i];
            connection_hash_table[i] = connection_hash_table[i]->next;
            free(to_free);
        }
    }
    ReleaseSRWLockExclusive(&lock);

    // Clear logged connections list
    clear_logged_connections();

    clear_pid_cache();

    // Reset per-port decision cache so stale entries don't carry over
    // if ProxyBridge is stopped and restarted with different rules.
    memset((void*)port_decided_bitmap, 0, sizeof(port_decided_bitmap));
    memset((void*)port_direct_bitmap,  0, sizeof(port_direct_bitmap));

    log_message("ProxyBridge stopped");

    return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Store the PID of the process that loaded this DLL
            g_current_process_id = GetCurrentProcessId();
            // Initialize Winsock here so that resolve_hostname() / getaddrinfo()
            // work correctly when AddProxyConfig is called before any thread
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
            break;
        }
        case DLL_PROCESS_DETACH:
            WSACleanup();
            if (running)
                ProxyBridge_Stop();
            // Close all proxy config UDP sockets
            for (int i = 0; i < g_proxy_config_count; i++)
            {
                PROXY_CONFIG *cfg = &g_proxy_configs[i];
                if (cfg->udp_tcp_ctrl != INVALID_SOCKET)  { closesocket(cfg->udp_tcp_ctrl);  cfg->udp_tcp_ctrl  = INVALID_SOCKET; }
                if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
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