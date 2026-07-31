#ifndef PB_INTERNAL_H
#define PB_INTERNAL_H

// Shared internal declarations for the ProxyBridge core, split across
// ProxyBridge.c (globals + lifecycle), pb_net.c, pb_rules.c, pb_conn.c.
// Defines, structs, extern globals and cross-module prototypes live here.

#include <winsock2.h>
#include <windows.h>
#include "ProxyBridge.h"
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAXBUF 0xFFFF
#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011  // its running UDP port still make sure to not run on same port as TCP, opening same port and tcp and udp cause issue and handling port at relay server response injection
#define MAX_PROCESS_NAME 1024
#define VERSION "4.0.13-Beta"
#define CONNECTION_HASH_SIZE 4096
#define SOCKS5_BUFFER_SIZE 1024
#define HTTP_BUFFER_SIZE 1024
#define FILTER_BUFFER_SIZE 1024
#define LOG_BUFFER_SIZE 1024
#define MAX_LIST_SIZE 65536  // max byte length for semicolon-delimited host/port/process lists

typedef struct PROCESS_RULE {
    UINT32 rule_id;
    char process_name[MAX_PROCESS_NAME];
    char *target_hosts;   // Dynamic: IP filter "*", "192.168.*.*", "10.0.0.1;172.16.0.0"
    char *target_ports;   // Dynamic: Port filter "*", "80", "80;443", "8000-9000"
    char *target_domains; // Dynamic: Domain filter "*", "google.com", "*.google.com;*.gstatic.com" ("" or "*" = no domain restriction)
    RuleProtocol protocol;  // TCP, UDP, or BOTH
    RuleAction action;
    UINT32 proxy_config_id;  // Which proxy config to route this rule through (0 = first available)
    BOOL enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_IPV6   0x04
#define SOCKS5_ATYP_DOMAIN 0x03  // send hostname to proxy rfc 1928
#define SOCKS5_AUTH_NONE   0x00

// Idle timeout before a connection-tracking entry is reaped. Clean closes are removed
// immediately on FIN/RST, so this only sweeps entries whose FIN/RST was missed. It MUST
// exceed the relay's TCP keepalive interval (5 min) and real idle periods (IMAP IDLE,
// voice channels, WebSocket, DB pools) - otherwise an open-but-idle proxied connection
// gets reaped mid-session and silently breaks until restart (issue: hours-long degradation).
#define CONNECTION_STALE_TIMEOUT_MS 1800000  // 30 minutes

// DNS snooping cache: maps intercepted A-record answers to their hostnames so
// that SOCKS5 connect can forward ATYP_DOMAIN instead of ATYP_IPV4, letting
// proxy servers that do their own name-resolution (e.g. mihomo) see the
// original hostname rather than a bare IP.  (Resolves issue #138.)
#define DNS_CACHE_BUCKETS 1024
#define DNS_CACHE_TTL_MS  300000  // 5 minutes

typedef struct DNS_CACHE_ENTRY {
    UINT32 ip;              // network-byte-order IPv4 
    char   domain[256];
    ULONGLONG expire_tick;
    struct DNS_CACHE_ENTRY *next;
} DNS_CACHE_ENTRY;

typedef struct DNS_CACHE_ENTRY_V6 {
    UINT8  ip6[16];         // raw IPv6 address
    char   domain[256];
    ULONGLONG expire_tick;
    struct DNS_CACHE_ENTRY_V6 *next;
} DNS_CACHE_ENTRY_V6;

typedef struct CONNECTION_INFO {
    UINT16 src_port;
    BOOL   is_udp;             // protocol - a TCP and a UDP flow may share a local port
    UINT32 src_ip;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    BOOL   is_tracked;
    ULONGLONG last_activity;
    UINT32 proxy_config_id;
    BOOL   is_ipv6;
    UINT8  src_ip6[16];        // raw IPv6 src (only valid when is_ipv6)
    UINT8  orig_dest_ip6[16];  // raw IPv6 dest (only valid when is_ipv6)
    struct CONNECTION_INFO *next;      // chain in the forward table (keyed by src_port)
    struct CONNECTION_INFO *rev_next;  // chain in the reverse table (keyed by orig_dest)
    UINT32 rev_bucket;                 // reverse bucket this entry is currently linked in
    BOOL   in_rev;                     // TRUE while linked in the reverse table
} CONNECTION_INFO;

typedef struct {
    SOCKET client_socket;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    UINT32 proxy_config_id;
    BOOL   is_ipv6;
    UINT8  orig_dest_ip6[16];
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

typedef struct LOGGED_CONNECTION {
    DWORD pid;
    UINT32 dest_ip;
    UINT16 dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

// Internal proxy configuration with per-config UDP SOCKS5 state
typedef struct {
    UINT32 config_id;           // Unique ID (1-based), 0 = unused slot
    ProxyType type;
    char host[256];
    UINT16 port;
    char username[256];
    char password[256];
    BOOL send_domain_to_proxy;  // TRUE = proxy resolves DNS (send hostname), FALSE = send IP
    UINT32 resolved_ip;         // cached at add/edit time - avoids DNS per connection
    ULONGLONG last_udp_attempt;
    SOCKET udp_tcp_ctrl;
    SOCKET udp_send_sock;
    struct sockaddr_in udp_relay_addr;
    BOOL udp_connected;
} PROXY_CONFIG;

typedef BOOL (*token_match_func)(const char *token, const void *data);

// ---- shared globals (defined in ProxyBridge.c) ----
extern PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
extern int g_proxy_config_count;
extern UINT32 g_next_config_id;
extern CONNECTION_INFO *connection_hash_table[CONNECTION_HASH_SIZE];
extern CONNECTION_INFO *connection_rev_table[CONNECTION_HASH_SIZE];
extern LOGGED_CONNECTION *logged_connections;
extern int g_logged_count;  // running length of logged_connections (guarded by `lock`)
extern PROCESS_RULE *rules_list;
extern UINT32 g_next_rule_id;
extern SRWLOCK lock;
extern SRWLOCK g_rules_lock;
extern HANDLE proxy_thread;
extern HANDLE udp_relay_thread;
extern HANDLE cleanup_thread;
extern volatile BOOL g_has_active_rules;
extern volatile BOOL g_has_domain_rules;
extern SOCKET udp_relay_socket;
extern SOCKET udp_relay_socket6;
extern volatile BOOL running;
extern DWORD g_current_process_id;
extern BOOL g_traffic_logging_enabled;
extern DNS_CACHE_ENTRY    *g_dns_cache[DNS_CACHE_BUCKETS];
extern DNS_CACHE_ENTRY_V6 *g_dns_cache_v6[DNS_CACHE_BUCKETS];
extern SRWLOCK             g_dns_cache_lock;
extern volatile LONG port_decided_bitmap[2048];  // 8 KB
extern volatile LONG port_direct_bitmap[2048];  // 8 KB
extern UINT16 g_local_relay_port;
extern BOOL g_localhost_via_proxy;  // default disabled for security - most proxy server block localhost for ssrf and also many app might not work if localhost trafic goes to remote server if proxy server is on diffrent machine
extern LogCallback g_log_callback;
extern ConnectionCallback g_connection_callback;

// ---- per-source-port decision bitmaps: hot-path inline helpers ----
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

// ---- pb_util.c ----
void log_message(const char *msg, ...);
const char* extract_filename(const char* path);
char* skip_whitespace(char *str);
void format_ip_address(UINT32 ip, char *buffer, size_t size);
BOOL parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data);
void configure_tcp_socket(SOCKET sock, int bufsize, DWORD timeout);
int connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int timeout_ms);
void configure_udp_socket(SOCKET sock, int bufsize, DWORD timeout);
int send_all(SOCKET sock, const char *buf, int len);
int recv_n(SOCKET s, char *buf, int n);
UINT32 parse_ipv4(const char *ip);
UINT32 resolve_hostname(const char *hostname);
void base64_encode(const char* input, char* output, size_t output_size);

// ---- pb_process.c ----
BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);

// ---- pb_rules.c ----
BOOL is_ipv6_multicast_or_linklocal(const UINT8 ip6[16]);
BOOL match_ip_pattern(const char *pattern, UINT32 ip);
BOOL match_port_pattern(const char *pattern, UINT16 port);
BOOL ip_match_wrapper(const char *token, const void *data);
BOOL match_ip_list(const char *ip_list, UINT32 ip);
BOOL match_ip_pattern_v6(const char *pattern, const UINT8 ip6[16]);
BOOL ip_match_wrapper_v6(const char *token, const void *data);
BOOL match_ip_list_v6(const char *ip_list, const UINT8 ip6[16]);
BOOL port_match_wrapper(const char *token, const void *data);
BOOL match_port_list(const char *port_list, UINT16 port);
BOOL wildcard_match(const char *pattern, const char *text);
BOOL match_process_pattern(const char *pattern, const char *process_full_path);
BOOL match_process_list(const char *process_list, const char *process_name);
BOOL match_domain_pattern(const char *pattern, const char *domain);
BOOL match_domain_list(const char *domain_list, const char *domain);
BOOL rule_has_domain_filter(const PROCESS_RULE *rule);
BOOL match_domain_filter(const PROCESS_RULE *rule, const char *domain);
BOOL is_broadcast_or_multicast(UINT32 ip);
RuleAction match_rule_inner(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id);
RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id);
RuleAction match_rule_v6_inner(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id);
RuleAction match_rule_v6(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id);
void update_has_active_rules(void);

// ---- pb_proxy.c ----
// Guards g_proxy_configs[] + g_proxy_config_count against concurrent Add/Edit/Delete (GUI
// thread) vs. relay/drain readers. Delete tombstones a slot (config_id=0) instead of shifting
// the array, so pointers/indices held by other threads stay valid.
extern SRWLOCK g_proxy_lock;
PROXY_CONFIG* find_proxy_config(UINT32 config_id);
// Snapshot a config into *out under the lock - use this on the TCP path where the caller holds
// the config across blocking network I/O and must be immune to a concurrent Edit/Delete.
BOOL find_proxy_config_copy(UINT32 config_id, PROXY_CONFIG *out);
BOOL any_socks5_config(void);
BOOL is_proxy_config_referenced(UINT32 config_id);

// ---- pb_dns.c ----
void dns_cache_init(void);
UINT32 dns_bucket(UINT32 ip);
void dns_cache_store(UINT32 ip, const char *domain);
BOOL dns_cache_lookup(UINT32 ip, char *out_domain, size_t out_size);
UINT32 dns_bucket_v6(const UINT8 ip6[16]);
void dns_cache_store_v6(const UINT8 ip6[16], const char *domain);
BOOL dns_cache_lookup_v6(const UINT8 ip6[16], char *out_domain, size_t out_size);
BOOL dns_parse_name(const UINT8 *msg, int msg_len, int *offset, char *dst, int dst_len);
void snoop_dns_response(const UINT8 *payload, int payload_len);
void cleanup_stale_dns_cache(void);
void flush_dns_resolver_cache(void);

// ---- pb_socks5.c ----
int socks5_read_connect_reply(SOCKET s, int *reply);
int socks5_connect_domain(SOCKET s, const char *hostname, UINT16 dest_port, const PROXY_CONFIG *cfg);
int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg);
int socks5_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg);
int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg);
BOOL establish_udp_associate_for_config(PROXY_CONFIG *cfg);

// ---- pb_http.c ----
int http_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg);
int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg);

// ---- pb_conntrack.c ----
UINT32 rev_hash_v4(UINT32 dest_ip, UINT16 dest_port);
UINT32 rev_hash_v6(const UINT8 dest_ip6[16], UINT16 dest_port);
void rev_insert(CONNECTION_INFO *c);
void rev_unlink(CONNECTION_INFO *c);
void add_connection(UINT16 src_port, BOOL is_udp, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id);
BOOL get_connection_full_v6(UINT16 src_port, BOOL is_udp, UINT8 dest_ip6[16], UINT16 *dest_port, UINT32 *proxy_config_id);
BOOL find_v6_udp_sender(const UINT8 orig_dest_ip6[16], UINT16 orig_dest_port, UINT8 src_ip6[16], UINT16 *src_port);
BOOL get_connection(UINT16 src_port, BOOL is_udp, UINT32 *dest_ip, UINT16 *dest_port);
BOOL get_connection_full(UINT16 src_port, BOOL is_udp, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id);
UINT32 get_connection_proxy_id(UINT16 src_port, BOOL is_udp);
void remove_connection(UINT16 src_port, BOOL is_udp, BOOL is_ipv6);
void cleanup_stale_connections(void);
BOOL is_connection_already_logged(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
void add_logged_connection(DWORD pid, UINT32 dest_ip, UINT16 dest_port, RuleAction action);
void pb_report_connection(DWORD pid, const char *name_override, BOOL is_ipv6, UINT32 dest_ip,
                          const UINT8 dest_ip6[16], UINT16 dest_port, RuleAction action,
                          UINT32 cfg_id, BOOL is_udp);
void clear_logged_connections(void);

// ---- pb_relay.c ----
DWORD WINAPI udp_relay_server(LPVOID arg);
DWORD WINAPI local_proxy_server(LPVOID arg);
DWORD WINAPI connection_handler(LPVOID arg);
DWORD WINAPI one_way_relay(LPVOID arg);
DWORD WINAPI transfer_handler(LPVOID arg);

// ---- ProxyBridge.c ----
DWORD WINAPI cleanup_worker(LPVOID arg);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

// ---- pb_driver.c (WFP driver integration, opt-in via PROXYBRIDGE_USE_DRIVER) ----
extern BOOL g_use_wfp_driver;
BOOL pb_driver_start(UINT16 relay_port);
void pb_driver_stop(void);
void pb_driver_sync_rules(void);   // re-push watch list after a rule change (no-op until started)
void pb_driver_sync_config(void);  // re-push config after a setting change (e.g. localhost-via-proxy)
BOOL pb_driver_orig_dest(SOCKET s, UINT32 *ip, UINT16 *port, DWORD *pid);
BOOL pb_driver_orig_dest6(SOCKET s, UINT8 ip6[16], UINT16 *port, DWORD *pid);
BOOL pb_driver_udp_orig(UINT32 src_ip, UINT16 src_port, UINT32 *ip, UINT16 *port, DWORD *pid);

#endif // PB_INTERNAL_H
