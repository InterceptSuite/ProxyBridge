#ifndef PROXYBRIDGE_H
#define PROXYBRIDGE_H

#define PROXYBRIDGE_VERSION "4.0.0"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PB_API __attribute__((visibility("default")))

typedef void (*LogCallback)(const char* message);
typedef void (*ConnectionCallback)(const char* process_name, uint32_t pid, const char* dest_ip, uint16_t dest_port, const char* proxy_info);

typedef enum {
    PROXY_TYPE_HTTP = 0,
    PROXY_TYPE_SOCKS5 = 1
} ProxyType;

typedef enum {
    RULE_ACTION_PROXY = 0,
    RULE_ACTION_DIRECT = 1,
    RULE_ACTION_BLOCK = 2
} RuleAction;

typedef enum {
    RULE_PROTOCOL_TCP = 0,
    RULE_PROTOCOL_UDP = 1,
    RULE_PROTOCOL_BOTH = 2
} RuleProtocol;

/* ---- Proxy configurations -------------------------------------------------------------------------------------------
 * Any number of proxies can be registered. Ids are non-zero and stable until the proxy is deleted.
 * Returns 0 on failure (the reason is written to err, if given). */
PB_API uint32_t ProxyBridge_AddProxy(const char* name, ProxyType type, const char* host, uint16_t port,
                              const char* username, const char* password, char* err, size_t err_size);
PB_API bool     ProxyBridge_EditProxy(uint32_t proxy_id, const char* name, ProxyType type, const char* host, uint16_t port,
                               const char* username, const char* password, char* err, size_t err_size);
/* "DNS via proxy" of one proxy (default true, as in the Windows and macOS apps): connections to an address whose host name the
 * application resolved are sent to the proxy by name, so the proxy resolves it (SOCKS5 domain address / HTTP CONNECT host name).
 * False sends the IP address. Names come from the application's own unencrypted DNS answers; without one the IP is sent.
 * UDP datagrams always carry the IP. */
PB_API bool     ProxyBridge_SetProxySendDomain(uint32_t proxy_id, bool send_domain);
PB_API bool     ProxyBridge_DeleteProxy(uint32_t proxy_id);   /* rules that used it fall back to the default proxy */
PB_API void     ProxyBridge_ClearProxies(void);
/* Which proxy a rule with proxy_id == 0 uses. 0 = the first proxy added. */
PB_API void     ProxyBridge_SetDefaultProxy(uint32_t proxy_id);

/* ---- Rules ----------------------------------------------------------------------------------------------------------
 * Rules are evaluated in list order, first match wins. process_name: ';' or ',' separated globs matched against the
 * executable's full path and file name ("*" or empty = any). target_hosts: ';' or ',' separated IPv4/IPv6 addresses,
 * CIDR (10.0.0.0/8), a-b ranges, octet wildcards (192.168.*.*) or "*" ("" = any). target_ports: list and ranges
 * ("80;443;8000-9000", "" or "*" = any).
 * proxy_id applies when action == RULE_ACTION_PROXY; 0 = default proxy.
 * AddRule returns the new rule id, or 0 on validation failure (reason in err). */
PB_API uint32_t ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports,
                             RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char* err, size_t err_size);
PB_API bool     ProxyBridge_EditRule(uint32_t rule_id, const char* process_name, const char* target_hosts, const char* target_ports,
                              RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char* err, size_t err_size);
/* "Also proxy localhost traffic" of one PROXY rule (default false): connections to 127.0.0.0/8 and ::1 that match the rule go to
 * the proxy. Without it a PROXY rule leaves loopback traffic direct, as Windows does. BLOCK and DIRECT rules never touch
 * loopback, and neither does DNS to the local resolver stub (port 53). */
PB_API bool     ProxyBridge_SetRuleLocalhost(uint32_t rule_id, bool localhost_via_proxy);
PB_API bool     ProxyBridge_EnableRule(uint32_t rule_id);
PB_API bool     ProxyBridge_DisableRule(uint32_t rule_id);
PB_API bool     ProxyBridge_DeleteRule(uint32_t rule_id);
PB_API bool     ProxyBridge_MoveRule(uint32_t rule_id, int new_index);   /* reorder: priority = position */
PB_API void     ProxyBridge_ClearRules(void);
/* Validates a rule without adding it; returns true if valid, otherwise writes the reason to err. */
PB_API bool     ProxyBridge_ValidateRule(const char* process_name, const char* target_hosts, const char* target_ports,
                                  char* err, size_t err_size);

/* ---- Legacy single-proxy helper -------------------------------------------------------------------------------------
 * Sets (creating on first use) the default proxy. Equivalent to Add/EditProxy on the "default" entry. */
PB_API bool ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, uint16_t proxy_port, const char* username, const char* password);

/* ---- Runtime --------------------------------------------------------------------------------------------------------- */
PB_API void ProxyBridge_SetDnsViaProxy(bool enable);
/* Batch: between BeginBatch and EndBatch, changes to proxies and rules are collected and loaded into the kernel datapath once, at
 * the end, so replacing a whole configuration never exposes a half-built rule set to new connections. Calls nest; every
 * BeginBatch needs an EndBatch. */
PB_API void ProxyBridge_BeginBatch(void);
PB_API void ProxyBridge_EndBatch(void);
/* Main switch (default true). False pauses every rule for new connections; existing connections are not touched. */
PB_API void ProxyBridge_SetEnabled(bool enable);
/* Connection log: by default a connection is reported once per (application, destination, port, protocol, action); true reports
 * every new TCP connection and every new UDP flow (a UDP flow again after 30 s of silence). ClearConnectionLogs forgets the history. */
PB_API void ProxyBridge_SetLogEveryConnection(bool enable);
PB_API void ProxyBridge_SetLogCallback(LogCallback callback);
PB_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
/* Same events with the protocol ("TCP" or "UDP") as well; both callbacks may be set. */
typedef void (*ConnectionCallbackEx)(const char* process_name, uint32_t pid, const char* dest_ip, uint16_t dest_port, const char* protocol, const char* proxy_info);
PB_API void ProxyBridge_SetConnectionCallbackEx(ConnectionCallbackEx callback);
PB_API void ProxyBridge_SetTrafficLoggingEnabled(bool enable);
PB_API void ProxyBridge_ClearConnectionLogs(void);
PB_API bool ProxyBridge_Start(void);   /* needs root (CAP_BPF/CAP_SYS_ADMIN) and a BTF kernel >= 5.11; returns false and logs why on failure */
PB_API bool ProxyBridge_Stop(void);    /* keeps rules and proxies; Start() may be called again */
/* Live connections: the TCP connections and UDP flows ProxyBridge is relaying through a proxy right now (direct and blocked traffic
 * is not part of it). Newest first, at most PB_FLOWS_MAX; cheap enough to poll about once a second. UDP flows are refreshed once
 * a second and stay listed for 30 s after their last datagram. Returns the number of entries written. */
#define PB_FLOWS_MAX 400
typedef struct {
    uint64_t id;             /* stable for the life of the flow */
    uint32_t pid;
    uint32_t proxy_id;
    uint32_t age_ms;         /* time since the flow started */
    uint64_t sent;           /* payload bytes application -> proxy */
    uint64_t received;       /* payload bytes proxy -> application */
    uint16_t port;           /* destination port */
    uint8_t  is_udp;
    uint8_t  is_ipv6;
    uint8_t  dest[16];       /* destination address (IPv4 as ::ffff:a.b.c.d) */
    char     name[40];       /* process name */
    char     host[64];       /* destination: the DNS name the application resolved if known, otherwise the address */
} ProxyBridgeFlow;
PB_API uint32_t ProxyBridge_GetFlows(ProxyBridgeFlow* out, uint32_t max);

/* Multi-step check (reach the proxy, open a tunnel and log in, load a page, measure tunnel set-up, probe UDP). Streams human readable
 * lines to the callback (called on the calling thread). Returns 0 when the proxy works, -1 when it cannot be reached, -2 when it
 * refuses the tunnel or the login. Works without ProxyBridge_Start(). */
typedef void (*ProxyTestLogCallback)(const char* line, void* user);
PB_API int  ProxyBridge_TestProxyEx(uint32_t proxy_id, const char* target_host, uint16_t target_port, ProxyTestLogCallback callback, void* user);
PB_API int  ProxyBridge_TestConnection(const char* target_host, uint16_t target_port, char* result_buffer, size_t buffer_size);
PB_API int  ProxyBridge_TestProxy(uint32_t proxy_id, const char* target_host, uint16_t target_port, char* result_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
