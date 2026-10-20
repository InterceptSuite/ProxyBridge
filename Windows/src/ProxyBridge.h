#ifndef PROXYBRIDGE_H
#define PROXYBRIDGE_H

#include <windows.h>

#ifdef PROXYBRIDGE_EXPORTS
#define PROXYBRIDGE_API __declspec(dllexport)
#else
#define PROXYBRIDGE_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROXY_CONFIGS 32

typedef void (*LogCallback)(const char* message);
typedef void (*ConnectionCallback)(const char* process_name, DWORD pid, const char* dest_ip, UINT16 dest_port, const char* proxy_info);

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

// Multiple proxy config management
// proxy_ip can be IP address or hostname; returns config_id (>0) on success, 0 on failure
// send_domain_to_proxy: TRUE = the proxy resolves DNS (send hostname; socks5h / CONNECT domain),
//                       FALSE = resolve locally and send the IP (socks5 / CONNECT ip). Per-config.
PROXYBRIDGE_API UINT32 ProxyBridge_AddProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL send_domain_to_proxy);
PROXYBRIDGE_API BOOL   ProxyBridge_EditProxyConfig(UINT32 config_id, ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL send_domain_to_proxy);
PROXYBRIDGE_API BOOL   ProxyBridge_DeleteProxyConfig(UINT32 config_id);
PROXYBRIDGE_API int    ProxyBridge_TestProxyConfig(UINT32 config_id, const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size);
// Detailed multi-step proxy check (like Proxifier's Proxy Checker). Streams human-readable
// log lines through the callback: TCP reach, tunnel + auth, page load, latency, and - for
// SOCKS5 - a UDP ASSOCIATE probe. Returns 0 if the critical tests passed, negative otherwise.
typedef void (*ProxyTestLogCallback)(const char* line, void* user);
PROXYBRIDGE_API int    ProxyBridge_TestProxyConfigEx(UINT32 config_id, const char* target_host, UINT16 target_port, ProxyTestLogCallback callback, void* user);

// Rule management - proxy_config_id selects which proxy config the rule uses (0 = first available)
// localhost_via_proxy: per rule. TRUE = connections to localhost (127.x / ::1) that match this rule are proxied;
// FALSE = they are sent direct (most proxies refuse localhost, and it never reaches a remote proxy's own machine).
// target_domains: semicolon/comma separated domain patterns ("*", "google.com", "*.google.com"); NULL/"" = no domain restriction.
// Domain matching relies on DNS snooping of the app's own resolutions; unencrypted DNS only (DoH/DoT bypasses it).
PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id, BOOL localhost_via_proxy);
PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id, BOOL localhost_via_proxy);
PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position);  // Move rule to specific position (1=first, 2=second, etc)
PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id);  // Get current position of rule in list (1-based)
// Live connections: the flows ProxyBridge is relaying right now (proxied TCP connections and proxied UDP flows).
// Direct and blocked traffic is not part of it - the engine never sees its data.
#define PB_FLOWS_MAX 400
typedef struct {
    UINT64 id;               // stable for the life of the flow
    UINT32 pid;
    UINT32 proxy_config_id;
    UINT32 rule_id;          // the rule that sent it through the proxy (0 = not known)
    UINT32 age_ms;           // time since the flow started; 0xFFFFFFFF = not known (UDP)
    UINT64 sent;             // payload bytes application -> proxy
    UINT64 received;         // payload bytes proxy -> application
    UINT16 port;             // destination port
    UINT8  is_udp;
    UINT8  is_ipv6;
    UINT8  dest[16];         // raw destination address (the engine resolves it into `host`)
    char   name[40];         // process image name (UTF-8)
    char   host[64];         // destination: the domain if known, otherwise the address (UTF-8)
} PB_FLOW;
// Fills `out` with up to `max` (at most PB_FLOWS_MAX) live flows, newest first. Cheap enough to poll about once a second.
PROXYBRIDGE_API UINT32 ProxyBridge_GetFlows(PB_FLOW* out, UINT32 max);
PROXYBRIDGE_API void ProxyBridge_SetLogEveryConnection(BOOL enable);   // FALSE (default): Connections log skips repeats; TRUE: every new connection
PROXYBRIDGE_API void ProxyBridge_SetEnabled(BOOL enable);   // main switch: FALSE pauses all rules for new connections (default TRUE)
PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback);
PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable);
PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void);  // Clear connection history from memory
PROXYBRIDGE_API BOOL ProxyBridge_Start(void);
PROXYBRIDGE_API BOOL ProxyBridge_Stop(void);
#ifdef __cplusplus
}
#endif

#endif
