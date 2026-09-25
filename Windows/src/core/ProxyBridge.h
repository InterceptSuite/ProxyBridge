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

#define MAX_PROXY_CONFIGS 16

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
// target_domains: semicolon/comma separated domain patterns ("*", "google.com", "*.google.com"); NULL/"" = no domain restriction.
// Domain matching relies on DNS snooping of the app's own resolutions; unencrypted DNS only (DoH/DoT bypasses it).
PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id);
typedef struct ProxyBridgeProxySpec {
    ProxyType type;
    const char *host;
    UINT16 port;
    const char *username;
    const char *password;
    BOOL send_domain_to_proxy;
} ProxyBridgeProxySpec;
// Input strings remain valid for the call. IDs are written only after success.
typedef struct ProxyBridgeRuleSpec {
    const char *process_name;
    const char *target_hosts;
    const char *target_ports;
    const char *target_domains;
    RuleProtocol protocol;
    RuleAction action;
    UINT32 proxy_config_id;
    BOOL enabled;
} ProxyBridgeRuleSpec;
PROXYBRIDGE_API BOOL ProxyBridge_ReplaceRules(const ProxyBridgeRuleSpec *rules, UINT32 count, UINT32 *out_ids);
// For this operation rule.proxy_config_id is a 1-based index in configs, or
// 0 for the default. Both output ID arrays change only after a successful commit.
// Identical proxy definitions retain their IDs; changed/new definitions receive new IDs.
PROXYBRIDGE_API BOOL ProxyBridge_ReplaceProfile(const ProxyBridgeProxySpec *configs, UINT32 config_count,
    const ProxyBridgeRuleSpec *rules, UINT32 rule_count, UINT32 *config_ids, UINT32 *rule_ids, BOOL loopback);
// Preparation copies all inputs and may resolve names; it does not publish or
// hold the writer gate. A handle has one owner. Commit consumes it on ANY result;
// otherwise discard it. Commit rejects changes to rules/proxies since preparation
// with ERROR_REVISION_MISMATCH. ID buffers need the original input counts.
PROXYBRIDGE_API void *ProxyBridge_PrepareProfile(const ProxyBridgeProxySpec*, UINT32,
    const ProxyBridgeRuleSpec*, UINT32, BOOL);
PROXYBRIDGE_API BOOL ProxyBridge_CommitProfile(void*, UINT32*, UINT32*);
PROXYBRIDGE_API void ProxyBridge_DiscardProfile(void*);
// Transactional GUI operations: position 0 appends; enable state is part of the same commit.
PROXYBRIDGE_API UINT32 ProxyBridge_AddRuleEx(const char*, const char*, const char*, const char*, RuleProtocol, RuleAction, UINT32, BOOL, UINT32);
PROXYBRIDGE_API BOOL ProxyBridge_EditRuleEx(UINT32, const char*, const char*, const char*, const char*, RuleProtocol, RuleAction, UINT32, BOOL);
PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id);
PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position);  // Move rule to specific position (1=first, 2=second, etc)
PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id);  // Get current position of rule in list (1-based)
PROXYBRIDGE_API void ProxyBridge_SetLocalhostViaProxy(BOOL enable);
PROXYBRIDGE_API BOOL ProxyBridge_SetLocalhostViaProxyChecked(BOOL enable);
PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback);
PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
PROXYBRIDGE_API void ProxyBridge_SetTrafficLoggingEnabled(BOOL enable);
PROXYBRIDGE_API void ProxyBridge_ClearConnectionLogs(void);  // Clear connection history from memory
// Keep the caller's LoadLibrary reference until all API calls return. Before
// FreeLibrary, stop successfully and join any caller-owned API/checker threads.
// Stop must be called outside DllMain and outside synchronous worker callbacks.
PROXYBRIDGE_API BOOL ProxyBridge_Start(void);
PROXYBRIDGE_API BOOL ProxyBridge_Stop(void);
// Last background confirmation, refreshed roughly every 500 ms; no synchronous IOCTL.
PROXYBRIDGE_API BOOL ProxyBridge_IsFilteringActive(void);
#ifdef __cplusplus
}
#endif

#endif
