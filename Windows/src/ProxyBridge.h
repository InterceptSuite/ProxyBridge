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
PROXYBRIDGE_API UINT32 ProxyBridge_AddProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password);
PROXYBRIDGE_API BOOL   ProxyBridge_EditProxyConfig(UINT32 config_id, ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password);
PROXYBRIDGE_API BOOL   ProxyBridge_DeleteProxyConfig(UINT32 config_id);
PROXYBRIDGE_API int    ProxyBridge_TestProxyConfig(UINT32 config_id, const char* target_host, UINT16 target_port, char* result_buffer, size_t buffer_size);

// Rule management - proxy_config_id selects which proxy config the rule uses (0 = first available)
PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id);
PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id);
PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position);  // Move rule to specific position (1=first, 2=second, etc)
PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id);  // Get current position of rule in list (1-based)
PROXYBRIDGE_API void ProxyBridge_SetDnsViaProxy(BOOL enable);
PROXYBRIDGE_API void ProxyBridge_SetLocalhostViaProxy(BOOL enable);
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
