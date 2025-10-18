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
    RULE_PROTOCOL_BOTH = 2  // Future: Match both TCP and UDP
} RuleProtocol;

PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action);
PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id);
PROXYBRIDGE_API BOOL ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port);
PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback);
PROXYBRIDGE_API void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
PROXYBRIDGE_API BOOL ProxyBridge_Start(void);
PROXYBRIDGE_API BOOL ProxyBridge_Stop(void);

#ifdef __cplusplus
}
#endif

#endif
