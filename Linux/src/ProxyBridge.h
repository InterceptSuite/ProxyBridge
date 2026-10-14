#ifndef PROXYBRIDGE_H
#define PROXYBRIDGE_H

#define PROXYBRIDGE_VERSION "4.0.0"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

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
uint32_t ProxyBridge_AddProxy(const char* name, ProxyType type, const char* host, uint16_t port,
                              const char* username, const char* password, char* err, size_t err_size);
bool     ProxyBridge_EditProxy(uint32_t proxy_id, const char* name, ProxyType type, const char* host, uint16_t port,
                               const char* username, const char* password, char* err, size_t err_size);
bool     ProxyBridge_DeleteProxy(uint32_t proxy_id);   /* rules that used it fall back to the default proxy */
void     ProxyBridge_ClearProxies(void);
/* Which proxy a rule with proxy_id == 0 uses. 0 = the first proxy added. */
void     ProxyBridge_SetDefaultProxy(uint32_t proxy_id);

/* ---- Rules ----------------------------------------------------------------------------------------------------------
 * Rules are evaluated in list order, first match wins. process_name: ';' or ',' separated globs matched against the
 * executable's full path and file name ("*" or empty = any). target_hosts: ';' or ',' separated IPv4/IPv6 addresses,
 * CIDR (10.0.0.0/8), a-b ranges, octet wildcards (192.168.*.*) or "*" ("" = any). target_ports: list and ranges
 * ("80;443;8000-9000", "" or "*" = any).
 * proxy_id applies when action == RULE_ACTION_PROXY; 0 = default proxy.
 * AddRule returns the new rule id, or 0 on validation failure (reason in err). */
uint32_t ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports,
                             RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char* err, size_t err_size);
bool     ProxyBridge_EditRule(uint32_t rule_id, const char* process_name, const char* target_hosts, const char* target_ports,
                              RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char* err, size_t err_size);
bool     ProxyBridge_EnableRule(uint32_t rule_id);
bool     ProxyBridge_DisableRule(uint32_t rule_id);
bool     ProxyBridge_DeleteRule(uint32_t rule_id);
bool     ProxyBridge_MoveRule(uint32_t rule_id, int new_index);   /* reorder: priority = position */
void     ProxyBridge_ClearRules(void);
/* Validates a rule without adding it; returns true if valid, otherwise writes the reason to err. */
bool     ProxyBridge_ValidateRule(const char* process_name, const char* target_hosts, const char* target_ports,
                                  char* err, size_t err_size);

/* ---- Legacy single-proxy helper -------------------------------------------------------------------------------------
 * Sets (creating on first use) the default proxy. Equivalent to Add/EditProxy on the "default" entry. */
bool ProxyBridge_SetProxyConfig(ProxyType type, const char* proxy_ip, uint16_t proxy_port, const char* username, const char* password);

/* ---- Runtime --------------------------------------------------------------------------------------------------------- */
void ProxyBridge_SetDnsViaProxy(bool enable);
void ProxyBridge_SetLogCallback(LogCallback callback);
void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
void ProxyBridge_SetTrafficLoggingEnabled(bool enable);
void ProxyBridge_ClearConnectionLogs(void);
bool ProxyBridge_Start(void);   /* needs root (CAP_BPF/CAP_SYS_ADMIN) and a BTF kernel >= 5.11; returns false and logs why on failure */
bool ProxyBridge_Stop(void);    /* keeps rules and proxies; Start() may be called again */
int  ProxyBridge_TestConnection(const char* target_host, uint16_t target_port, char* result_buffer, size_t buffer_size);
int  ProxyBridge_TestProxy(uint32_t proxy_id, const char* target_host, uint16_t target_port, char* result_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
