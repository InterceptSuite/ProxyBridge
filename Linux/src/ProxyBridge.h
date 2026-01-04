// ProxyBridge.h  - Most code copied from Windows eader fie 
#ifndef PROXYBRIDGE_H
#define PROXYBRIDGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol flags
#define PROTO_TCP  0x01
#define PROTO_UDP  0x02
#define PROTO_BOTH 0x03

// Actions
#define ACTION_DIRECT 0
#define ACTION_PROXY  1
#define ACTION_BLOCK  2

// Proxy types
typedef enum {
    PROXY_TYPE_HTTP = 0,
    PROXY_TYPE_SOCKS5 = 1
} ProxyType;

// Rule structure (EXACT Windows PROCESS_RULE)
typedef struct {
    uint32_t rule_id;
    char process_name[256];   // "*", "chrome.exe", "firefox.exe; chrome.exe"
    char target_hosts[512];   // "*", "192.168.*.*", "10.0.0.1; 172.16.0.1"
    char target_ports[256];   // "*", "80; 443", "80-8000"
    uint8_t proto;            // PROTO_TCP/UDP/BOTH
    uint8_t action;           // ACTION_DIRECT/PROXY/BLOCK
    bool enabled;
} ProxyRule;

// Proxy settings
typedef struct {
    char proxy_host[256];     // IP or hostname
    uint16_t proxy_port;
    ProxyType proxy_type;     // HTTP or SOCKS5
    char username[128];
    char password[128];
    bool dns_via_proxy;       // Send DNS through proxy
} ProxySettings;

// Connection event callback
typedef void (*ConnectionCallback)(
    const char *process_name,
    uint32_t pid,
    const char *dest_ip,
    uint16_t dest_port,
    const char *proxy_info
);

// API Functions (match Windows)
bool ProxyBridge_Start(void);
void ProxyBridge_Stop(void);
void ProxyBridge_SetProxySettings(const ProxySettings *settings);
uint32_t ProxyBridge_AddRule(const ProxyRule *rule);
bool ProxyBridge_UpdateRule(uint32_t rule_id, const ProxyRule *rule);
bool ProxyBridge_RemoveRule(uint32_t rule_id);
void ProxyBridge_ClearRules(void);
void ProxyBridge_SetConnectionCallback(ConnectionCallback callback);
const char* ProxyBridge_GetVersion(void);

#ifdef __cplusplus
}
#endif

#endif // PROXYBRIDGE_H
