// The window's link to the engine. With the ProxyBridge service running, every engine call goes over its socket (the window
// then needs no root). Without a service, a window started as root runs the engine inside itself, as before.
//
// The functions have the signatures of the ProxyBridge_* functions they stand for; gui.h maps the names, so the rest of the
// window is written against the library API in both modes.
#ifndef PB_CLIENT_H
#define PB_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ProxyBridge.h"

enum { PBC_CONNECTED = 0, PBC_NO_SERVICE = 1, PBC_REFUSED = -1 };

// Tries the service. PBC_NO_SERVICE: nothing is listening (a root window may then run its own engine). PBC_REFUSED: the service
// is there but will not talk to us (not allowed, version mismatch...); err says why.
int  pbc_connect(const char *socket_path, char *err, size_t errn);
bool pbc_is_service(void);              // service mode
bool pbc_alive(void);                   // service mode and the connection is healthy
bool pbc_service_engine_running(void);  // what the service said when we connected
void pbc_disconnect(void);
// Called (from the reader thread) when the connection is lost.
void pbc_set_lost_callback(void (*cb)(void));
// After a lost connection: try again. True when connected again (the window must then send its configuration again).
bool pbc_reconnect(void);

// Feeds the service's recent log lines (what it did before this window connected) to cb.
void pbc_replay_history(LogCallback cb);

// Whether "Start at Boot" is on, and switching it. Service mode asks the service; embedded mode writes the unit itself.
bool pbc_boot_is_enabled(void);
bool pbc_boot_set(bool enable, char **error);   // *error g_malloc'd

#ifndef PBC_IMPL
#define ProxyBridge_AddProxy pbc_AddProxy
#define ProxyBridge_EditProxy pbc_EditProxy
#define ProxyBridge_SetProxySendDomain pbc_SetProxySendDomain
#define ProxyBridge_DeleteProxy pbc_DeleteProxy
#define ProxyBridge_ClearProxies pbc_ClearProxies
#define ProxyBridge_SetDefaultProxy pbc_SetDefaultProxy
#define ProxyBridge_AddRule pbc_AddRule
#define ProxyBridge_EditRule pbc_EditRule
#define ProxyBridge_SetRuleLocalhost pbc_SetRuleLocalhost
#define ProxyBridge_EnableRule pbc_EnableRule
#define ProxyBridge_DisableRule pbc_DisableRule
#define ProxyBridge_DeleteRule pbc_DeleteRule
#define ProxyBridge_MoveRule pbc_MoveRule
#define ProxyBridge_ClearRules pbc_ClearRules
#define ProxyBridge_ValidateRule pbc_ValidateRule
#define ProxyBridge_SetDnsViaProxy pbc_SetDnsViaProxy
#define ProxyBridge_SetEnabled pbc_SetEnabled
#define ProxyBridge_SetLogEveryConnection pbc_SetLogEveryConnection
#define ProxyBridge_SetLogCallback pbc_SetLogCallback
#define ProxyBridge_SetConnectionCallbackEx pbc_SetConnectionCallbackEx
#define ProxyBridge_SetTrafficLoggingEnabled pbc_SetTrafficLoggingEnabled
#define ProxyBridge_BeginBatch pbc_BeginBatch
#define ProxyBridge_EndBatch pbc_EndBatch
#define ProxyBridge_Start pbc_Start
#define ProxyBridge_Stop pbc_Stop
#define ProxyBridge_GetFlows pbc_GetFlows
#define ProxyBridge_TestProxyEx pbc_TestProxyEx
#endif

uint32_t pbc_AddProxy(const char *name, ProxyType type, const char *host, uint16_t port, const char *username, const char *password, char *err, size_t err_size);
bool     pbc_EditProxy(uint32_t id, const char *name, ProxyType type, const char *host, uint16_t port, const char *username, const char *password, char *err, size_t err_size);
bool     pbc_SetProxySendDomain(uint32_t id, bool send_domain);
bool     pbc_DeleteProxy(uint32_t id);
void     pbc_ClearProxies(void);
void     pbc_SetDefaultProxy(uint32_t id);
uint32_t pbc_AddRule(const char *process, const char *hosts, const char *ports, RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char *err, size_t err_size);
bool     pbc_EditRule(uint32_t id, const char *process, const char *hosts, const char *ports, RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char *err, size_t err_size);
bool     pbc_SetRuleLocalhost(uint32_t id, bool on);
bool     pbc_EnableRule(uint32_t id);
bool     pbc_DisableRule(uint32_t id);
bool     pbc_DeleteRule(uint32_t id);
bool     pbc_MoveRule(uint32_t id, int new_index);
void     pbc_ClearRules(void);
bool     pbc_ValidateRule(const char *process, const char *hosts, const char *ports, char *err, size_t err_size);
void     pbc_SetDnsViaProxy(bool enable);
void     pbc_SetEnabled(bool enable);
void     pbc_SetLogEveryConnection(bool enable);
void     pbc_SetLogCallback(LogCallback cb);
void     pbc_SetConnectionCallbackEx(ConnectionCallbackEx cb);
void     pbc_SetTrafficLoggingEnabled(bool enable);
void     pbc_BeginBatch(void);
void     pbc_EndBatch(void);
bool     pbc_Start(void);
bool     pbc_Stop(void);
uint32_t pbc_GetFlows(ProxyBridgeFlow *out, uint32_t max);
int      pbc_TestProxyEx(uint32_t proxy_id, const char *host, uint16_t port, ProxyTestLogCallback cb, void *user);

#endif
