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
typedef void (*ConnectionCallback)(const char* process_name, DWORD pid, UINT16 src_port, const char* dest_ip, UINT16 dest_port);

typedef struct {
    const char* target_process;
    const char* exclude_process;
    const char* proxy_url;
    UINT16 relay_port;
    LogCallback log_callback;
    ConnectionCallback connection_callback;
} ProxyBridgeConfig;

PROXYBRIDGE_API BOOL ProxyBridge_Start(void);
PROXYBRIDGE_API BOOL ProxyBridge_Stop(void);
PROXYBRIDGE_API BOOL ProxyBridge_SetConfig(const ProxyBridgeConfig* config);

#ifdef __cplusplus
}
#endif

#endif
