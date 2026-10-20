// pb_api.h - thin loader for ProxyBridgeCore.dll.
//
// Mirrors the exported C API in ../src/ProxyBridge.h. The DLL is loaded dynamically
// (LoadLibrary + GetProcAddress) by name, so the
// GUI has no import-lib link dependency and fails gracefully if the DLL is missing.
#ifndef PB_API_H
#define PB_API_H

#include <windows.h>

// enums (must match ProxyBridge.h)
typedef enum { PB_PROXY_HTTP = 0, PB_PROXY_SOCKS5 = 1 } PBProxyType;
typedef enum { PB_ACTION_PROXY = 0, PB_ACTION_DIRECT = 1, PB_ACTION_BLOCK = 2 } PBRuleAction;
typedef enum { PB_PROTO_TCP = 0, PB_PROTO_UDP = 1, PB_PROTO_BOTH = 2 } PBRuleProtocol;

// one live connection (must match PB_FLOW in ../../src/ProxyBridge.h)
typedef struct {
    UINT64 id;
    UINT32 pid;
    UINT32 proxy_config_id;
    UINT32 rule_id;          // 0 = not known
    UINT32 age_ms;           // 0xFFFFFFFF = not known
    UINT64 sent, received;   // payload bytes application -> proxy, proxy -> application
    UINT16 port;
    UINT8  is_udp, is_ipv6;
    UINT8  dest[16];
    char   name[40];         // process image name (UTF-8)
    char   host[64];         // destination: domain if known, else address (UTF-8)
} PBFlow;
#define PB_FLOWS_MAX_GUI 400

// callbacks (native thread - never touch UI directly from these)
typedef void (*PBLogCallback)(const char* message);
typedef void (*PBConnectionCallback)(const char* process_name, DWORD pid,
                                     const char* dest_ip, unsigned short dest_port,
                                     const char* proxy_info);

// exported function pointer typedefs
typedef UINT32 (*PFN_AddProxyConfig)(PBProxyType, const char*, unsigned short, const char*, const char*, BOOL);
typedef BOOL   (*PFN_EditProxyConfig)(UINT32, PBProxyType, const char*, unsigned short, const char*, const char*, BOOL);
typedef BOOL   (*PFN_DeleteProxyConfig)(UINT32);
typedef int    (*PFN_TestProxyConfig)(UINT32, const char*, unsigned short, char*, size_t);
typedef void   (*PBTestLogCallback)(const char* line, void* user);
typedef int    (*PFN_TestProxyConfigEx)(UINT32, const char*, unsigned short, PBTestLogCallback, void*);
typedef UINT32 (*PFN_AddRule)(const char*, const char*, const char*, const char*, PBRuleProtocol, PBRuleAction, UINT32, BOOL);
typedef BOOL   (*PFN_EnableRule)(UINT32);
typedef BOOL   (*PFN_DisableRule)(UINT32);
typedef BOOL   (*PFN_DeleteRule)(UINT32);
typedef BOOL   (*PFN_EditRule)(UINT32, const char*, const char*, const char*, const char*, PBRuleProtocol, PBRuleAction, UINT32, BOOL);
typedef BOOL   (*PFN_MoveRuleToPosition)(UINT32, UINT32);
typedef UINT32 (*PFN_GetRulePosition)(UINT32);
typedef void   (*PFN_SetLogCallback)(PBLogCallback);
typedef void   (*PFN_SetConnectionCallback)(PBConnectionCallback);
typedef void   (*PFN_SetTrafficLoggingEnabled)(BOOL);
typedef void   (*PFN_SetEnabled)(BOOL);
typedef void   (*PFN_SetLogEveryConnection)(BOOL);
typedef void   (*PFN_ClearConnectionLogs)(void);
typedef UINT32 (*PFN_GetFlows)(PBFlow*, UINT32);
typedef BOOL   (*PFN_Start)(void);
typedef BOOL   (*PFN_Stop)(void);

// resolved API table
typedef struct {
    HMODULE                       dll;
    PFN_AddProxyConfig            AddProxyConfig;
    PFN_EditProxyConfig           EditProxyConfig;
    PFN_DeleteProxyConfig         DeleteProxyConfig;
    PFN_TestProxyConfig           TestProxyConfig;
    PFN_TestProxyConfigEx         TestProxyConfigEx;
    PFN_AddRule                   AddRule;
    PFN_EnableRule                EnableRule;
    PFN_DisableRule               DisableRule;
    PFN_DeleteRule                DeleteRule;
    PFN_EditRule                  EditRule;
    PFN_MoveRuleToPosition        MoveRuleToPosition;
    PFN_GetRulePosition           GetRulePosition;
    PFN_SetLogCallback            SetLogCallback;
    PFN_SetConnectionCallback     SetConnectionCallback;
    PFN_SetTrafficLoggingEnabled  SetTrafficLoggingEnabled;
    PFN_SetEnabled                SetEnabled;
    PFN_SetLogEveryConnection     SetLogEveryConnection;
    PFN_ClearConnectionLogs       ClearConnectionLogs;
    PFN_GetFlows                  GetFlows;
    PFN_Start                     Start;
    PFN_Stop                      Stop;
} PBApi;

// Loads ProxyBridgeCore.dll (from the exe's directory) and resolves every export.
// Returns TRUE only if the DLL and all required functions were found.
// Used by ProxyBridgeSvc.exe (the service that owns the engine) and as the GUI's
// elevated fallback when the service is not installed. See pb_ipc.h for the normal path.
static BOOL PB_LoadDirect(PBApi* api)
{
    ZeroMemory(api, sizeof(*api));

    // Load from the executable's own directory so we don't depend on CWD/PATH.
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return FALSE;
    for (DWORD i = n; i > 0; i--) { if (path[i - 1] == L'\\') { path[i] = 0; break; } }
    lstrcatW(path, L"ProxyBridgeCore.dll");

    // Absolute path only, and its dependencies (WinDivert.dll) come from that folder or System32:
    // never from the current directory or PATH (DLL planting).
    api->dll = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!api->dll) return FALSE;

    #define PB_BIND(field, name) \
        api->field = (PFN_##field)(void*)GetProcAddress(api->dll, "ProxyBridge_" name); \
        if (!api->field) return FALSE;

    PB_BIND(AddProxyConfig,           "AddProxyConfig");
    PB_BIND(EditProxyConfig,          "EditProxyConfig");
    PB_BIND(DeleteProxyConfig,        "DeleteProxyConfig");
    PB_BIND(TestProxyConfig,          "TestProxyConfig");
    PB_BIND(TestProxyConfigEx,        "TestProxyConfigEx");
    PB_BIND(AddRule,                  "AddRule");
    PB_BIND(EnableRule,               "EnableRule");
    PB_BIND(DisableRule,              "DisableRule");
    PB_BIND(DeleteRule,               "DeleteRule");
    PB_BIND(EditRule,                 "EditRule");
    PB_BIND(MoveRuleToPosition,       "MoveRuleToPosition");
    PB_BIND(GetRulePosition,          "GetRulePosition");
    PB_BIND(SetLogCallback,           "SetLogCallback");
    PB_BIND(SetConnectionCallback,    "SetConnectionCallback");
    PB_BIND(SetTrafficLoggingEnabled, "SetTrafficLoggingEnabled");
    PB_BIND(SetEnabled,               "SetEnabled");
    PB_BIND(SetLogEveryConnection,    "SetLogEveryConnection");
    PB_BIND(ClearConnectionLogs,      "ClearConnectionLogs");
    PB_BIND(GetFlows,                 "GetFlows");
    PB_BIND(Start,                    "Start");
    PB_BIND(Stop,                     "Stop");
    #undef PB_BIND

    return TRUE;
}

static void PB_UnloadDirect(PBApi* api)
{
    if (api->dll) FreeLibrary(api->dll);
    ZeroMemory(api, sizeof(*api));
}

#endif // PB_API_H
