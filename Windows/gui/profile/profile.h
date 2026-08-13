// profile.h - read/write settings.json + *.pbprofile.
//
// Storage:
//   %APPDATA%\ProxyBridge\settings.json               -> { ActiveProfileName, ... }
//   %APPDATA%\ProxyBridge\profiles\<name>.pbprofile   -> ProxyProfile (PascalCase JSON)
//
// The in-memory struct holds every profile field - including LogFilters, which have no
// editor yet but are round-tripped verbatim so nothing is lost on save.
#ifndef PB_PROFILE_H
#define PB_PROFILE_H

#include <windows.h>

#define PB_MAX_CFG     32
#define PB_MAX_RULE    128
#define PB_MAX_FILTER  64
#define PB_NAME_MAX    64
#define PB_APPS_MAX    1024   // Applications field: holds a "; "-separated list of many exes

typedef struct {
    UINT32  storedId;              // Id as written in the profile
    UINT32  nativeId;              // id returned by AddProxyConfig after apply
    wchar_t name[128];            // friendly label (GUI-only; not sent to the core)
    wchar_t type[16];             // "SOCKS5" | "HTTP"
    wchar_t host[128];
    wchar_t port[16];
    wchar_t user[128];
    wchar_t pass[128];
    int     sendDomain;           // 1 = proxy resolves DNS (send hostname), 0 = send IP
} PBConfig;

typedef struct {
    UINT32  nativeId;              // id returned by AddRule after apply
    wchar_t name[128];            // friendly label (GUI-only; not sent to the core)
    wchar_t proc[PB_APPS_MAX];
    wchar_t hosts[256];
    wchar_t ports[128];
    wchar_t domains[256];
    wchar_t proto[8];             // "TCP" | "UDP" | "BOTH"
    wchar_t action[16];           // "PROXY" | "DIRECT" | "BLOCK"
    int     enabled;
    UINT32  cfgStoredId;          // ProxyConfigId as written in the profile
} PBRule;

typedef struct {
    wchar_t mode[16], proc[256], ip[64], port[16], proto[8], action[16];
} PBFilter;

typedef struct {
    int      localhostViaProxy;
    int      trafficLogging;
    int      autoClearLogs;
    int      closeToTray;
    wchar_t  language[8];         // "en" | "zh"
    PBConfig cfg[PB_MAX_CFG];   int cfgCount;
    PBRule   rule[PB_MAX_RULE]; int ruleCount;
    PBFilter filter[PB_MAX_FILTER]; int filterCount;
} PBProfile;

// settings.json (active profile pointer). Other settings fields are preserved on write.
void PB_GetActiveProfile(wchar_t* out, int cch);
void PB_SetActiveProfile(const wchar_t* name);

// settings.json - "check for updates on startup" flag (preserves the other fields).
BOOL PB_GetCheckUpdates(void);
void PB_SetCheckUpdates(BOOL enable);

// *.pbprofile. Load fills defaults if the file is missing/invalid.
void PB_ProfileDefaults(PBProfile* p, const wchar_t* name);
void PB_ProfileLoad(const wchar_t* name, PBProfile* p);
BOOL PB_ProfileSave(const wchar_t* name, const PBProfile* p);

// Management.
int  PB_ProfileList(wchar_t names[][PB_NAME_MAX], int maxNames);   // returns count
BOOL PB_ProfileDelete(const wchar_t* name);
BOOL PB_ProfileRename(const wchar_t* oldName, const wchar_t* newName);
BOOL PB_ProfileImport(const wchar_t* srcPath, wchar_t* assignedName, int cch);
BOOL PB_ProfileExport(const wchar_t* name, const wchar_t* destPath);

#endif // PB_PROFILE_H
