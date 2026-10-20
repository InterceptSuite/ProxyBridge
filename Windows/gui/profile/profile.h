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
#define PB_HOSTS_MAX   8192   // Target Hosts: one ";"-separated list of IPs and domain names (8191 characters + NUL)
#define PB_APPS_MAX    8192   // Applications field: a "; "-separated list of many programs (8191 characters + NUL)

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
    wchar_t hosts[PB_HOSTS_MAX];  // IPs, ranges and domain names together ("*" = any host)
    wchar_t ports[128];
    wchar_t proto[8];             // "TCP" | "UDP" | "BOTH"
    wchar_t action[16];           // "PROXY" | "DIRECT" | "BLOCK"
    int     enabled;
    int     localhost;            // 1 = connections to localhost (127.x / ::1) matching this rule are proxied too
    UINT32  cfgStoredId;          // ProxyConfigId as written in the profile
} PBRule;

typedef struct {
    wchar_t mode[16], proc[256], ip[64], port[16], proto[8], action[16];
} PBFilter;

// Stable ids for proxy configs. These are owned by the profile and are NOT the id the engine returns
// from AddProxyConfig (that one is only valid for the current engine session and is remapped on load).
// Never reused, so a rule can never silently start pointing at a proxy added after its own was deleted.
typedef struct PBProfile PBProfile;
UINT32 PB_AllocConfigId(PBProfile* p);

typedef struct PBProfile {
    int      trafficLogging;
    int      autoClearLogs;
    int      logEveryConnection;   // 1 = the Connections log shows every new connection, not just the first of identical ones
    int      closeToTray;
    int      fontZoom;            // UI/log text zoom in percent (60-300), 100 = DPI default
    UINT32   nextCfgId;           // next stable proxy-config id to hand out (persisted; ids are never reused)
    wchar_t  language[8];         // "en" | "zh"
    PBConfig cfg[PB_MAX_CFG];   int cfgCount;
    PBRule   rule[PB_MAX_RULE]; int ruleCount;
    PBFilter filter[PB_MAX_FILTER]; int filterCount;
} PBProfile;

// Target Hosts list helpers. Line breaks only exist in the editor for readability:
//   PB_ListNormalize - in place; removes line breaks/tabs/control characters, trims blanks around the
//                      separators (';' or ','), drops empty entries and joins with ';'. Never grows the text.
//   PB_ListFormat    - writes the list with a line break after every ';' (cch must be >= 3 * len + 1).
void PB_ListNormalize(wchar_t* s);
void PB_ListFormat(const wchar_t* in, wchar_t* out, size_t cch);

// The profile file (and the engine) keep IPs and domain names in two keys, TargetHosts and TargetDomains; the
// GUI shows them as one list.
//   PB_HostsMerge - TargetHosts + TargetDomains (either may be "" or "*") -> one list ("*" if both are empty).
//   PB_HostsSplit - one list -> IP-like entries and domain entries. Each output is "*" when it has no entries,
//                   and both are "*" when the list contains "*". cch of each output must be >= len(merged) + 2.
void PB_HostsMerge(const wchar_t* ips, const wchar_t* doms, wchar_t* out, size_t cch);
void PB_HostsSplit(const wchar_t* merged, wchar_t* ips, size_t ipsCch, wchar_t* doms, size_t domsCch);

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
