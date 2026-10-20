// .pbprofile: the JSON profile format shared with the Windows and macOS apps (PascalCase keys).
//
//   { "Version": "1.0", "Name": "...", "IsTrafficLoggingEnabled": true,
//     "ProxyConfigs": [ { "Id": 1, "Name": "work", "Type": "SOCKS5", "Host": "...", "Port": "1080",
//                         "Username": "", "Password": "", "SendDomainToProxy": true } ],
//     "ProxyRules":   [ { "Name": "...", "ProcessName": "...", "TargetHosts": "...", "TargetPorts": "...", "TargetDomains": "...",
//                         "Protocol": "TCP|UDP|BOTH", "Action": "PROXY|DIRECT|BLOCK", "IsEnabled": true,
//                         "ProxyConfigId": 1, "LocalhostViaProxy": false } ] }
//
// Linux keeps domain names in the host list; they are split into TargetDomains on export and merged back on import.
// Fields this program does not use (LogFilters, ...) are ignored on import. A top-level LocalhostViaProxy from older profiles
// becomes the default for rules that do not carry their own.
#ifndef PB_PROFILE_H
#define PB_PROFILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PBP_MAX_FILE    (4u << 20)
#define PBP_MAX_PROXIES 256
#define PBP_MAX_RULES   4096
#define PBP_EXT         ".pbprofile"
#define PBP_MAX_FILTERS 64
#define PBP_ZOOM_MIN    60
#define PBP_ZOOM_MAX    300

struct pbp_proxy {
    uint32_t id;        // stable within the file; rules refer to it
    char *name;
    int   type;         // 0 = HTTP, 1 = SOCKS5 (same values as ProxyType)
    char *host;
    uint16_t port;
    char *user, *pass;
    bool  send_domain;   // SendDomainToProxy: the proxy resolves host names (default true)
};

struct pbp_rule {
    char *name;                      // label shown in the rule list; may be empty
    char *process, *hosts, *ports;   // hosts holds IPs and domain names together
    int   protocol;                  // 0 TCP, 1 UDP, 2 BOTH (RuleProtocol)
    int   action;                    // 0 PROXY, 1 DIRECT, 2 BLOCK (RuleAction)
    bool  enabled;
    bool  localhost;                 // LocalhostViaProxy: a PROXY rule that also proxies 127.0.0.0/8 and ::1
    uint32_t proxy_id;               // 0 = default proxy
};

// A connection-log filter (GUI). Patterns are case-insensitive globs; "" and "*" and "All" match anything.
struct pbp_filter {
    bool  exclude;                   // Mode: "Exclude" hides matches, "Include" shows only matches
    char *process, *ip, *port;
    char *protocol;                  // "All", "TCP" or "UDP"
    char *action;                    // "All", "Direct", "Proxy" or "Blocked"
};

struct pbp_profile {
    char *name;
    bool  logging;                   // IsTrafficLoggingEnabled
    bool  dns_via_proxy;             // DnsViaProxy (Linux extension)
    bool  log_every;                 // LogEveryConnection: the connection log is not de-duplicated
    bool  auto_clear;                // AutoClearConnectionLogs: a log is wiped once it passes 500 lines (default true)
    int   font_zoom;                 // FontZoom in percent, 60-300 (default 100)
    struct pbp_filter *filters; size_t nfilters;     // LogFilters
    uint32_t default_proxy_id;       // DefaultProxyId (Linux extension); 0 = first proxy
    struct pbp_proxy *proxies; size_t nproxies;
    struct pbp_rule  *rules;   size_t nrules;
};

// Returns 0 or -1 with a reason in err. On failure *out is empty and need not be freed.
int   pbp_parse(const char *json, size_t len, struct pbp_profile *out, char *err, size_t errlen);
char *pbp_serialize(const struct pbp_profile *p);               // malloc'd, NUL terminated
void  pbp_free(struct pbp_profile *p);

int   pbp_load_file(const char *path, struct pbp_profile *out, char *err, size_t errlen);
// Writes data to path atomically (temporary file + fsync + rename), mode 0600.
int   pbp_write_file(const char *path, const char *data, char *err, size_t errlen);
// Atomic (temporary file + rename), mode 0600 because the file holds proxy credentials.
int   pbp_save_file(const char *path, const struct pbp_profile *p, char *err, size_t errlen);

// settings.json next to the profiles holds the name of the active profile and the update check switch (both are not per profile);
// everything else lives in the profile files.
// start_at_boot: the ProxyBridge service applies the active profile when it starts, and keeps routing after the window is closed
// (default false: the service stays idle until a window asks, and routing stops when that window closes).
int   pbp_settings_load(const char *path, char **active, bool *check_updates, bool *start_at_boot);   // -1 if missing or unreadable; either bool may be NULL
int   pbp_settings_save(const char *path, const char *active, bool check_updates, bool start_at_boot, char *err, size_t errlen);

// Does a connection pass the filters? Excludes run first (any match hides); then, if there are Include filters, one must match.
// protocol: "TCP"/"UDP"; action: "Direct"/"Proxy"/"Blocked".
bool  pbp_filters_pass(const struct pbp_filter *f, size_t n, const char *process, const char *ip, const char *port,
                       const char *protocol, const char *action);

// Profile name <-> file name inside a profiles directory (percent-encoding, so any name is safe).
char *pbp_filename_for(const char *name);                          // malloc'd, includes the extension
char *pbp_name_from_filename(const char *filename);                // NULL if it is not a profile file
// Directory holding settings.json and profiles/ (PROXYBRIDGE_CONFIG_DIR overrides /etc/proxybridge, used by tests).
const char *pbp_config_dir(void);
// "name" or a path: a path is used as is, a bare name is looked up as <dir>/profiles/<name>.pbprofile.
char *pbp_resolve(const char *dir, const char *name_or_path);

// Splits a host list into IP-like and domain tokens (either output may be empty); the caller frees both.
void  pbp_split_hosts(const char *hosts, char **ips, char **domains);
char *pbp_merge_hosts(const char *ips, const char *domains);

// The update feed: {"linux": {"version": "...", "download": "...", "release_notes": "..."}, ...}. 0 if there is a linux version.
int   pbp_update_parse(const char *json, size_t len, char **version, char **download, char **notes);
// Is `candidate` a higher version than `current`? Numeric parts only (4.0.0-Beta equals 4.0.0).
bool  pbp_version_newer(const char *candidate, const char *current);

struct pbp_proxy *pbp_find_proxy(const struct pbp_profile *p, uint32_t id);

#endif
