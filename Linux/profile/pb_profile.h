// .pbprofile: the JSON profile format shared with the Windows and macOS apps (PascalCase keys).
//
//   { "Version": "1.0", "Name": "...", "IsTrafficLoggingEnabled": true,
//     "ProxyConfigs": [ { "Id": 1, "Name": "work", "Type": "SOCKS5", "Host": "...", "Port": "1080",
//                         "Username": "", "Password": "", "SendDomainToProxy": false } ],
//     "ProxyRules":   [ { "ProcessName": "...", "TargetHosts": "...", "TargetPorts": "...", "TargetDomains": "...",
//                         "Protocol": "TCP|UDP|BOTH", "Action": "PROXY|DIRECT|BLOCK", "IsEnabled": true,
//                         "ProxyConfigId": 1 } ] }
//
// Linux keeps domain names in the host list; they are split into TargetDomains on export and merged back on import.
// Fields this program does not use (LocalhostViaProxy, LogFilters, ...) are ignored on import.
#ifndef PB_PROFILE_H
#define PB_PROFILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PBP_MAX_FILE    (4u << 20)
#define PBP_MAX_PROXIES 256
#define PBP_MAX_RULES   4096
#define PBP_EXT         ".pbprofile"

struct pbp_proxy {
    uint32_t id;        // stable within the file; rules refer to it
    char *name;
    int   type;         // 0 = HTTP, 1 = SOCKS5 (same values as ProxyType)
    char *host;
    uint16_t port;
    char *user, *pass;
};

struct pbp_rule {
    char *process, *hosts, *ports;   // hosts holds IPs and domain names together
    int   protocol;                  // 0 TCP, 1 UDP, 2 BOTH (RuleProtocol)
    int   action;                    // 0 PROXY, 1 DIRECT, 2 BLOCK (RuleAction)
    bool  enabled;
    uint32_t proxy_id;               // 0 = default proxy
};

struct pbp_profile {
    char *name;
    bool  logging;                   // IsTrafficLoggingEnabled
    bool  dns_via_proxy;             // DnsViaProxy (Linux extension)
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

// settings.json next to the profiles: which profile is active, plus the GUI-wide switches (absent keys keep the defaults).
int   pbp_settings_load(const char *path, char **active, bool *logging, bool *dns);   // -1 if missing or unreadable
int   pbp_settings_save(const char *path, const char *active, bool logging, bool dns, char *err, size_t errlen);

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

struct pbp_proxy *pbp_find_proxy(const struct pbp_profile *p, uint32_t id);

#endif
