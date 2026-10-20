// Rule model: parsing/validation and the full userspace matcher (the reference semantics; the BPF side is a compiled subset).
#ifndef PB_RULES_H
#define PB_RULES_H

#include "pb_internal.h"

#define PB_MAX_PATTERNS 64          // process and port lists
#define PB_MAX_HOST_PATTERNS 1024   // Target Host list (IPs, ranges and domains together)
#define PB_HOSTS_MAX 8192           // longest Target Host text, including the terminating NUL

enum { PB_HOST_V4_RANGE = 1, PB_HOST_V4_BOX, PB_HOST_V6_RANGE };

struct pb_host_pat {
    int kind;
    uint32_t lo4, hi4;             // PB_HOST_V4_RANGE, host order
    uint8_t  box_lo[4], box_hi[4]; // PB_HOST_V4_BOX: per-octet inclusive range (e.g. 192.168.*.*  or 10.1-5.*.*)
    uint8_t  lo6[16], hi6[16];     // PB_HOST_V6_RANGE, network order
};

struct pb_port_range { uint16_t lo, hi; };

struct pb_rule {
    uint32_t id;
    bool enabled;
    RuleProtocol protocol;
    RuleAction   action;
    uint32_t     proxy_id;         // action == PROXY: 0 = default proxy
    bool         localhost;        // action == PROXY: also proxy loopback destinations that match

    char process_src[512], hosts_src[PB_HOSTS_MAX], ports_src[512];   // original text, kept for the UI / export

    bool any_proc;
    char (*procs)[256];  int nprocs;
    bool any_host;
    struct pb_host_pat *hosts; int nhosts;
    char (*domains)[256]; int ndomains;      // lower-case domain globs ("*.github.com", "example.org"), matched against DNS-learned names
    bool any_port;
    struct pb_port_range *ports; int nports;
};

// Parses and validates the three pattern strings into `out` (id/enabled/action/protocol/proxy_id are left to the caller).
// On failure returns false and writes a human readable reason to err. On success the caller must pb_rule_free().
bool pb_rule_parse(struct pb_rule *out, const char *process, const char *hosts, const char *ports, char *err, size_t errlen);
void pb_rule_free(struct pb_rule *r);

bool pb_glob_match(const char *pattern, const char *str);
bool pb_rule_match_process(const struct pb_rule *r, const char *exe_path);
bool pb_rule_match_proto(const struct pb_rule *r, int ipproto);
// names/nnames: domain names the DNS tap has learned for this destination address (may be NULL/0).
bool pb_rule_match_dest(const struct pb_rule *r, int family, const uint8_t addr16[16], uint16_t port,
                        const char *const *names, int nnames);
bool pb_rule_has_domains(const struct pb_rule *r);
bool pb_domain_match(const char *pattern, const char *name);   // case-insensitive; glob if it contains * or ?, else exact

// Destinations that are never redirected (loopback, multicast, broadcast, DHCP, DNS when !dns_via_proxy).
bool pb_implicit_direct(int family, const uint8_t addr16[16], uint16_t port, int ipproto, bool dns_via_proxy);

// First enabled matching rule wins. Returns the index of the matching rule or -1 (no rule: DIRECT).
int pb_rules_eval(const struct pb_rule *rules, size_t n, const char *exe_path, int family, const uint8_t addr16[16],
                  uint16_t port, int ipproto, const char *const *names, int nnames);

#endif
