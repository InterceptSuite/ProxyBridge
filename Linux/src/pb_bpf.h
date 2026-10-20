// eBPF backend: loads and attaches the datapath, compiles rules into BPF maps, delivers flow events.
#ifndef PB_BPF_H
#define PB_BPF_H

#include "pb_internal.h"
#include "pb_rules.h"
#include "bpf/pb_bpf_shared.h"

struct pb_bpf_cfg {
    uint16_t tcp_port, udp_port;
    uint32_t self_tgid;
    bool     log;
    bool     dns_via_proxy;
};

// A rule as seen by the compiler: the parsed rule plus its effective action and proxy.
struct pb_rule_view {
    const struct pb_rule *rule;
    int      action;         // PROXY with no usable proxy has already become BLOCK
    uint16_t proxy_id;
    bool     udp_direct;     // the proxy cannot carry UDP
    bool     localhost;      // PROXY rule that also proxies loopback destinations
    bool     wants_names;    // needs the DNS tap: a domain rule, or a proxy that is sent host names
};

typedef void (*pb_event_cb)(const struct pb_event *e);

// Returns 0, or -1 after logging why (not root, kernel too old, no cgroup2, verifier...).
int  pb_bpf_start(const struct pb_bpf_cfg *cfg, pb_event_cb cb);
// Detaches the hooks and stops the event reader; the maps stay valid until pb_bpf_stop() (relay threads may still look up).
void pb_bpf_detach(void);
void pb_bpf_stop(void);

void pb_bpf_set_flags(bool log, bool dns_via_proxy);
void pb_bpf_set_paused(bool paused);
// Recompiles the rule set and rescans /proc for running executables. -1 if it does not fit.
int  pb_bpf_sync(const struct pb_rule_view *v, size_t n);
// Installs the class of the executable the kernel reported in `o` (slow-path learning); no-op for known binaries.
void pb_bpf_learn(const struct pb_orig *o, const char *exe_path, const struct pb_rule_view *v, size_t n);
// Processes (tgids) whose traffic is never redirected, e.g. the local proxy itself.
void pb_bpf_set_exempt(const uint32_t *tgids, size_t n);

// (rule, address) pairs whose DNS name matches a domain rule.
// Path of an executable the kernel identified by (dev, ino) that this process has seen before; false if it has not.
// Lets a decision be made for a process that exited before the relay got to it.
bool pb_bpf_exe_path(uint32_t dev, uint64_t ino, char *out, size_t n);

void pb_bpf_dom_set(uint32_t rule_idx, uint32_t ip_host);
void pb_bpf_dom_clear(void);

int  pb_bpf_take_tcp_orig(uint32_t client_ip_be, uint16_t client_port, struct pb_orig *out);
int  pb_bpf_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out);

#endif
