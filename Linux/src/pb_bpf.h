// eBPF backend: loads/attaches the datapath, compiles rules into BPF maps, reads flow events.
#ifndef PB_BPF_H
#define PB_BPF_H

#include "pb_internal.h"
#include "pb_rules.h"
#include "bpf/pb_bpf_shared.h"

struct pb_bpf_cfg {
    uint16_t tcp_port, udp_port;   // relay ports (already bound by the relay)
    uint32_t self_tgid;            // process hosting the relay; never redirected
    bool     log;
    bool     dns_via_proxy;
};

// One rule as seen by the compiler: the parsed rule plus its resolved proxy.
struct pb_rule_view {
    const struct pb_rule *rule;
    int      action;         // effective action (PROXY with no usable proxy has already become BLOCK)
    uint16_t proxy_id;       // resolved (0 for DIRECT/BLOCK)
    bool     udp_direct;     // PROXY rule whose proxy is HTTP: UDP goes direct
};

typedef void (*pb_event_cb)(const struct pb_event *e);

// Returns 0 on success; on failure returns -1 after logging the reason (kernel too old, not root, no cgroup2, verifier...).
int  pb_bpf_start(const struct pb_bpf_cfg *cfg, pb_event_cb cb);
void pb_bpf_stop(void);
bool pb_bpf_running(void);

void pb_bpf_set_flags(bool log, bool dns_via_proxy);
// Recompiles the rule set (and rescans /proc for running executables). Returns -1 if it does not fit (too many rules).
int  pb_bpf_sync(const struct pb_rule_view *v, size_t n);
// Slow-path learning: install the class for the exact executable key the kernel reported in `o`, using the same rule set
// that decide() just evaluated.
void pb_bpf_learn(const struct pb_orig *o, const char *exe_path, const struct pb_rule_view *v, size_t n);

// Domain rules: (rule index, address) pairs whose DNS name matches. Set by the DNS tap before the answer reaches the client.
void pb_bpf_dom_set(uint32_t rule_idx, uint32_t ip_host);
void pb_bpf_dom_clear(void);
void pb_bpf_set_dns_tap(bool on);

int  pb_bpf_take_tcp_orig(uint16_t client_port, struct pb_orig *out);
int  pb_bpf_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out);

#endif
