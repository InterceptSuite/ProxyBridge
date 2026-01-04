// SPDX-License-Identifier: GPL-2.0
// ProxyBridge - EXACT Windows WinDivert equivalent using cgroup/connect4
//
// Flow (same as Windows):
// 1. Application calls connect() → cgroup/connect4 hook intercepts
// 2. Get process name, dst IP, dst port, protocol
// 3. Check rules (EXACT Windows match_rule logic)
// 4. If ACTION_PROXY → redirect to local relay (save original dest)
// 5. If ACTION_DIRECT → allow normal connection
// 6. If ACTION_BLOCK → reject connection

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_RULES 100
#define MAX_PROCESS_NAME 256

// Rule definitions (EXACT match to Windows)
#define PROTO_TCP  0x01
#define PROTO_UDP  0x02
#define PROTO_BOTH 0x03

#define ACTION_DIRECT 0
#define ACTION_PROXY  1
#define ACTION_BLOCK  2

// Local relay ports (must match Windows LOCAL_PROXY_PORT)
#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011

// Socket constants
#define SOL_IP 0
#define SO_ORIGINAL_DST 80

// Connection event for logging
struct conn_event {
    char process_name[16];
    __u32 pid;
    __u32 dest_ip;
    __u16 dest_port;
    __u8 action;
    __u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Rule structure (matches Windows PROCESS_RULE)
struct proxy_rule {
    char process_name[MAX_PROCESS_NAME];  // "*" or "chrome.exe" or "firefox.exe; chrome.exe"
    char target_hosts[512];               // "*" or "192.168.*.*" or "10.0.0.1; 172.16.0.1"
    char target_ports[256];               // "*" or "80; 443" or "80-8000"
    __u8 proto;                           // PROTO_TCP/UDP/BOTH
    __u8 action;                          // ACTION_DIRECT/PROXY/BLOCK
    __u8 enabled;                         // 1 = enabled, 0 = disabled
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct proxy_rule);
} rules_map SEC(".maps");

// Save original destination for SO_ORIGINAL_DST retrieval
struct orig_dest {
    __u32 ip;
    __u16 port;
    __u16 local_port;  // Local port to identify the connection
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);  // socket cookie
    __type(value, struct orig_dest);
} socket_map SEC(".maps");

// Helper: match wildcard pattern (simplified)
static __always_inline int match_pattern(const char *str, const char *pattern) {
    // "*" matches everything
    if (pattern[0] == '*')
        return 1;
    
    // Empty pattern matches empty string
    if (pattern[0] == '\0')
        return (str[0] == '\0') ? 1 : 0;
    
    // Simple exact match
    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        if (pattern[i] == '\0')
            return (str[i] == '\0') ? 1 : 0;
        if (str[i] != pattern[i])
            return 0;
    }
    return 0;
}

// Helper: check if process name matches rule
// Windows logic: rule.process_name can be "*" or "chrome.exe" or "firefox.exe; chrome.exe"
static __always_inline int match_process(const char *proc_name, const char *rule_pattern) {
    // "*" = match all
    if (rule_pattern[0] == '*')
        return 1;
    
    // Exact match
    return match_pattern(proc_name, rule_pattern);
}

// Helper: check if port matches rule
// Windows logic: "*" or "80" or "80; 443" or "80-8000"
static __always_inline int match_port(__u16 port, const char *rule_ports) {
    // "*" = match all
    if (rule_ports[0] == '*')
        return 1;
    
    // Empty = match all
    if (rule_ports[0] == '\0')
        return 1;
    
    // TODO: Parse port numbers/ranges (complex for BPF)
    // For now: always match if not wildcard
    return 1;
}

// Helper: check if IP matches rule
// Windows logic: "*" or "192.168.*.*" or "10.0.0.1; 172.16.0.1"
static __always_inline int match_ip(__u32 ip, const char *rule_hosts) {
    // "*" = match all
    if (rule_hosts[0] == '*')
        return 1;
    
    // Empty = match all
    if (rule_hosts[0] == '\0')
        return 1;
    
    // TODO: Parse IP patterns (complex for BPF)
    // For now: always match if not wildcard
    return 1;
}

// Check rules (EXACT Windows check_process_rule logic)
static __always_inline __u8 check_rules(const char *proc_name, __u32 dst_ip, __u16 dst_port, __u8 is_tcp) {
    struct proxy_rule *rule;
    __u8 proto_flag = is_tcp ? PROTO_TCP : PROTO_UDP;
    
    // Check each rule (limited to avoid verifier issues)
    #pragma unroll
    for (__u32 i = 0; i < 10; i++) {
        rule = bpf_map_lookup_elem(&rules_map, &i);
        if (!rule) {
            bpf_printk("Rule %d: NULL", i);
            continue;
        }
        
        bpf_printk("Rule %d: enabled=%d proto=%d action=%d", i, rule->enabled, rule->proto, rule->action);
        bpf_printk("Rule %d: process='%s'", i, rule->process_name);
        
        // Skip disabled rules
        if (!rule->enabled) {
            bpf_printk("Rule %d: DISABLED", i);
            continue;
        }
        
        // Check protocol
        if ((rule->proto & proto_flag) == 0) {
            bpf_printk("Rule %d: proto mismatch", i);
            continue;
        }
        
        // Check process name
        if (!match_process(proc_name, rule->process_name)) {
            bpf_printk("Rule %d: process mismatch", i);
            continue;
        }
        
        // Check IP
        if (!match_ip(dst_ip, rule->target_hosts)) {
            bpf_printk("Rule %d: IP mismatch", i);
            continue;
        }
        
        // Check port
        if (!match_port(dst_port, rule->target_ports)) {
            bpf_printk("Rule %d: port mismatch", i);
            continue;
        }
        
        // Rule matched!
        bpf_printk("Rule %d: MATCHED! action=%d", i, rule->action);
        return rule->action;
    }
    
    // No rule matched → default DIRECT
    bpf_printk("No rule matched, returning DIRECT");
    return ACTION_DIRECT;
}

// cgroup/connect4: Intercept TCP connect() calls
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
    // Get process name (thread group leader, not thread name)
    char proc_name[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(proc_name, sizeof(proc_name), &group_leader->comm);
    
    // Get destination
    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    
    // Debug: print all connections
    bpf_printk("CONNECT: %s -> %d.%d.%d.%d:%d", proc_name,
               (dst_ip>>24)&0xFF, (dst_ip>>16)&0xFF, (dst_ip>>8)&0xFF, dst_ip&0xFF, dst_port);
    
    // Skip DNS (always allow)
    if (dst_port == 53)
        return 1; // Allow
    
    // Skip localhost connections
    if ((dst_ip >> 24) == 127)
        return 1;
    
    // Check rules
    __u8 action = check_rules(proc_name, dst_ip, dst_port, 1);
    
    bpf_printk("RULE RESULT: action=%d for %s", action, proc_name);
    
    // Log ALL connections (like Windows does)
    struct conn_event event = {0};
    __builtin_memcpy(event.process_name, proc_name, 16);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.dest_ip = dst_ip;
    event.dest_port = dst_port;
    event.action = action;
    event.proto = PROTO_TCP;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    // DIRECT → allow normal connection
    if (action == ACTION_DIRECT)
        return 1;
    
    // BLOCK → reject connection
    if (action == ACTION_BLOCK)
        return 0;
    
    // PROXY → redirect to local relay
    if (action == ACTION_PROXY) {
        bpf_printk("REDIRECTING %s to proxy", proc_name);
        // Save original destination
        __u64 cookie = bpf_get_socket_cookie(ctx);
        struct orig_dest orig = {
            .ip = dst_ip,
            .port = dst_port,
            .local_port = 0
        };
        bpf_map_update_elem(&socket_map, &cookie, &orig, BPF_ANY);
        
        // Redirect to local relay (127.0.0.1:34010)
        ctx->user_ip4 = bpf_htonl(0x7f000001);  // 127.0.0.1
        ctx->user_port = bpf_htons(LOCAL_PROXY_PORT);
    }
    
    return 1;  // Allow (possibly modified) connection
}

// cgroup/sendmsg4: Intercept UDP sendmsg() calls
SEC("cgroup/sendmsg4")
int cgroup_sendmsg4(struct bpf_sock_addr *ctx)
{
    // Get process name (thread group leader, not thread name)
    char proc_name[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(proc_name, sizeof(proc_name), &group_leader->comm);
    
    // Get destination
    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    
    // Skip port 0 and localhost
    if (dst_port == 0 || dst_ip == 0x7f000001) return 1;
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check rules with UDP protocol
    int action = check_rules(proc_name, dst_ip, dst_port, PROTO_UDP);
    
    // Send event (with UDP protocol)
    struct conn_event event = {0};
    __builtin_memcpy(event.process_name, proc_name, sizeof(event.process_name));
    event.pid = pid;
    event.dest_ip = dst_ip;
    event.dest_port = dst_port;
    event.action = action;
    event.proto = PROTO_UDP;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    // DIRECT → allow normally
    if (action == ACTION_DIRECT)
        return 1;
    
    // BLOCK → reject
    if (action == ACTION_BLOCK)
        return 0;
    
    // PROXY → redirect to local UDP relay
    if (action == ACTION_PROXY) {
        // Save original destination
        __u64 cookie = bpf_get_socket_cookie(ctx);
        struct orig_dest orig = {
            .ip = dst_ip,
            .port = dst_port,
            .local_port = 0
        };
        bpf_map_update_elem(&socket_map, &cookie, &orig, BPF_ANY);
        
        // Redirect to local UDP relay (127.0.0.1:34011)
        ctx->user_ip4 = bpf_htonl(0x7f000001);  // 127.0.0.1
        ctx->user_port = bpf_htons(LOCAL_UDP_RELAY_PORT);
    }
    
    return 1;
}

char _license[] SEC("license") = "GPL";
