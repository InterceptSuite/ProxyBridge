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
    char process_name[MAX_PROCESS_NAME];  // "*" or "curl" or "firefox;chrome;wget"
    char target_hosts[512];               // "*" or "192.168.*.*" or "10.0.0.1;172.16.0.1" or "10.10.1.1-10.10.255.255"
    char target_ports[256];               // "*" or "80;443" or "80-8000"
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

// Helper: compare two strings up to delimiter
static __always_inline int str_equals_delim(const char *s1, const char *s2, int max_len) {
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= max_len)
            return 0;
        
        // s2 ends at delimiter or null
        if (s2[i] == ';' || s2[i] == '\0')
            return (s1[i] == '\0') ? 1 : 0;
        
        // s1 ends but s2 continues
        if (s1[i] == '\0')
            return 0;
        
        // Mismatch
        if (s1[i] != s2[i])
            return 0;
    }
    return 0;
}

// Helper: check if process name matches rule
// Linux: rule.process_name can be "*" or "curl" or "firefox;chrome;wget"
static __always_inline int match_process(const char *proc_name, const char *rule_pattern) {
    // "*" = match all
    if (rule_pattern[0] == '*')
        return 1;
    
    int pos = 0;
    
    // Check each process name in semicolon-separated list (support up to 10 entries)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos >= MAX_PROCESS_NAME || rule_pattern[pos] == '\0')
            break;
        
        // Skip whitespace
        while (pos < MAX_PROCESS_NAME && rule_pattern[pos] == ' ') pos++;
        if (pos >= MAX_PROCESS_NAME || rule_pattern[pos] == '\0')
            break;
        
        // Compare process name with current pattern entry
        if (str_equals_delim(proc_name, &rule_pattern[pos], MAX_PROCESS_NAME - pos))
            return 1;
        
        // Skip to next semicolon
        while (pos < MAX_PROCESS_NAME && rule_pattern[pos] != ';' && rule_pattern[pos] != '\0')
            pos++;
        if (pos < MAX_PROCESS_NAME && rule_pattern[pos] == ';')
            pos++;
    }
    
    return 0;
}

// Helper: parse number from string
static __always_inline int parse_number(const char *str, int *pos, int max_len) {
    int num = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (*pos >= max_len || str[*pos] < '0' || str[*pos] > '9')
            break;
        num = num * 10 + (str[*pos] - '0');
        (*pos)++;
    }
    return num;
}

// Helper: check if port matches rule
// Windows logic: "*" or "80" or "80;443" or "80-8000"
static __always_inline int match_port(__u16 port, const char *rule_ports) {
    // "*" = match all
    if (rule_ports[0] == '*')
        return 1;
    
    // Empty = match all
    if (rule_ports[0] == '\0')
        return 1;
    
    int pos = 0;
    
    // Parse port patterns (support up to 10 entries)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos >= 256 || rule_ports[pos] == '\0')
            break;
        
        // Skip whitespace
        while (pos < 256 && rule_ports[pos] == ' ') pos++;
        if (pos >= 256 || rule_ports[pos] == '\0')
            break;
        
        // Parse first number
        int start_port = parse_number(rule_ports, &pos, 256);
        
        // Check for range (80-8000)
        if (pos < 256 && rule_ports[pos] == '-') {
            pos++;
            int end_port = parse_number(rule_ports, &pos, 256);
            if (port >= start_port && port <= end_port)
                return 1;
        } else {
            // Single port
            if (port == start_port)
                return 1;
        }
        
        // Skip to next entry (semicolon)
        while (pos < 256 && rule_ports[pos] != ';' && rule_ports[pos] != '\0') pos++;
        if (pos < 256 && rule_ports[pos] == ';') pos++;
    }
    
    return 0;
}

// Helper: check if IP octet matches pattern
static __always_inline int match_octet(__u8 octet, const char *pattern, int *pos, int max_len) {
    if (*pos >= max_len)
        return 0;
    
    // Wildcard matches anything
    if (pattern[*pos] == '*') {
        (*pos)++;
        return 1;
    }
    
    // Parse number
    int num = parse_number(pattern, pos, max_len);
    return (octet == num);
}

// Helper: parse full IP address from string (returns IP as u32)
static __always_inline __u32 parse_ip_address(const char *pattern, int *pos, int max_len) {
    __u32 ip = 0;
    
    // Parse 4 octets
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        int octet = parse_number(pattern, pos, max_len);
        ip = (ip << 8) | (octet & 0xFF);
        
        // Skip dot (except after last octet)
        if (i < 3 && *pos < max_len && pattern[*pos] == '.')
            (*pos)++;
    }
    
    return ip;
}

// Helper: check if single IP pattern matches (supports wildcards and ranges)
static __always_inline int match_single_ip(__u32 ip, const char *pattern, int start_pos, int end_pos) {
    int pos = start_pos;
    
    // Check for IP range format: 10.10.1.1-10.10.255.255
    int has_range = 0;
    #pragma unroll
    for (int i = start_pos; i < end_pos && i < start_pos + 40; i++) {
        if (pattern[i] == '-' && i > start_pos) {
            has_range = 1;
            break;
        }
    }
    
    if (has_range) {
        // Parse start IP
        __u32 start_ip = parse_ip_address(pattern, &pos, end_pos);
        
        // Skip hyphen
        if (pos < end_pos && pattern[pos] == '-')
            pos++;
        
        // Parse end IP
        __u32 end_ip = parse_ip_address(pattern, &pos, end_pos);
        
        // Check if IP is in range
        return (ip >= start_ip && ip <= end_ip) ? 1 : 0;
    }
    
    // Wildcard pattern matching (192.168.*.*)
    __u8 oct1 = (ip >> 24) & 0xFF;
    __u8 oct2 = (ip >> 16) & 0xFF;
    __u8 oct3 = (ip >> 8) & 0xFF;
    __u8 oct4 = ip & 0xFF;
    
    pos = start_pos;
    
    // Match each octet
    if (!match_octet(oct1, pattern, &pos, end_pos))
        return 0;
    if (pos >= end_pos || pattern[pos++] != '.')
        return 0;
    
    if (!match_octet(oct2, pattern, &pos, end_pos))
        return 0;
    if (pos >= end_pos || pattern[pos++] != '.')
        return 0;
    
    if (!match_octet(oct3, pattern, &pos, end_pos))
        return 0;
    if (pos >= end_pos || pattern[pos++] != '.')
        return 0;
    
    if (!match_octet(oct4, pattern, &pos, end_pos))
        return 0;
    
    return 1;
}

// Helper: check if IP matches rule
// Windows logic: "*" or "192.168.*.*" or "10.0.0.1;172.16.0.1" or "10.10.1.1-10.10.255.255"
static __always_inline int match_ip(__u32 ip, const char *rule_hosts) {
    // "*" = match all
    if (rule_hosts[0] == '*')
        return 1;
    
    // Empty = match all
    if (rule_hosts[0] == '\0')
        return 1;
    
    int pos = 0;
    
    // Parse IP patterns separated by semicolons (support up to 10 entries)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos >= 512 || rule_hosts[pos] == '\0')
            break;
        
        // Skip whitespace
        while (pos < 512 && rule_hosts[pos] == ' ') pos++;
        if (pos >= 512 || rule_hosts[pos] == '\0')
            break;
        
        // Find end of this pattern (semicolon or end)
        int start = pos;
        int end = pos;
        #pragma unroll
        for (int j = 0; j < 20; j++) {
            if (end >= 512 || rule_hosts[end] == '\0' || rule_hosts[end] == ';')
                break;
            end++;
        }
        
        // Check if this pattern matches
        if (match_single_ip(ip, rule_hosts, start, end))
            return 1;
        
        // Move to next pattern
        pos = end;
        if (pos < 512 && rule_hosts[pos] == ';')
            pos++;
    }
    
    return 0;
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
    // Get process name
    char proc_name[16];
    bpf_get_current_comm(proc_name, sizeof(proc_name));
    
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

char _license[] SEC("license") = "GPL";
