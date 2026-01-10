// SPDX-License-Identifier: GPL-2.0
// ProxyBridge - Linux eBPF 

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define MAX_RULES 100
#define MAX_PROCESS_NAME 256

#define PROTO_TCP  0x01
#define PROTO_UDP  0x02
#define PROTO_BOTH 0x03

#define ACTION_DIRECT 0
#define ACTION_PROXY  1
#define ACTION_BLOCK  2

#define LOCAL_PROXY_PORT 34010
#define LOCAL_UDP_RELAY_PORT 34011

#define SOL_IP 0
#define SO_ORIGINAL_DST 80

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

// Save original destination
struct sock_info {
    __u32 orig_ip;
    __u16 orig_port;
    char process[16];
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);  // socket cookie
    __type(value, struct sock_info);
} socket_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} relay_pid SEC(".maps");

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    
    if (dst_port == 0 || (dst_ip >> 24) == 127 || dst_port == 53) return 1;
    
    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *relay_pid_ptr = bpf_map_lookup_elem(&relay_pid, &key);
    if (relay_pid_ptr && *relay_pid_ptr == current_pid) return 1;
    
    char proc_name[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(proc_name, sizeof(proc_name), &group_leader->comm);
    
    struct conn_event event = {0};
    __builtin_memcpy(event.process_name, proc_name, 16);
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.dest_ip = dst_ip;
    event.dest_port = dst_port;
    event.proto = PROTO_TCP;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_info info = {0};
    info.orig_ip = dst_ip;
    info.orig_port = dst_port;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(info.process, proc_name, 16);
    bpf_map_update_elem(&socket_map, &cookie, &info, BPF_ANY);
    
    ctx->user_ip4 = bpf_htonl(0x7f000001);
    ctx->user_port = bpf_htons(LOCAL_PROXY_PORT);
    
    return 1;
}

SEC("cgroup/sendmsg4")
int cgroup_sendmsg4(struct bpf_sock_addr *ctx)
{
    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    __u16 dst_port = bpf_ntohs(ctx->user_port);
    
    if (dst_port == 0 || dst_ip == 0x7f000001 || dst_port == 53) return 1;
    
    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u32 *relay_pid_ptr = bpf_map_lookup_elem(&relay_pid, &key);
    if (relay_pid_ptr && *relay_pid_ptr == current_pid) return 1;
    
    char proc_name[16];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    bpf_probe_read_kernel_str(proc_name, sizeof(proc_name), &group_leader->comm);
    
    struct conn_event event = {0};
    __builtin_memcpy(event.process_name, proc_name, sizeof(event.process_name));
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.dest_ip = dst_ip;
    event.dest_port = dst_port;
    event.proto = PROTO_UDP;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_info info = {0};
    info.orig_ip = dst_ip;
    info.orig_port = dst_port;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(info.process, proc_name, 16);
    bpf_map_update_elem(&socket_map, &cookie, &info, BPF_ANY);
    
    ctx->user_ip4 = bpf_htonl(0x7f000001);
    ctx->user_port = bpf_htons(LOCAL_UDP_RELAY_PORT);
    
    return 1;
}

char _license[] SEC("license") = "GPL";
