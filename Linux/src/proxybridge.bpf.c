#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "proxybridge.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_key);
    __type(value, __u8);
} tcp_conn_map SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
    struct net_event *e;
    struct conn_key key = {};
    u16 family;
    __u8 val = 1;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    
    if (family == AF_INET) {
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
        e->dport = bpf_ntohs(e->dport);
        e->protocol = PROTO_TCP;
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);

        key.saddr = e->saddr;
        key.daddr = e->daddr;
        key.sport = e->sport;
        key.dport = e->dport;
        bpf_map_update_elem(&tcp_conn_map, &key, &val, BPF_ANY);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct net_event *e;
    u16 family;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    
    if (family == AF_INET) {
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
        e->dport = bpf_ntohs(e->dport);
        e->protocol = PROTO_UDP;
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
