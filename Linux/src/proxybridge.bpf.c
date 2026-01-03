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

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
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
        e->protocol = PROTO_TCP;
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);
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

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct net_event *e;
    u16 family;
    u8 state;

    BPF_CORE_READ_INTO(&state, sk, __sk_common.skc_state);
    if (state != TCP_ESTABLISHED)
        return 0;

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
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
