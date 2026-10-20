// cgroup socket-address hooks: redirect selected processes' connect()/sendmsg() to the userspace relay.
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "pb_bpf_shared.h"

// Minimal kernel types, relocated against the running kernel's BTF (CO-RE).
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct super_block { __u32 s_dev; };
struct inode { struct super_block *i_sb; unsigned long i_ino; };
struct file { struct inode *f_inode; };
struct mm_struct { struct file *exe_file; };
struct task_struct { struct mm_struct *mm; };
#pragma clang attribute pop

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define AF_INET 2
#define AF_INET6 10

#define ACT_PROXY  0
#define ACT_DIRECT 1
#define ACT_BLOCK  2
#define ACT_DECIDE 3

#define M_NO 0
#define M_YES 1
#define M_MAYBE 2

struct pb_orig {
    __u8  addr[16];
    __u16 port;
    __u16 proxy_id;
    __u32 pid;
    __u8  family, proto, action, pad;
    __u32 exe_dev, exe_pad;
    __u64 exe_ino;
};

volatile struct pb_cfg cfg;

#define MAP(name, kind, entries, key_t, val_t) \
    struct { __uint(type, kind); __uint(max_entries, entries); __type(key, key_t); __type(value, val_t); } name SEC(".maps")

MAP(exe2class, BPF_MAP_TYPE_HASH, 16384, struct pb_exe_key, __u32);
MAP(classes, BPF_MAP_TYPE_ARRAY, PB_MAX_CLASSES, __u32, struct pb_bclass);
MAP(brules, BPF_MAP_TYPE_ARRAY, PB_MAX_RULES, __u32, struct pb_brule);
MAP(exempt, BPF_MAP_TYPE_HASH, 64, __u32, __u8);
MAP(by_cookie, BPF_MAP_TYPE_LRU_HASH, 32768, __u64, struct pb_orig);
MAP(by_port, BPF_MAP_TYPE_LRU_HASH, 32768, struct pb_port_key, struct pb_orig);
MAP(flows, BPF_MAP_TYPE_LRU_HASH, 32768, __u32, struct pb_orig);
MAP(dom_hit, BPF_MAP_TYPE_LRU_HASH, 65536, struct pb_dom_key, __u8);
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } events SEC(".maps");

static __always_inline int foreign_netns(void *ctx)
{
    __u64 want = cfg.netns;
    return want && bpf_get_netns_cookie(ctx) != want;
}

static __always_inline int rule_match(const struct pb_brule *r, __u32 ri, __u8 fam, __u32 ip4, __u16 port)
{
    int port_res = M_YES;
    if (!(r->flags & PB_RF_ANY_PORT)) {
        port_res = M_NO;
        #pragma unroll
        for (int i = 0; i < PB_BPF_MAX_PORT; i++) {
            if (i >= r->n_port) break;
            if (port >= r->port[i].lo && port <= r->port[i].hi) { port_res = M_YES; break; }
        }
        if (port_res == M_NO && (r->flags & PB_RF_PORT_COMPLEX)) port_res = M_MAYBE;
        if (port_res == M_NO) return M_NO;
    }
    int host_res;
    if (r->flags & PB_RF_ANY_HOST) host_res = M_YES;
    else if (r->flags & PB_RF_HOST_COMPLEX) host_res = M_MAYBE;
    else if (fam == AF_INET6) host_res = (r->flags & PB_RF_HAS_V6) ? M_MAYBE : M_NO;
    else {
        host_res = M_NO;
        #pragma unroll
        for (int i = 0; i < PB_BPF_MAX_V4; i++) {
            if (i >= r->n_v4) break;
            if (ip4 >= r->v4[i].lo && ip4 <= r->v4[i].hi) { host_res = M_YES; break; }
        }
        if (host_res == M_NO && (r->flags & PB_RF_DOMAINS)) {
            struct pb_dom_key dk = { .rule = ri, .ip = ip4 };
            if (bpf_map_lookup_elem(&dom_hit, &dk)) host_res = M_YES;
        }
    }
    if (host_res == M_NO) return M_NO;
    return (host_res == M_MAYBE || port_res == M_MAYBE) ? M_MAYBE : M_YES;
}

static __always_inline int is_loopback(const struct pb_orig *o)
{
    const __u8 *a = o->addr;
    if (o->family == AF_INET) return a[12] == 127;
    int loopback = a[15] == 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) if (a[i]) loopback = 0;
    return loopback;
}

static __always_inline int implicit_direct(const struct pb_orig *o)
{
    const __u8 *a = o->addr;
    if (o->family == AF_INET) {
        if (a[12] == 127 || a[12] == 0 || a[12] >= 224) return 1;
    } else {
        if (a[0] == 0xff || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)) return 1;
        int loopback = a[15] == 1;
        #pragma unroll
        for (int i = 0; i < 15; i++) if (a[i]) loopback = 0;
        if (loopback) return 1;
    }
    if (o->proto == IPPROTO_UDP && (o->port == 67 || o->port == 68)) return 1;
    return o->port == 53 && !cfg.dns_via_proxy;
}

// Sets o->proxy_id for ACT_PROXY.
static __always_inline int decide(struct pb_orig *o)
{
    if (!cfg.enabled || cfg.paused || o->pid == cfg.self_tgid) return ACT_DIRECT;
    if (cfg.n_exempt && bpf_map_lookup_elem(&exempt, &o->pid)) return ACT_DIRECT;
    int tap = o->port == 53 && cfg.dns_tap;
    // Loopback joins the rule walk only when some rule asks for it; the resolver stub (port 53) and the relay itself never do.
    int lo = cfg.n_localhost && is_loopback(o) && o->port != 53 && o->port != cfg.tcp_port && o->port != cfg.udp_port;
    if (!tap && !lo && implicit_direct(o)) return ACT_DIRECT;

    struct mm_struct *mm = bpf_get_current_task_btf()->mm;
    if (!mm) return ACT_DIRECT;
    struct pb_exe_key key = {};
    key.dev = mm->exe_file->f_inode->i_sb->s_dev;
    key.ino = mm->exe_file->f_inode->i_ino;
    o->exe_dev = key.dev;
    o->exe_ino = key.ino;
    if (!key.ino) return ACT_DECIDE;

    __u32 *cid = bpf_map_lookup_elem(&exe2class, &key);
    if (!cid) return ACT_DECIDE;
    struct pb_bclass *c = bpf_map_lookup_elem(&classes, cid);
    if (!c || c->n > PB_RULES_PER_CLASS) return ACT_DECIDE;
    if (tap) {
        if (c->tap) return ACT_DECIDE;
        if (implicit_direct(o)) return ACT_DIRECT;
    }

    __u32 ip4 = o->family == AF_INET ? bpf_ntohl(*(const __u32 *)(o->addr + 12)) : 0;
    __u8 pbit = o->proto == IPPROTO_TCP ? 1 : 2;
    #pragma unroll
    for (int i = 0; i < PB_RULES_PER_CLASS; i++) {
        if (i >= c->n) break;
        __u32 ri = c->rule[i];
        struct pb_brule *r = bpf_map_lookup_elem(&brules, &ri);
        if (!r) return ACT_DECIDE;
        if (!(r->proto_mask & pbit)) continue;
        int m = rule_match(r, ri, o->family, ip4, o->port);
        if (m == M_NO) continue;
        if (m == M_MAYBE) return ACT_DECIDE;
        if (lo && !(r->action == ACT_PROXY && (r->flags & PB_RF_LOCALHOST))) return ACT_DIRECT;
        if (r->action != ACT_PROXY) return r->action;
        if (o->proto == IPPROTO_UDP && (r->flags & PB_RF_UDP_DIRECT)) return ACT_DIRECT;
        o->proxy_id = r->proxy_id;
        return ACT_PROXY;
    }
    return ACT_DIRECT;
}

static __always_inline void emit(const struct pb_orig *o, int action)
{
    if (!cfg.log) return;
    struct pb_event *e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) return;
    e->pid = o->pid;
    bpf_get_current_comm(e->comm, sizeof e->comm);
    __builtin_memcpy(e->addr, o->addr, 16);
    e->port = o->port;
    e->proxy_id = o->proxy_id;
    e->family = o->family;
    e->proto = o->proto;
    e->action = action;
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void set_mapped_v4(__u32 *ip6, __u32 ip4_be)
{
    ip6[0] = 0; ip6[1] = 0; ip6[2] = bpf_htonl(0x0000ffff); ip6[3] = ip4_be;
}

static __always_inline void orig_from_v4(struct pb_orig *o, __u32 ip_be, __u16 port_be, __u8 proto)
{
    __builtin_memset(o, 0, sizeof *o);
    o->addr[10] = 0xff; o->addr[11] = 0xff;
    __builtin_memcpy(o->addr + 12, &ip_be, 4);
    o->port = bpf_ntohs(port_be);
    o->family = AF_INET;
    o->proto = proto;
    o->pid = bpf_get_current_pid_tgid() >> 32;
}

// A v4-mapped address on an IPv6 socket is an IPv4 destination.
static __always_inline void orig_from_v6(struct pb_orig *o, const __u32 ip6[4], __u16 port_be, __u8 proto)
{
    __builtin_memset(o, 0, sizeof *o);
    __builtin_memcpy(o->addr, ip6, 16);
    o->port = bpf_ntohs(port_be);
    o->proto = proto;
    o->pid = bpf_get_current_pid_tgid() >> 32;
    o->family = (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == bpf_htonl(0x0000ffff)) ? AF_INET : AF_INET6;
}

// Loopback flow address 127.1-255.x.y standing for one UDP destination of one process; the relay recovers the destination
// from it and checks that the datagram really comes from that process. 0 when no address is free (the caller refuses the
// send rather than borrowing another flow's address).
static __always_inline __u32 udp_flow_addr(struct pb_orig *o)
{
    const __u32 *w = (const __u32 *)o->addr;
    __u32 h = w[0] * 2654435761u ^ w[1] * 40503u ^ w[2] * 2246822519u ^ w[3] * 3266489917u;
    h ^= ((__u32)o->port << 16) | o->proxy_id;
    h ^= (__u32)o->action * 668265263u;
    h ^= o->pid * 374761393u;
    h ^= h >> 15; h *= 2246822519u; h ^= h >> 13;
    for (int i = 0; i < 8; i++) {
        __u32 addr = bpf_htonl(0x7f000000 | (((h + i) & 0x00ffffff) | 0x00010000));
        struct pb_orig *ex = bpf_map_lookup_elem(&flows, &addr);
        if (!ex) { bpf_map_update_elem(&flows, &addr, o, BPF_NOEXIST); return addr; }
        if (!__builtin_memcmp(ex->addr, o->addr, 16) && ex->port == o->port && ex->proxy_id == o->proxy_id &&
            ex->action == o->action && ex->pid == o->pid) return addr;
    }
    return 0;
}

// 0: leave the call untouched, 1: redirected to the relay, -1: block.
static __always_inline int route(struct pb_orig *o)
{
    int act = decide(o);
    if (act == ACT_DIRECT || act == ACT_BLOCK) {
        emit(o, act);
        return act == ACT_BLOCK ? -1 : 0;
    }
    o->action = act;
    if (act == ACT_PROXY) emit(o, ACT_PROXY);
    else o->proxy_id = 0;
    return 1;
}

SEC("cgroup/connect4")
int pb_connect4(struct bpf_sock_addr *ctx)
{
    if (foreign_netns(ctx) || (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)) return 1;
    struct pb_orig o;
    orig_from_v4(&o, ctx->user_ip4, ctx->user_port, ctx->protocol);
    int r = route(&o);
    if (r <= 0) return r == 0;
    if (ctx->protocol == IPPROTO_TCP) {
        __u64 ck = bpf_get_socket_cookie(ctx);
        bpf_map_update_elem(&by_cookie, &ck, &o, BPF_ANY);
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(cfg.tcp_port);
    } else {
        __u32 fa = udp_flow_addr(&o);
        if (!fa) return 0;
        ctx->user_ip4 = fa;
        ctx->user_port = bpf_htons(cfg.udp_port);
    }
    return 1;
}

SEC("cgroup/connect6")
int pb_connect6(struct bpf_sock_addr *ctx)
{
    if (foreign_netns(ctx) || (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)) return 1;
    __u32 ip6[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
    struct pb_orig o;
    orig_from_v6(&o, ip6, ctx->user_port, ctx->protocol);
    int r = route(&o);
    if (r <= 0) return r == 0;
    if (ctx->protocol == IPPROTO_TCP) {
        __u64 ck = bpf_get_socket_cookie(ctx);
        bpf_map_update_elem(&by_cookie, &ck, &o, BPF_ANY);
        set_mapped_v4(ctx->user_ip6, bpf_htonl(0x7f000001));
        ctx->user_port = bpf_htons(cfg.tcp_port);
    } else {
        __u32 fa = udp_flow_addr(&o);
        if (!fa) return 0;
        set_mapped_v4(ctx->user_ip6, fa);
        ctx->user_port = bpf_htons(cfg.udp_port);
    }
    return 1;
}

SEC("cgroup/sendmsg4")
int pb_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (foreign_netns(ctx) || ctx->protocol != IPPROTO_UDP) return 1;
    struct pb_orig o;
    orig_from_v4(&o, ctx->user_ip4, ctx->user_port, IPPROTO_UDP);
    int r = route(&o);
    if (r <= 0) return r == 0;
    __u32 fa = udp_flow_addr(&o);
    if (!fa) return 0;
    ctx->user_ip4 = fa;
    ctx->user_port = bpf_htons(cfg.udp_port);
    return 1;
}

// udpv6_sendmsg refuses a hook that rewrites a native IPv6 destination to a v4-mapped address and loopback has only ::1, so
// a native IPv6 flow that must be proxied fails closed (EPERM); the application falls back to IPv4 or TCP.
SEC("cgroup/sendmsg6")
int pb_sendmsg6(struct bpf_sock_addr *ctx)
{
    if (foreign_netns(ctx) || ctx->protocol != IPPROTO_UDP) return 1;
    __u32 ip6[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
    struct pb_orig o;
    orig_from_v6(&o, ip6, ctx->user_port, IPPROTO_UDP);
    int r = route(&o);
    if (r <= 0) return r == 0;
    return o.action != ACT_PROXY;
}

// Replies come from the flow address; show the application the real peer.
SEC("cgroup/recvmsg4")
int pb_recvmsg4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP || ctx->user_port != bpf_htons(cfg.udp_port)) return 1;
    __u32 key = ctx->user_ip4;
    struct pb_orig *o = bpf_map_lookup_elem(&flows, &key);
    if (o && o->family == AF_INET) {
        ctx->user_ip4 = *(__u32 *)(o->addr + 12);
        ctx->user_port = bpf_htons(o->port);
    }
    return 1;
}

SEC("cgroup/recvmsg6")
int pb_recvmsg6(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol != IPPROTO_UDP || ctx->user_port != bpf_htons(cfg.udp_port)) return 1;
    if (ctx->user_ip6[0] || ctx->user_ip6[1] || ctx->user_ip6[2] != bpf_htonl(0x0000ffff)) return 1;
    __u32 key = ctx->user_ip6[3];
    struct pb_orig *o = bpf_map_lookup_elem(&flows, &key);
    if (!o) return 1;
    const __u32 *w = (const __u32 *)o->addr;
    ctx->user_ip6[0] = w[0]; ctx->user_ip6[1] = w[1]; ctx->user_ip6[2] = w[2]; ctx->user_ip6[3] = w[3];
    ctx->user_port = bpf_htons(o->port);
    return 1;
}

// getpeername() on a redirected socket reports the original destination.
SEC("cgroup/getpeername4")
int pb_getpeername4(struct bpf_sock_addr *ctx)
{
    struct pb_orig *o;
    if (ctx->protocol == IPPROTO_UDP) {
        __u32 key = ctx->user_ip4;
        o = bpf_map_lookup_elem(&flows, &key);
    } else if (ctx->protocol == IPPROTO_TCP) {
        __u64 ck = bpf_get_socket_cookie(ctx);
        o = bpf_map_lookup_elem(&by_cookie, &ck);
    } else return 1;
    if (o && o->family == AF_INET) {
        ctx->user_ip4 = *(__u32 *)(o->addr + 12);
        ctx->user_port = bpf_htons(o->port);
    }
    return 1;
}

SEC("cgroup/getpeername6")
int pb_getpeername6(struct bpf_sock_addr *ctx)
{
    struct pb_orig *o;
    if (ctx->protocol == IPPROTO_UDP) {
        if (ctx->user_ip6[0] || ctx->user_ip6[1] || ctx->user_ip6[2] != bpf_htonl(0x0000ffff)) return 1;
        __u32 key = ctx->user_ip6[3];
        o = bpf_map_lookup_elem(&flows, &key);
    } else if (ctx->protocol == IPPROTO_TCP) {
        __u64 ck = bpf_get_socket_cookie(ctx);
        o = bpf_map_lookup_elem(&by_cookie, &ck);
    } else return 1;
    if (o) {
        const __u32 *w = (const __u32 *)o->addr;
        ctx->user_ip6[0] = w[0]; ctx->user_ip6[1] = w[1]; ctx->user_ip6[2] = w[2]; ctx->user_ip6[3] = w[3];
        ctx->user_port = bpf_htons(o->port);
    }
    return 1;
}

// Hands the original destination to the relay, keyed by the client's source address and port.
SEC("sockops")
int pb_sockops(struct bpf_sock_ops *s)
{
    if (s->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) return 1;
    __u64 ck = bpf_get_socket_cookie(s);
    struct pb_orig *o = bpf_map_lookup_elem(&by_cookie, &ck);
    if (!o) return 1;
    struct pb_port_key k = { .ip = s->local_ip4, .port = s->local_port };
    if (s->family == AF_INET6 && !s->local_ip6[0] && !s->local_ip6[1] && s->local_ip6[2] == bpf_htonl(0x0000ffff))
        k.ip = s->local_ip6[3];
    bpf_map_update_elem(&by_port, &k, o, BPF_ANY);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
