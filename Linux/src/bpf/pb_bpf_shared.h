// Types shared by the BPF object and userspace.
#ifndef PB_BPF_SHARED_H
#define PB_BPF_SHARED_H

#ifdef __BPF__
typedef __u8 pb_u8; typedef __u16 pb_u16; typedef __u32 pb_u32; typedef __u64 pb_u64;
#else
#include <stdint.h>
typedef uint8_t pb_u8; typedef uint16_t pb_u16; typedef uint32_t pb_u32; typedef uint64_t pb_u64;
#endif

#define PB_MAX_RULES        512
#define PB_MAX_CLASSES      2048
#define PB_RULES_PER_CLASS  16
#define PB_BPF_MAX_V4       4
#define PB_BPF_MAX_PORT     4

#define PB_RF_ANY_HOST      0x01
#define PB_RF_ANY_PORT      0x02
#define PB_RF_HOST_COMPLEX  0x04   // host pattern the kernel cannot express: "maybe" for every destination
#define PB_RF_PORT_COMPLEX  0x08   // more port ranges than fit: "maybe" when none of the stored ones match
#define PB_RF_HAS_V6        0x10   // IPv6 patterns present: "maybe" for IPv6 destinations
#define PB_RF_UDP_DIRECT    0x20   // PROXY rule whose proxy cannot carry UDP: UDP goes direct
#define PB_RF_DOMAINS       0x40   // answered through the dom_hit map filled by the DNS tap
#define PB_RF_LOCALHOST     0x80   // PROXY rule that also proxies loopback destinations

#define PB_CLASS_DECIDE     0xffffffffu   // pb_bclass.n: always take the slow path for this binary

struct pb_cfg {
    pb_u32 enabled;         // at least one rule is loaded
    pb_u32 paused;          // main switch off: nothing is redirected
    pb_u32 self_tgid;       // the process hosting the relay is never redirected
    pb_u32 log;
    pb_u32 dns_via_proxy;
    pb_u32 dns_tap;         // a domain rule exists
    pb_u32 n_exempt;        // entries in the exempt map
    pb_u32 n_localhost;     // rules that proxy loopback traffic; 0 keeps every loopback connection out of the rule walk
    pb_u16 tcp_port, udp_port;
    pb_u64 netns;           // network namespace of the relay; other namespaces are ignored (0 = unknown)
};

struct pb_exe_key { pb_u32 dev; pb_u32 pad; pb_u64 ino; };
struct pb_port_key { pb_u32 ip; pb_u32 port; };          // client source address (network order) and port
struct pb_dom_key { pb_u32 rule; pb_u32 ip; };           // ip in host order

struct pb_brule {
    pb_u16 proxy_id;
    pb_u8  action;          // 0 proxy, 1 direct, 2 block
    pb_u8  proto_mask;      // 1 tcp, 2 udp
    pb_u8  flags, n_v4, n_port, pad;
    struct { pb_u32 lo, hi; } v4[PB_BPF_MAX_V4];      // host order
    struct { pb_u16 lo, hi; } port[PB_BPF_MAX_PORT];  // host order
};

struct pb_bclass {
    pb_u32 n;
    pb_u32 tap;             // covered by a domain rule: its DNS must be observed
    pb_u32 rule[PB_RULES_PER_CLASS];
};

struct pb_event {
    pb_u32 pid;
    pb_u8  comm[16];
    pb_u8  addr[16];
    pb_u16 port, proxy_id;
    pb_u8  family, proto, action, pad;
};

#endif
